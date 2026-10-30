// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console2} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {MtxPipelineLib} from "../../src/metatx/MtxPipelineLib.sol";
import {MetaTokenBase} from "../../src/metatx/MetaTokenBase.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {IERC20MetaTx} from "../../src/metatx/IERC20MetaTx.sol";
import {IUALedger} from "../../src/metatx/IUALedger.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {SigCheck} from "../../src/common/SigCheck.sol";
import {HederaLib} from "../../src/hedera/HederaLib.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {SmartKeyAccountFactory} from "../../src/account/SmartKeyAccountFactory.sol";
import {SubjectKey, KeyKind} from "../../src/account/SmartKeyAccount.sol";
import {PqzRegistryBase, PQZ_UID} from "../pqz/helpers/PqzRegistryBase.sol";
import {MockHederaAccountService} from "../hedera/HederaMocks.sol";
import {normalInit} from "../v2/helpers/V2Fixture.sol";
import {plainEnv} from "../helpers/Catalogue.sol";
import {IRig, PlainRig, PqzRig, ZetherRig} from "./MetaTxParity.t.sol";

/// Submits `cd` to `t` with exactly `g` gas for the frame (not a transaction: no intrinsic gas, no calldata floor).
contract GasProbe {
    function hit(address t, bytes calldata cd, uint256 g) external returns (bool ok, bytes memory ret) {
        (ok, ret) = t.call{gas: g}(cd);
    }
}

/// The tokens' call paths on `MtxPipelineLib` (metatx split T3, spec §3.3/§3.4; R2, R7, R8, R12). The `Ctx` and the
/// calldata a token hands the library are read from the DELEGATECALL itself (`vm.startStateDiffRecording`), so the test
/// sees what the library got, not what a view reports.
///
/// The `NORMAL` fixture `tok` runs on the gen-1 registry of chain 7622 (`mldsa65` on its mocked precompile, cap 100,000)
/// with this chain's `SmartKeyAccount` implementation; `htok` is the same kind built `IS_HEDERA` (HIP-632 at 0x16a,
/// `MockHederaAccountService`).
contract MtxCtxTest is PqzRegistryBase {
    uint256 internal constant ALICE_PK = 0xA11CE;
    uint256 internal constant SKA_PK = 0x5EED;
    uint256 internal constant ED_PK = 0xA11CE5; // the Hedera account's "ED" key (the mock's secp256k1 stand-in)
    address internal constant RELAYER = address(0xBEEF);
    address internal constant BOB = address(0xB0B);
    address internal constant HAS = address(0x16a);
    uint32 internal constant RR = MetaTxLib.MODE_RESTRICT_RELAYER;
    bytes32 internal constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)");
    // ERC20MetaTx `_UA_STORAGE` (ERC-7201 `scaas.ua.ledger`); the ERC-20 `_balances` / `_totalSupply` slots per
    // test/v2/layout/NormalToken.json
    bytes32 internal constant UA_STORAGE = 0x9e2def943e5a7ec3982e5d00524104579a6b98ce8b31343ac0092718cc04e900;

    address internal alice = vm.addr(ALICE_PK);
    address internal hed = address(uint160(1_234_567)); // a Hedera account 0.0.N, no code
    SmartKeyAccountFactory internal fac;
    NormalToken internal tok;
    NormalToken internal htok;
    bytes32 internal u; // an `mldsa65` UA of `reg`

    function setUp() public {
        vm.chainId(7622);
        vm.warp(1_800_000_000);
        _registryStack();
        fac = new SmartKeyAccountFactory(PQZ_UID);
        tok = _token(fac.IMPLEMENTATION(), false);
        htok = _token(address(0), true);
        vm.etch(HAS, type(MockHederaAccountService).runtimeCode);
        MockHederaAccountService(HAS).setEdKey(hed, vm.addr(ED_PK));
        u = _mldsaUA(9);
        tok.mint(alice, 1_000_000);
        tok.mintToUA(u, 1_000_000);
        htok.mint(hed, 1_000_000);
    }

    function _token(address ska, bool hedera) internal returns (NormalToken t) {
        NormalToken impl = new NormalToken(1, plainEnv(address(this), ska, PQZ_UID, address(reg), hedera), "");
        t = NormalToken(Clones.clone(address(impl)));
        t.initialize(address(this), 1, abi.encode(normalInit("Points", "PTS", 6, 0, address(this), address(this))));
    }

    // ------------------------------------------------------------------ helpers

    function _ecdsa(uint256 pk, bytes32 d) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, d);
        return abi.encodePacked(r, s, v);
    }

    /// HIP-632 "ED25519" 64 bytes (the mock's compact secp256k1 stand-in, `HederaV2.t.sol`).
    function _ed(bytes32 d) internal pure returns (bytes memory) {
        (bytes32 r, bytes32 vs) = vm.signCompact(ED_PK, d);
        return abi.encodePacked(r, vs);
    }

    function _mt(address from, bytes memory data, uint256 batch, uint32 mode, uint256 fee)
        internal view returns (MetaTxLib.MetaTransaction memory m)
    {
        m = MetaTxLib.MetaTransaction(from, data, batch, 0, block.timestamp + 300, mode, RELAYER, fee, address(0));
    }

    function _um(bytes32 from, bytes memory data, uint256 batch, uint32 mode, uint256 fee)
        internal view returns (MetaTxLib.UAMetaTransaction memory m)
    {
        m = MetaTxLib.UAMetaTransaction(from, data, batch, 0, block.timestamp + 300, mode, RELAYER, fee, address(0));
    }

    function _tr(address from, address to, uint256 batch) internal view returns (MetaTxLib.MetaTransfer memory) {
        return MetaTxLib.MetaTransfer(from, to, 1_000, bytes32(0), batch, 0, block.timestamp + 300,
            RR | MetaTxLib.MODE_FEE_FIXED, RELAYER, 5, address(0));
    }

    function _ut(bytes32 from, bytes32 to, uint256 batch) internal view returns (MetaTxLib.UAMetaTransfer memory) {
        return MetaTxLib.UAMetaTransfer(from, to, 1_000, bytes32(0), batch, 0, block.timestamp + 300,
            RR | MetaTxLib.MODE_FEE_FIXED, RELAYER, 5, address(0));
    }

    /// The relayer submits `cd` to `t` with all gas, recording every account and storage access.
    function _recorded(address t, bytes memory cd) internal returns (bool ok, bytes memory ret, VmSafe.AccountAccess[] memory a) {
        vm.startStateDiffRecording();
        vm.prank(RELAYER);
        (ok, ret) = t.call(cd);
        a = vm.stopAndReturnStateDiff();
    }

    /// The index of the first DELEGATECALL into the library with selector `sel` while `t` runs (reverts if none). A
    /// DELEGATECALL's `accessor` is the frame's `msg.sender`, so `t` is checked through the slot owner of the frame's
    /// storage accesses where it has any.
    function _libCall(VmSafe.AccountAccess[] memory a, address t, bytes4 sel) internal pure returns (uint256) {
        for (uint256 i; i < a.length; ++i) {
            if (a[i].kind == VmSafe.AccountAccessKind.DelegateCall && a[i].account == address(MtxPipelineLib)
                && a[i].data.length >= 4 && bytes4(a[i].data) == sel) {
                for (uint256 j; j < a[i].storageAccesses.length; ++j) {
                    require(a[i].storageAccesses[j].account == t, "the library ran in another contract's context");
                }
                return i;
            }
        }
        revert("no DELEGATECALL into MtxPipelineLib with that selector");
    }

    /// The `Ctx` (the first argument word block of every external library function that takes one) at access `i`.
    function _ctxAt(VmSafe.AccountAccess[] memory a, uint256 i) internal pure returns (MtxPipelineLib.Ctx memory) {
        return abi.decode(_slice(a[i].data, 4, 128), (MtxPipelineLib.Ctx));
    }

    /// The first call into `target` after access `from`, at a greater call depth (issued inside that frame).
    function _inside(VmSafe.AccountAccess[] memory a, uint256 from, address target) internal pure returns (uint256) {
        for (uint256 i = from + 1; i < a.length; ++i) {
            VmSafe.AccountAccessKind k = a[i].kind;
            bool isCall = k == VmSafe.AccountAccessKind.Call || k == VmSafe.AccountAccessKind.StaticCall
                || k == VmSafe.AccountAccessKind.DelegateCall || k == VmSafe.AccountAccessKind.CallCode;
            if (a[i].account == target && isCall) {
                require(a[i].depth > a[from].depth, "the access is not inside the library frame");
                return i;
            }
        }
        revert("no access to the target inside the library frame");
    }

    /// Every distinct slot of `t` written (and not reverted) in `a`.
    function _writes(VmSafe.AccountAccess[] memory a, address t) internal pure returns (bytes32[] memory all) {
        all = new bytes32[](64);
        uint256 n;
        for (uint256 i; i < a.length; ++i) {
            for (uint256 j; j < a[i].storageAccesses.length; ++j) {
                VmSafe.StorageAccess memory s = a[i].storageAccesses[j];
                if (s.account == t && s.isWrite && !s.reverted) n = _add(all, n, s.slot);
            }
        }
        assembly ("memory-safe") { mstore(all, n) }
    }

    function _add(bytes32[] memory set, uint256 n, bytes32 x) internal pure returns (uint256) {
        for (uint256 i; i < n; ++i) if (set[i] == x) return n;
        set[n] = x;
        return n + 1;
    }

    function _assertSet(bytes32[] memory got, bytes32[] memory want, string memory what) internal pure {
        assertEq(got.length, want.length, string.concat(what, ": the number of written slots"));
        for (uint256 i; i < want.length; ++i) {
            bool found;
            for (uint256 j; j < got.length; ++j) if (got[j] == want[i]) found = true;
            assertTrue(found, string.concat(what, ": an expected slot was not written"));
        }
    }

    function _nonceSlot(bytes32 from, uint256 batch) internal pure returns (bytes32) {
        return keccak256(abi.encode(batch, keccak256(abi.encode(from, MtxPipelineLib.STORAGE_SLOT))));
    }

    function _balSlot(address a) internal view returns (bytes32 s) {
        s = keccak256(abi.encode(a, uint256(0)));
        assertEq(uint256(vm.load(address(tok), s)), tok.balanceOf(a), "the _balances slot formula");
    }

    function _uaSlot(bytes32 ua) internal view returns (bytes32 s) {
        s = keccak256(abi.encode(ua, UA_STORAGE));
        assertEq(uint256(vm.load(address(tok), s)), tok.balanceOfUA(ua), "the UA ledger slot formula");
    }

    function _supplySlot() internal view returns (bytes32 s) {
        s = bytes32(uint256(2));
        assertEq(uint256(vm.load(address(tok), s)), tok.totalSupply(), "the _totalSupply slot");
    }

    function _set(bytes32 a, bytes32 b, bytes32 c, bytes32 d, bytes32 e, uint256 n)
        internal pure returns (bytes32[] memory s)
    {
        s = new bytes32[](n);
        bytes32[5] memory x = [a, b, c, d, e];
        for (uint256 i; i < n; ++i) s[i] = x[i];
    }

    /// The relayer's call of `cd` on `t` with `g` gas, state rolled back.
    function _try(address t, bytes memory cd, uint256 g) internal returns (bool ok, bytes memory ret) {
        uint256 snap = vm.snapshotState();
        vm.prank(RELAYER);
        (ok, ret) = t.call{gas: g}(cd);
        vm.revertToState(snap);
    }

    /// The smallest gas in (lo, hi] at which `cd` succeeds (success is monotone in the gas).
    function _minGas(address t, bytes memory cd, uint256 lo, uint256 hi) internal returns (uint256) {
        (bool ok,) = _try(t, cd, hi);
        assertTrue(ok, "works at the upper bound");
        (ok,) = _try(t, cd, lo);
        assertFalse(ok, "fails at the lower bound");
        while (hi - lo > 1) {
            uint256 mid = (lo + hi) / 2;
            (ok,) = _try(t, cd, mid);
            if (ok) hi = mid;
            else lo = mid;
        }
        return hi;
    }

    // ------------------------------------------------------------------ R2: the context

    /// R2: per kind on a clone (the six kinds of the parity rigs, plus `tok` with a `SmartKeyAccount` implementation and
    /// `htok` on Hedera), the `Ctx` a relayed call hands the library equals the token's own views.
    function test_ctxEqualsTokenViews() public {
        IRig[3] memory rigs = [IRig(address(new PlainRig())), IRig(address(new PqzRig())), IRig(address(new ZetherRig()))];
        PlainRig(address(rigs[0])).init();
        PqzRig(address(rigs[1])).init();
        ZetherRig(address(rigs[2])).init();
        uint256 n;
        for (uint256 r; r < 3; ++r) {
            (string[] memory kinds, address[] memory ts,) = rigs[r].setup();
            for (uint256 i; i < ts.length; ++i) {
                _checkCtx(ts[i], kinds[i]);
                ++n;
            }
        }
        assertEq(n, 7, "NONE, UNDERLYING, NONE_LEDGEROFF, NONE_PQZ, UNDERLYING_PQZ, NONE_ZETHER, UNDERLYING_ZETHER");
        _checkCtx(address(tok), "NONE+SKA");
        _checkCtx(address(htok), "NONE+HEDERA");
        assertTrue(MetaTokenBase(address(tok)).SMART_KEY_ACCOUNT_IMPL() != address(0));
        assertTrue(MetaTokenBase(address(htok)).IS_HEDERA());
    }

    function _checkCtx(address t, string memory kind) internal {
        // the typed path (an expired transfer: the library runs and refuses it) and the generic path hand one Ctx
        MtxPipelineLib.Ctx memory c = _ctxOf(t, abi.encodeCall(IERC20MetaTx.mtxExecuteTransfer,
            (MetaTxLib.MetaTransfer(address(0), address(0), 0, 0, 0, 0, 0, 0, address(0), 0, address(0)), "")),
            MtxPipelineLib.preTransfer.selector);
        MtxPipelineLib.Ctx memory c2 = _ctxOf(t, abi.encodeCall(IMetaTx.mtxExecute,
            (MetaTxLib.MetaTransaction(address(0), "", 0, 0, 0, 0, address(0), 0, address(0)), "")),
            MtxPipelineLib.preCall.selector);
        assertEq(keccak256(abi.encode(c)), keccak256(abi.encode(c2)), string.concat(kind, ": one Ctx on every path"));
        MetaTokenBase k = MetaTokenBase(t);
        assertEq(c.domainSeparator, _separator(t), string.concat(kind, ": domainSeparator"));
        assertEq(c.registry, k.registry(), string.concat(kind, ": registry"));
        address ska = k.SMART_KEY_ACCOUNT_IMPL();
        assertEq(c.skaCloneCodehash, ska == address(0) ? bytes32(0) : keccak256(_cloneCode(ska)),
            string.concat(kind, ": skaCloneCodehash"));
        assertEq(c.hedera, k.IS_HEDERA(), string.concat(kind, ": hedera"));
    }

    function _ctxOf(address t, bytes memory cd, bytes4 sel) internal returns (MtxPipelineLib.Ctx memory) {
        (bool ok,, VmSafe.AccountAccess[] memory a) = _recorded(t, cd);
        assertFalse(ok);
        return _ctxAt(a, _libCall(a, t, sel));
    }

    /// The separator of `t`'s `eip712Domain()` (ERC-5267).
    function _separator(address t) internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address vc, bytes32 salt,) =
            MetaTokenBase(t).eip712Domain();
        assertEq(vc, t);
        return keccak256(abi.encode(DOMAIN_TYPEHASH, keccak256(bytes(name)), keccak256(bytes(version)), chainId, vc, salt));
    }

    // ------------------------------------------------------------------ R2: the four digest views against the vectors

    /// `mtxDigest`, `mtxTransferDigest` (metatx_kat.json, metatransfer_kat.json), `uaDigest`, `uaTransferDigest`
    /// (clientkeys' metatx3.json: every `call`, `burn` and `transfer` row) and `mtxDigest` of a Zether kind (the
    /// zether-prover's envelope.json), each on a clone etched at the vector's token address on the vector's chain.
    function test_digestViewsEqualKats() public {
        // metatx_kat.json / metatransfer_kat.json: a `NORMAL` clone, chain 7622
        string memory j = vm.readFile("test/vectors/metatx_kat.json");
        address at = _etchNormal(vm.parseJsonAddress(j, ".verifying_contract"), vm.parseJsonBytes32(j, ".salt"), 7622);
        assertEq(MetaTokenBase(at).mtxDigest(_katTx(j)), vm.parseJsonBytes32(j, ".digest"), "metatx_kat");
        j = vm.readFile("test/vectors/metatransfer_kat.json");
        assertEq(vm.parseJsonAddress(j, ".verifying_contract"), at);
        assertEq(MetaTokenBase(at).mtxTransferDigest(_katTransfer(j)), vm.parseJsonBytes32(j, ".digest"), "metatransfer_kat");

        // clientkeys' UA vectors (metatx3.json, context A)
        j = vm.readFile("../vectors/ua/metatx3.json");
        at = _etchNormal(vm.parseJsonAddress(j, ".token"), vm.parseJsonBytes32(j, ".chainUid"), vm.parseJsonUint(j, ".chainId"));
        assertEq(_uaRows(j, at, ".call[", false) + _uaRows(j, at, ".burn[", false) + _uaRows(j, at, ".transfer[", true), 33,
            "metatx3: every call, burn and transfer row");

        // the zether-prover's envelope.json: a `NORMAL_ZETHER` clone (domain "SCaaS ZetherToken") at its token address
        ZetherRig zr = new ZetherRig();
        zr.init();
        (, address[] memory zs,) = zr.setup();
        j = vm.readFile("test/vectors/zether/s3/envelope.json");
        at = vm.parseJsonAddress(j, ".token");
        vm.etch(at, _cloneCode(_implOf(zs[0])));
        vm.chainId(vm.parseJsonUint(j, ".chainId"));
        assertEq(vm.parseJsonBytes32(j, ".chainUid"), MetaTokenBase(zs[0]).chainUid());
        assertEq(MetaTokenBase(at).mtxDigest(_envelopeTx(j)), vm.parseJsonBytes32(j, ".digest"), "zether-prover envelope");
    }

    function _u(string memory j, string memory key) internal pure returns (uint256) {
        return vm.parseUint(vm.parseJsonString(j, key));
    }

    function _katTx(string memory j) internal pure returns (MetaTxLib.MetaTransaction memory m) {
        m.from = vm.parseJsonAddress(j, ".from");
        m.data = vm.parseJsonBytes(j, ".data");
        m.batch = _u(j, ".batch");
        m.nonce = _u(j, ".nonce");
        m.validUntil = _u(j, ".valid_until");
        m.mode = uint32(_u(j, ".mode"));
        m.relayer = vm.parseJsonAddress(j, ".relayer");
        m.fee = _u(j, ".fee");
        m.feeRecipient = vm.parseJsonAddress(j, ".fee_recipient");
    }

    function _katTransfer(string memory j) internal pure returns (MetaTxLib.MetaTransfer memory t) {
        t.from = vm.parseJsonAddress(j, ".from");
        t.to = vm.parseJsonAddress(j, ".to");
        t.value = _u(j, ".value");
        t.entryRef = vm.parseJsonBytes32(j, ".entry_ref");
        t.batch = _u(j, ".batch");
        t.nonce = _u(j, ".nonce");
        t.validUntil = _u(j, ".valid_until");
        t.mode = uint32(_u(j, ".mode"));
        t.relayer = vm.parseJsonAddress(j, ".relayer");
        t.fee = _u(j, ".fee");
        t.feeRecipient = vm.parseJsonAddress(j, ".fee_recipient");
    }

    function _envelopeTx(string memory j) internal pure returns (MetaTxLib.MetaTransaction memory m) {
        m.from = vm.parseJsonAddress(j, ".meta.from");
        m.data = vm.parseJsonBytes(j, ".meta.data");
        m.batch = uint256(vm.parseJsonBytes32(j, ".meta.batch"));
        m.nonce = vm.parseJsonUint(j, ".meta.nonce");
        m.validUntil = vm.parseJsonUint(j, ".meta.validUntil");
        m.mode = uint32(vm.parseJsonUint(j, ".meta.mode"));
        m.relayer = vm.parseJsonAddress(j, ".meta.relayer");
        m.fee = vm.parseJsonUint(j, ".meta.fee");
        m.feeRecipient = vm.parseJsonAddress(j, ".meta.feeRecipient");
    }

    /// Every row of `list` (`.call[` / `.burn[`: `uaDigest`; `.transfer[`: `uaTransferDigest`) against its digest.
    function _uaRows(string memory j, address at, string memory list, bool transfer) internal view returns (uint256 n) {
        for (; vm.keyExistsJson(j, string.concat(list, vm.toString(n), "]")); ++n) {
            string memory r = string.concat(list, vm.toString(n), "].");
            string memory p = string.concat(r, "typedData.message.");
            bytes32 got = transfer ? MetaTokenBase(at).uaTransferDigest(_ut3(j, p)) : MetaTokenBase(at).uaDigest(_um3(j, p));
            assertEq(got, vm.parseJsonBytes32(j, string.concat(r, "digest")), string.concat("metatx3 ", list));
        }
    }

    function _um3(string memory j, string memory p) internal pure returns (MetaTxLib.UAMetaTransaction memory m) {
        m.from = vm.parseJsonBytes32(j, string.concat(p, "from"));
        m.data = vm.parseJsonBytes(j, string.concat(p, "data"));
        m.batch = vm.parseJsonUint(j, string.concat(p, "batch"));
        m.nonce = vm.parseJsonUint(j, string.concat(p, "nonce"));
        m.validUntil = vm.parseJsonUint(j, string.concat(p, "validUntil"));
        m.mode = uint32(vm.parseJsonUint(j, string.concat(p, "mode")));
        m.relayer = vm.parseJsonAddress(j, string.concat(p, "relayer"));
        m.fee = vm.parseJsonUint(j, string.concat(p, "fee"));
        m.feeRecipient = vm.parseJsonAddress(j, string.concat(p, "feeRecipient"));
    }

    function _ut3(string memory j, string memory p) internal pure returns (MetaTxLib.UAMetaTransfer memory t) {
        t.from = vm.parseJsonBytes32(j, string.concat(p, "from"));
        t.to = vm.parseJsonBytes32(j, string.concat(p, "to"));
        t.value = vm.parseJsonUint(j, string.concat(p, "value"));
        t.entryRef = vm.parseJsonBytes32(j, string.concat(p, "entryRef"));
        t.batch = vm.parseJsonUint(j, string.concat(p, "batch"));
        t.nonce = vm.parseJsonUint(j, string.concat(p, "nonce"));
        t.validUntil = vm.parseJsonUint(j, string.concat(p, "validUntil"));
        t.mode = uint32(vm.parseJsonUint(j, string.concat(p, "mode")));
        t.relayer = vm.parseJsonAddress(j, string.concat(p, "relayer"));
        t.fee = vm.parseJsonUint(j, string.concat(p, "fee"));
        t.feeRecipient = vm.parseJsonAddress(j, string.concat(p, "feeRecipient"));
    }

    function _etchNormal(address at, bytes32 uid, uint256 chainId) internal returns (address) {
        vm.chainId(chainId);
        NormalToken impl = new NormalToken(1, plainEnv(address(this), address(0), uid, address(0), false), "");
        vm.etch(at, _cloneCode(address(impl)));
        return at;
    }

    function _cloneCode(address impl) internal pure returns (bytes memory) {
        return abi.encodePacked(hex"363d3d373d3d3d363d73", impl, hex"5af43d82803e903d91602b57fd5bf3");
    }

    function _implOf(address clone) internal view returns (address) {
        return address(bytes20(_slice(clone.code, 10, 20)));
    }

    // ------------------------------------------------------------------ R7: the written slots

    /// R7: per path, the slots a relayed call writes are exactly the ones behind R1's recorded fields (the lane's nonce,
    /// the balances that move, the supply on a burn): nothing else, so the library writes no slot beyond the nonce. (The
    /// library frame alone, through a harness: `MtxPipelineLibTest.test_preCall_writesOnlyTheNonceSlot`; the state-diff
    /// `Resume` entries do not delimit a frame reliably past a nested sub-call, so the frame split is not read here.)
    function test_relayedCall_writesRecordedSlots() public {
        bytes32 relayer = _balSlot(RELAYER);
        // mtxExecute: burn(1,000) with a fixed fee of 5 to the relayer
        MetaTxLib.MetaTransaction memory m = _mt(alice, abi.encodeCall(NormalToken.burn, (1_000)), 11,
            RR | MetaTxLib.MODE_FEE_FIXED, 5);
        _checkWrites(abi.encodeCall(IMetaTx.mtxExecute, (m, _ecdsa(ALICE_PK, tok.mtxDigest(m)))), "mtxExecute",
            _set(_nonceSlot(MetaTxLib.pad(alice), 11), _balSlot(alice), relayer, _supplySlot(), 0, 4));
        // uaExecute: the `mldsa65` UA burns through UA_POOL, fee from its ledger
        MetaTxLib.UAMetaTransaction memory um = _um(u, abi.encodeCall(NormalToken.burn, (1_000)), 12,
            RR | MetaTxLib.MODE_FEE_FIXED, 5);
        _checkWrites(abi.encodeCall(IUALedger.uaExecute, (um, _mlAuth())), "uaExecute",
            _set(_nonceSlot(u, 12), _uaSlot(u), _balSlot(MetaTxLib.UA_POOL), _supplySlot(), relayer, 5));
        // mtxExecuteTransfer: alice -> BOB 100, fee 5
        MetaTxLib.MetaTransfer memory t = _tr(alice, BOB, 13);
        _checkWrites(abi.encodeCall(IERC20MetaTx.mtxExecuteTransfer, (t, _ecdsa(ALICE_PK, tok.mtxTransferDigest(t)))),
            "mtxExecuteTransfer", _set(_nonceSlot(MetaTxLib.pad(alice), 13), _balSlot(alice), _balSlot(BOB), relayer, 0, 4));
        // uaExecuteTransfer: u -> BOB 100, fee 5
        MetaTxLib.UAMetaTransfer memory ut = _ut(u, MetaTxLib.pad(BOB), 14);
        _checkWrites(abi.encodeCall(IUALedger.uaExecuteTransfer, (ut, _mlAuth())), "uaExecuteTransfer",
            _set(_nonceSlot(u, 14), _uaSlot(u), _balSlot(MetaTxLib.UA_POOL), _balSlot(BOB), relayer, 5));
    }

    function _checkWrites(bytes memory cd, string memory path, bytes32[] memory want) internal {
        (bool ok, bytes memory ret, VmSafe.AccountAccess[] memory a) = _recorded(address(tok), cd);
        assertTrue(ok, vm.toString(ret));
        _assertSet(_writes(a, address(tok)), want, path);
    }

    // ------------------------------------------------------------------ R8: the extra frame and the 63/64 rule

    /// R8: a `SmartKeyAccount` clone signs an `mtxExecute`. Its ERC-1271 call, now issued from the library frame (two
    /// frames below the token's entry), gets the 400,000 cap (the library's copy of the `skaCloneCodehash` rule). The
    /// smallest working call gas is logged (Task 8's node floor input); one gas less reverts with the SigCheck starvation
    /// error for that cap, never as a bad signature.
    function test_minGas_smartKeyAccountMtxExecute() public {
        address acct = fac.deploy(SubjectKey(KeyKind.SECP256K1, bytes32(uint256(uint160(vm.addr(SKA_PK)))), 0, 0, 0),
            address(0x6A2D));
        tok.mint(acct, 1_000);
        MetaTxLib.MetaTransaction memory m = _mt(acct, abi.encodeCall(IMetaTx.cancelNonce, (9)), 1, RR, 0);
        bytes memory sig = abi.encode(uint256(0), new bytes32[](0), _ecdsa(SKA_PK, tok.mtxDigest(m)));
        bytes memory cd = abi.encodeCall(IMetaTx.mtxExecute, (m, sig));
        // the ERC-1271 STATICCALL comes from the library's frame
        uint256 snap = vm.snapshotState();
        (bool ok, bytes memory ret, VmSafe.AccountAccess[] memory a) = _recorded(address(tok), cd);
        assertTrue(ok, vm.toString(ret));
        uint256 i = _inside(a, _libCall(a, address(tok), MtxPipelineLib.preCall.selector), acct);
        assertTrue(a[i].kind == VmSafe.AccountAccessKind.StaticCall);
        assertEq(a[i].accessor, address(tok));
        vm.revertToState(snap);

        uint256 g = _minGas(address(tok), cd, 300_000, 2_000_000);
        console2.log("min gas, SmartKeyAccount-signed mtxExecute (relayer's call gas):", g);
        console2.log("spec section 9 node floor ERC1271_FLOOR (21,000 + 400,000 * 64/63 + 5,000):", uint256(432_349));
        (ok, ret) = _try(address(tok), cd, g - 1);
        assertFalse(ok);
        assertEq(bytes4(ret), SigCheck.SigCheckGasStarved.selector, "below the minimum: starvation, not a verdict");
        (uint256 cap,) = abi.decode(_slice(ret, 4, 64), (uint256, uint256));
        assertEq(cap, MtxPipelineLib.SMART_KEY_1271_GAS, "the SmartKeyAccount cap");
    }

    /// R8: an `mldsa65` UA's `uaExecute`: the registry's verify, now issued from the library frame, keeps its hold. The
    /// smallest working relayer's call gas is logged. Below the smallest working frame gas the call runs out of gas or
    /// reverts with the registry's starvation error (`UAVerifyGas`, the UA path's counterpart of `SigCheckGasStarved`),
    /// never with a verdict. (At the transaction level the EIP-7976 calldata floor of the 3,309-byte signature hides the
    /// window, so the sweep runs on frames.)
    function test_minGas_mldsa65UaExecute() public {
        MetaTxLib.UAMetaTransaction memory m = _um(u, abi.encodeCall(NormalToken.burn, (10)), 2, 0, 0);
        bytes memory cd = abi.encodeCall(IUALedger.uaExecute, (m, _mlAuth()));
        uint256 snap = vm.snapshotState();
        (bool ok, bytes memory ret, VmSafe.AccountAccess[] memory a) = _recorded(address(tok), cd);
        assertTrue(ok, vm.toString(ret));
        uint256 i = _inside(a, _libCall(a, address(tok), MtxPipelineLib.preCall.selector), address(reg));
        assertTrue(a[i].kind == VmSafe.AccountAccessKind.StaticCall);
        assertEq(a[i].accessor, address(tok));
        vm.revertToState(snap);

        uint256 g = _minGas(address(tok), cd, 100_000, 2_000_000);
        console2.log("min gas, mldsa65 uaExecute (relayer's call gas):", g);
        GasProbe p = new GasProbe();
        uint256 frameMin;
        uint256 starved;
        for (uint256 x = g; x > 60_000; x -= 1_000) {
            snap = vm.snapshotState();
            (ok, ret) = p.hit(address(tok), cd, x);
            vm.revertToState(snap);
            if (ok) {
                assertEq(starved, 0, "success is monotone in the gas");
                frameMin = x;
                continue;
            }
            bool isStarved = keccak256(ret) == keccak256(abi.encodeWithSelector(UAKinds.UAVerifyGas.selector));
            assertTrue(ret.length == 0 || isStarved, "below the minimum: out of gas or starvation, never a verdict");
            if (isStarved) ++starved;
        }
        console2.log("min frame gas (1,000 steps), mldsa65 uaExecute:", frameMin);
        assertGt(frameMin, 0);
        assertGt(starved, 0, "the registry's starvation error fires below the minimum");
    }

    // ------------------------------------------------------------------ R12: Hedera one frame deeper

    /// R12: on an `IS_HEDERA` token the HIP-632 branch is the library's copy (token -> MtxPipelineLib -> HederaLib, both
    /// DELEGATECALL) and the system contract still sees the token as its caller, by CALL (the mock halts in a static
    /// frame), on the generic, typed and UA paths.
    function test_hedera_hip632CallerIsToken() public {
        address t = address(htok);
        MetaTxLib.MetaTransaction memory m = _mt(hed, abi.encodeCall(IMetaTx.cancelNonce, (9)), 1, RR, 0);
        _hip632(t, abi.encodeCall(IMetaTx.mtxExecute, (m, _ed(htok.mtxDigest(m)))), MtxPipelineLib.preCall.selector);
        MetaTxLib.MetaTransfer memory x = _tr(hed, BOB, 2);
        _hip632(t, abi.encodeCall(IERC20MetaTx.mtxExecuteTransfer, (x, _ed(htok.mtxTransferDigest(x)))),
            MtxPipelineLib.preTransfer.selector);
        MetaTxLib.UAMetaTransfer memory y = _ut(MetaTxLib.pad(hed), MetaTxLib.pad(BOB), 3);
        _hip632(t, abi.encodeCall(IUALedger.uaExecuteTransfer, (y, _ed(htok.uaTransferDigest(y)))),
            MtxPipelineLib.preTransfer.selector);
        assertEq(htok.balanceOf(BOB), 2_000);
        assertEq(htok.mtxNonce(hed, 1) + htok.mtxNonce(hed, 2) + htok.mtxNonce(hed, 3), 3);
    }

    function _hip632(address t, bytes memory cd, bytes4 sel) internal {
        (bool ok, bytes memory ret, VmSafe.AccountAccess[] memory a) = _recorded(t, cd);
        assertTrue(ok, vm.toString(ret));
        uint256 l = _libCall(a, t, sel);
        uint256 h = _inside(a, l, address(HederaLib));
        assertTrue(a[h].kind == VmSafe.AccountAccessKind.DelegateCall, "HederaLib by DELEGATECALL from the library");
        uint256 s = _inside(a, h, HAS);
        assertTrue(a[s].kind == VmSafe.AccountAccessKind.Call, "HIP-632 by CALL");
        assertEq(a[s].accessor, t, "HIP-632 sees the token as its caller");
    }
}
