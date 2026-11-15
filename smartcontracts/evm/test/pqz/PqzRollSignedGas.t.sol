// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console2, Vm} from "forge-std/Test.sol";
import {PqzSlots} from "./PqzState.t.sol";
import {GasBurner, _qm1BlobCode} from "./PqzStateGas.t.sol";
import {SlhStandIn, PQZ_UID} from "./helpers/PqzRegistryBase.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {IPqzToken} from "../../src/pqz/IPqzToken.sol";
import {NormalPqzToken} from "../../src/pqz/NormalPqzToken.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UACall} from "../ua/UACall.sol";
import {MtxDigest} from "../helpers/MtxDigest.sol";
import {Catalogue, pqzEnv} from "../helpers/Catalogue.sol";
import {EnvKit} from "../helpers/EnvKit.sol";
import {nid} from "../helpers/Ids.sol";

/// @notice Step 8 (spec 2026-11-13-pqz-three-keys §7, K3-8; owner 2026-11-14 "không cần hỏi"): `ROLL_MAX` for the holder's signed
///         rollover. The rule: per set, the largest multiple of 16 whose relayed `mtxRollOverSigned` keeps the full transaction's
///         REGULAR gas within `0.75 · 2^24` on both relay paths (`mtxExecute`, an ECDSA envelope; `uaExecute`, a PQ fee UA). Worst
///         case per §7: `n` entries rolled plus `n` skip marks on further credits (each a cold slot and its own cold blob, every
///         coefficient `q − 1`), on a class-3 token with the opening (where an `msig` may hold). Measured directly at every
///         multiple of 16 up to the set's `ROLL_MAX` (no line fit), each point its own account and its own cold transaction
///         (`isolate`; a snapshot reverted around it), outer fee FIXED 7. One test per holder and path, so a run can be split
///         by `--match-test`. The verifiers stand in at their measured prices and are etched only around the measured call
///         (`setUp` runs with metering paused, where a gas-burning loop never ends). UNAUDITED.
abstract contract PqzRollSignedGasBase is PqzSlots {
    uint256 internal constant CAP = (uint256(1) << 24) * 3 / 4; // 12,582,912
    uint256 internal constant PRE = 16; // entries rolled before the measured call (acc materialised)
    uint256 internal constant RM = PqzCore.ROLL_MAX;
    uint256 internal constant RKEY = 0xA11CE;
    address internal constant RELAYER = address(0x7E1A7E);
    uint256 internal constant FN_SIG = 666;

    uint256 internal nextBlob = 0x5EED0000;
    uint8 internal nextSeed = 100;
    bytes32 internal fee; // the `uaExecute` fee UA

    /// The ECDSA signer's and the fee UA's balances on the token.
    function _fund(bytes32 f) internal {
        _public(tok, vm.addr(RKEY), 1000);
        NormalPqzToken(address(tok)).mintToUA(f, 1000, EnvKit.codeUidOf(address(tok))); // round 3zb: the chain word
        minted += 1000;
    }

    /// The verifiers at their measured prices, after the mocks are cleared (subclass).
    function _burners() internal virtual;

    /// A single-key holder (default `mldsa65`) and its auth bytes (the filler signature).
    function _holderOne(uint8 seed) internal virtual returns (bytes32, bytes memory) {
        return (_mldsaUA(seed), _single(ML65_SIG));
    }

    function _single(uint256 sigLen) internal pure returns (bytes memory) {
        return abi.encode(bytes(""), new bytes(sigLen));
    }

    /// An `fndsa512` UA (no PQZ key): key `0x09 ‖ seed ‖ 0…` (every `h_i < q`).
    function _fnUA(uint8 seed) internal returns (bytes32) {
        bytes memory k = new bytes(897);
        (k[0], k[1]) = (0x09, bytes1(seed));
        return UACall.register(reg, UAKinds.FNDSA512, k, UACall.attrs("", 0, ""), new bytes(FN_SIG), "");
    }

    /// An `n`-of-`n` `mldsa65` `msig` (PQ-eligible, no PQZ key); its auth bytes (every member's filler signature).
    function _msig(uint8 n) internal returns (bytes32 ua, bytes memory auth) {
        bytes32[] memory ids = new bytes32[](n);
        for (uint8 i; i < n; ++i) ids[i] = _mldsaUA(nextSeed++);
        for (uint256 i = 1; i < n; ++i) for (uint256 j = i; j > 0 && ids[j - 1] > ids[j]; --j) (ids[j - 1], ids[j]) = (ids[j], ids[j - 1]);
        bytes memory d = abi.encodePacked(uint16(n), uint16(n));
        IUARegistry.MemberSig[] memory s = new IUARegistry.MemberSig[](n);
        for (uint16 i; i < n; ++i) {
            d = abi.encodePacked(d, UAKinds.MLDSA65, ids[i], uint16(1));
            s[i] = IUARegistry.MemberSig(i, new IUARegistry.InnerSig[](0), new bytes(ML65_SIG));
        }
        ua = reg.uaOf(UAKinds.MSIG, d);
        UACall.register(reg, UAKinds.MSIG, d, UACall.attrs("", 0, ""), abi.encode(s), "");
        auth = abi.encode(d, abi.encode(s));
    }

    /// `ua`'s scoped record of this token with the opening KEM key, signed by its own auth.
    function _record(bytes32 ua, bytes memory auth) internal {
        IUARegistry.KemKey memory k;
        (k.scheme, k.mlkemEk, k.x25519) = (1, _blob(uint256(ua), 1568), keccak256(abi.encode(ua)));
        reg.setPqzScopedKey(ua, address(tok), 0, _spk(++keySeed), keccak256(hex"aa"), k, type(uint64).max, UACall.auth(ua, auth));
        reg.storePqzScopedPop(ua, address(tok), 0, hex"aa");
    }

    /// `k` credits of `ua`, each pointing into its own etched blob (block 1: old enough after the roll).
    function _seed(bytes32 ua, uint256 k, bytes memory code) internal {
        for (uint256 i; i < k; ++i) {
            address b = address(uint160(++nextBlob));
            vm.etch(b, code);
            uint256 e = uint256(uint160(b)) << 96 | uint256(16) << 80 | uint256(16 + PqzCt.PKP) << 64 | 1;
            vm.store(address(tok), _pendingSlot(ua, i), bytes32(e));
        }
        vm.store(address(tok), bytes32(_acctSlot(ua)), bytes32(k));
    }

    /// The worst-case call: `n` entries rolled from `rolled`, `n` marks on the credits after them.
    function _call(bytes32 ua, bytes memory auth, uint256 n) internal view returns (bytes memory) {
        uint64 r = tok.pqzAccount(ua, 0).rolled;
        uint64[] memory skip = new uint64[](n);
        for (uint256 i; i < n; ++i) skip[i] = uint64(r + n + i);
        return abi.encodeCall(IPqzToken.mtxRollOverSigned, (ua, 0, uint64(n), skip, uint64(block.number + 1000), UACall.auth(ua, auth)));
    }

    function _gas(bytes memory data) internal returns (uint256) {
        (bool ok, bytes memory ret) = address(tok).call(data);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
        return vm.lastCallGas().gasTotalUsed;
    }

    /// `data` relayed as a full transaction with a FIXED outer fee of 7: `ua` a `uaExecute` envelope of `fee` (a filler signature
    /// of `feeSig` bytes), else an `mtxExecute` (ECDSA) envelope.
    function _fullTx(bool ua, uint256 feeSig, bytes memory data) internal returns (uint256) {
        bytes memory call;
        if (ua) {
            MetaTxLib.UAMetaTransaction memory u;
            (u.from, u.data, u.validUntil, u.mode, u.fee) = (fee, data, block.timestamp + 1 hours, MetaTxLib.MODE_FEE_FIXED, 7);
            call = abi.encodeCall(tok.mtxExecute, (u, UACall.auth(fee, abi.encode(bytes(""), new bytes(feeSig)))));
        } else {
            MetaTxLib.MetaTransaction memory m;
            (m.from, m.data, m.validUntil, m.mode, m.fee) = (vm.addr(RKEY), data, block.timestamp + 1 hours, MetaTxLib.MODE_FEE_FIXED, 7);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(RKEY, MtxDigest.metaTx(address(tok), m));
            call = abi.encodeWithSignature("executeMetaTransaction((address,bytes,uint256,uint256,uint256,uint32,address,uint256,address),bytes)",
                m, abi.encodePacked(r, s, v));
        }
        vm.clearMockedCalls();
        _burners();
        vm.prank(RELAYER);
        return _gas(call);
    }

    /// One holder kind on one path: a fresh holder per point `n = step, 2·step, …, last` (`PRE + 2n` credits, `PRE` rolled),
    /// then each worst-case call measured cold; `fit<step>` is the largest `n` of the run whose transaction stays under `CAP`.
    function _points(string memory name, bool msig_, bool ua, uint256 feeSig, uint256 step, uint256 last)
        internal returns (uint256 fit)
    {
        uint256 k = last / step;
        bytes32[] memory h = new bytes32[](k);
        bytes[] memory a = new bytes[](k);
        bytes memory code = _qm1BlobCode();
        for (uint256 i; i < k; ++i) {
            if (msig_) {
                (h[i], a[i]) = _msig(2);
            } else {
                (h[i], a[i]) = _holderOne(nextSeed++);
            }
            _record(h[i], a[i]);
            _seed(h[i], PRE + 2 * step * (i + 1), code);
        }
        vm.roll(block.number + 100);
        for (uint256 i; i < k; ++i) {
            tok.mtxPrepareAcc(h[i], 0, 0);
            tok.mtxPrepareAcc(h[i], 0, 1);
            tok.mtxRollOverSigned(h[i], 0, uint64(PRE), new uint64[](0), uint64(block.number + 1000), UACall.auth(h[i], a[i]));
        }
        string memory head = string.concat("ROLLSIG ", PqzSet.NAME, " | ", name, " | ", ua ? "uaExecute" : "mtxExecute");
        for (uint256 i; i < k; ++i) {
            uint256 n = step * (i + 1);
            bytes memory data = _call(h[i], a[i], n);
            uint256 snap = vm.snapshotState();
            uint256 g = _fullTx(ua, feeSig, data);
            vm.revertToState(snap);
            if (g <= CAP && fit == n - step) fit = n;
            console2.log(string.concat(head, " | n ", vm.toString(n), " + ", vm.toString(n), " marks | regular ", vm.toString(g),
                g <= CAP ? " | fits" : " | OVER"));
        }
        console2.log(string.concat(head, " | ROLL_MAX ", vm.toString(RM), " | fit", vm.toString(step), " ", vm.toString(fit)));
    }

    /// The ML-DSA precompile cases: `ROLL_MAX` fits the signed rollover's worst case on this path (the set's `roll_max` is sized
    /// by them, decision 2026-11-14 on CTR-PQZ-41).
    function _pinned(string memory name, bool msig_, bool ua, uint256 feeSig) internal {
        assertEq(_points(name, msig_, ua, feeSig, 16, RM), RM, "ROLL_MAX: the signed rollover's worst case fits on this path");
    }
}

/// @notice The holder's ML-DSA-65 signature through its precompile at the gas table's 100,006 [estimate] (a `GasBurner`; its fee UA on
///         `uaExecute` the same kind), for a single `mldsa65` holder and a 2-of-2 `mldsa65` `msig`.
contract PqzRollSignedGasTest is PqzRollSignedGasBase {
    function setUp() public {
        vm.pauseGasMetering();
        _stack();
        (vMode, vUA, vOwnKey, vOpening) = (PqzCore.OFFCHAIN, nid(vm.addr(0xA77E57)), true, true);
        tok = _newToken("rollsig");
        (vMode, vUA, vOwnKey, vOpening) = (0, bytes32(0), false, false);
        fee = _mldsaUA(50);
        _fund(fee);
        vm.resumeGasMetering();
    }

    function _burners() internal override {
        vm.etch(ML65, address(new GasBurner(100_006 - 2_900)).code);
    }

    function test_rollSigned_mldsa65_mtxExecute() public { _pinned("mldsa65 (precompile)", false, false, ML65_SIG); }

    function test_rollSigned_mldsa65_uaExecute() public { _pinned("mldsa65 (precompile)", false, true, ML65_SIG); }

    function test_rollSigned_msig_mtxExecute() public { _pinned("msig 2-of-2 mldsa65 (precompile)", true, false, ML65_SIG); }

    function test_rollSigned_msig_uaExecute() public { _pinned("msig 2-of-2 mldsa65 (precompile)", true, true, ML65_SIG); }
}

/// @notice A chain without the ML-DSA precompile: the registry's `mldsa65` verifier in Solidity on the cached expanded key, standing
///         in at its measured `requireAuthorized` 5,811,372 (accounts.md, P6c) under the kind's cap 5,950,000; the `uaExecute` fee
///         UA an `fndsa512` (2.3 M, cap 2.5 M: the practical PQ kinds there, accounts.md). An `msig` of two Solidity-verified
///         ML-DSA members does not fit any transaction (accounts.md register step 4) and is not measured here.
contract PqzRollSignedGasSolTest is PqzRollSignedGasBase {
    uint256 internal constant ML65_SOL = 5_811_372;
    address internal mlSol;
    address internal fnSol;

    function setUp() public {
        vm.pauseGasMetering();
        _stack();
        // a registry like the fixture's with Solidity-priced verifiers (cheap until `_burners`), its factory and release
        (mlSol, fnSol) = (address(new SlhStandIn(0)), address(new SlhStandIn(0)));
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](3);
        k[0] = UARegistry.KindConfig(UAKinds.MLDSA65, mlSol, 5_950_000);
        k[1] = UARegistry.KindConfig(UAKinds.PQZ_MLWE, address(pqv), CAP_PQZ);
        k[2] = UARegistry.KindConfig(UAKinds.FNDSA512, fnSol, 2_500_000);
        reg = new UARegistry(PQZ_UID, address(0), false, 12_000_000, address(0), true, k);
        OpenFactory f2 = new OpenFactory(nid(registrar));
        EnvKit.configure(f2, PQZ_UID, 0, address(0));
        Catalogue.release(f2, IOpenFactory.TokenKind.NORMAL_PQZ, 1, pqzEnv(address(f2), PQZ_UID, address(reg), address(pqv)),
            type(NormalPqzToken).creationCode);
        vm.prank(registrar);
        f2.setTokenKindEnabled(IOpenFactory.TokenKind.NORMAL_PQZ, true, EnvKit.uidOf(address(f2)));
        (vMode, vUA, vOwnKey, vOpening, aMode) = (PqzCore.OFFCHAIN, nid(vm.addr(0xA77E57)), true, true, 0); // no auditor: not read by a rollover
        tok = NormalPqzToken(f2.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(_cfg(uint256(1) << 40)), "rollsig-sol"));
        (vMode, vUA, vOwnKey, vOpening) = (0, bytes32(0), false, false);
        fee = _fnUA(51);
        _fund(fee);
        vm.resumeGasMetering();
    }

    function _burners() internal override {
        vm.etch(mlSol, address(new SlhStandIn(ML65_SOL)).code);
        vm.etch(fnSol, address(new SlhStandIn(2_300_000)).code);
    }

    /// Every `n` from 1 to 16 (the client rule of CTR-PQZ-41: without the precompile the holder's client signs the largest `n`
    /// that fits; reported, not pinned: it depends on the chain's verifier).
    function test_rollSignedSol_mldsa65_mtxExecute() public { _points("mldsa65 (Solidity, cached 5.81 M)", false, false, FN_SIG, 1, 16); }

    function test_rollSignedSol_mldsa65_uaExecute() public {
        _points("mldsa65 (Solidity, cached 5.81 M), fndsa512 fee UA", false, true, FN_SIG, 1, 16);
    }
}

/// @notice MD-13 (owner 2026-11-15, F-1): a chain without the ML-DSA precompile, `mldsa87` on the registry's three-part cache: the
///         holder a single `mldsa87` UA standing in at the worst accepting `verifyCached`'s least working gas 8,772,934
///         (`PqGas.t.sol`) under its cap 8,850,000; the `uaExecute` fee UA a cached `mldsa65` at its worst, 5,910,464 (cap 5,950,000).
///         Where the debit bound refuses the holder (n2560-kmax16384, n2816-kmax65536) its scoped record is `UAPqzHolder`: no
///         credit can reach a key that could not be spent. Where it is admitted, every `n` from 1 to 16 is measured and reported
///         (the client rule of CTR-PQZ-41: the holder signs the largest `n` that fits); `ROLL_MAX` itself does not fit there (it
///         is sized with precompile-priced signers). A cached ML-DSA fee signer does not fit with a cached `mldsa87` holder at all
///         (8.77 M + 5.91 M + the rollover > 12.6 M): reported, the `mtxExecute` (ECDSA) path is the holder's.
contract PqzRollSignedGasSol87Test is PqzRollSignedGasBase {
    uint256 internal constant ML87_SOL = 8_772_934;
    uint256 internal constant ML65_SOL = 5_910_464;
    uint256 internal constant ML87_SIG = 4_627;
    address internal ml87;
    address internal ml65;

    function setUp() public {
        vm.pauseGasMetering();
        _stack();
        (ml87, ml65) = (address(new SlhStandIn(0)), address(new SlhStandIn(0)));
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](3);
        k[0] = UARegistry.KindConfig(UAKinds.MLDSA87, ml87, 8_850_000);
        k[1] = UARegistry.KindConfig(UAKinds.PQZ_MLWE, address(pqv), CAP_PQZ);
        k[2] = UARegistry.KindConfig(UAKinds.MLDSA65, ml65, 5_950_000);
        reg = new UARegistry(PQZ_UID, address(0), false, 12_000_000, address(0), true, k);
        OpenFactory f2 = new OpenFactory(nid(registrar));
        EnvKit.configure(f2, PQZ_UID, 0, address(0));
        Catalogue.release(f2, IOpenFactory.TokenKind.NORMAL_PQZ, 1, pqzEnv(address(f2), PQZ_UID, address(reg), address(pqv)),
            type(NormalPqzToken).creationCode);
        vm.prank(registrar);
        f2.setTokenKindEnabled(IOpenFactory.TokenKind.NORMAL_PQZ, true, EnvKit.uidOf(address(f2)));
        (vMode, vUA, vOwnKey, vOpening, aMode) = (PqzCore.OFFCHAIN, nid(vm.addr(0xA77E57)), true, true, 0);
        tok = NormalPqzToken(f2.createToken(IOpenFactory.TokenKind.NORMAL_PQZ, 1, abi.encode(_cfg(uint256(1) << 40)), "rollsig-sol87"));
        (vMode, vUA, vOwnKey, vOpening) = (0, bytes32(0), false, false);
        fee = _mldsaUA(52);
        _fund(fee);
        vm.resumeGasMetering();
    }

    function _burners() internal override {
        vm.etch(ml87, address(new SlhStandIn(ML87_SOL)).code);
        vm.etch(ml65, address(new SlhStandIn(ML65_SOL)).code);
    }

    /// An `mldsa87` UA with the filler key `0x87 ‖ seed ‖ 0…`.
    function _holderOne(uint8 seed) internal override returns (bytes32, bytes memory) {
        bytes memory pk = new bytes(2_592);
        (pk[0], pk[1]) = (0x87, bytes1(seed));
        return (UACall.register(reg, UAKinds.MLDSA87, pk, UACall.attrs("", 0, ""), new bytes(ML87_SIG), ""), _single(ML87_SIG));
    }

    /// This set's MD-13 verdict on a cached `mldsa87` holder (`UARegistryCoreLib._pqzHolder`'s single-key bound).
    function _admitted() internal pure returns (bool) {
        return 8_850_000 + uint256(8_850_000) / 63 + 5_000 + PqzSet.PQZ_DEBIT_MIN_GAS + 16 * (192 + 4_640) <= 1 << 24;
    }

    function _run(bool ua, string memory name) internal {
        if (!_admitted()) {
            (bytes32 h, bytes memory a) = _holderOne(nextSeed++);
            IUARegistry.KemKey memory k;
            (k.scheme, k.mlkemEk, k.x25519) = (1, _blob(uint256(h), 1568), keccak256(abi.encode(h)));
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzHolder.selector, h));
            reg.setPqzScopedKey(h, address(tok), 0, _spk(++keySeed), keccak256(hex"aa"), k, type(uint64).max, UACall.auth(h, a));
            console2.log(string.concat("ROLLSIG ", PqzSet.NAME, " | ", name, " | not a PQZ holder here (MD-13): UAPqzHolder"));
            return;
        }
        uint256 fit = _points(name, false, ua, ML65_SIG, 1, 16);
        if (ua) assertEq(fit, 0, "a cached ML-DSA fee signer with a cached mldsa87 holder fits no rollover");
        else assertLt(fit, RM, "ROLL_MAX is sized with precompile-priced signers");
    }

    function test_rollSignedSol87_mtxExecute() public { _run(false, "mldsa87 (Solidity, cached 8.77 M)"); }

    function test_rollSignedSol87_uaExecute() public { _run(true, "mldsa87 (Solidity, cached 8.77 M), cached mldsa65 fee UA"); }
}
