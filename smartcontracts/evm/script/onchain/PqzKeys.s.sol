// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {console2} from "forge-std/console2.sol";
import {Tokens} from "./Tokens.s.sol";
import {kindModuleNames, kindImplArgs} from "../KindModules.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IConfidentialWrappedToken} from "../../src/confidential/IConfidentialToken.sol";
import {IPqzToken, IPqzWrappedToken} from "../../src/pqz/IPqzToken.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {PqzCt} from "../../src/pqz/PqzCt.sol";
import {NormalPqzToken} from "../../src/pqz/NormalPqzToken.sol";
import {WrappedPqzToken} from "../../src/pqz/WrappedPqzToken.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {PqUA} from "../../src/ua/PqUA.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {GovernanceLib} from "../../src/governance/GovernanceLib.sol";
import {HederaLib} from "../../src/hedera/HederaLib.sol";
import {MtxPipelineLib} from "../../src/metatx/MtxPipelineLib.sol";
import {WrappedLib} from "../../src/metatx/WrappedLib.sol";
import {RegulatedLib} from "../../src/regulated/RegulatedLib.sol";
import {PqzStateLib} from "../../src/pqz/PqzStateLib.sol";
import {PqzTransferLib} from "../../src/pqz/PqzTransferLib.sol";
import {PqzBurnLib} from "../../src/pqz/PqzBurnLib.sol";
import {PqzViewLib} from "../../src/pqz/PqzViewLib.sol";
import {PqzWrappedLib} from "../../src/pqz/PqzWrappedLib.sol";
import {MockERC20} from "../../test/helpers/Mocks.sol";

/// @notice Group `pqzkeys` (spec 2026-11-13-pqz-three-keys §15.2, step 7c): the PQZ kinds 4, 5, 12, 13 on the local chain in
///         the `OFFCHAIN` verify mode (no PQZ precompile on anvil: the releases on deps `[0]`, a verifier EOA signs each
///         `PqzVerdict`), released by this group's own factory (notice 0). Holders are ML-DSA-65 UAs (keys and signatures
///         by script/pqz/mldsa.mjs through `vm.ffi`: run with `--ffi`), each with scoped PQZ key records (K3-3). Two runs
///         (`pqzkeys.sh`): `PqzKeysSetup.setup()` the factory, the holders and their records, the public layer of every
///         PQZ kind (`Tokens`' sweep, the 212 entries the pq groups left uncalled), the confidential layer per class
///         (class 2 `offchain-shared`, class 3 with and without the sealed opening) and their negatives; then, after the
///         `ROLL_AGE` blocks, `PqzKeysRoll.roll()` the rollovers, whose signed form binds the pending slots as they are on
///         chain (a forge run simulates before it sends: a slot written in the same run would carry another block).
///         Ciphertexts and proofs are filler bytes (an `OFFCHAIN` token checks the verifier's verdict, not the proof);
///         what a wallet checks of an opening (it opens, the credit is spent; a planted bad credit) needs pqz-ffi and is
///         the pq group's (pending its three-key path). Test keys only. UNAUDITED.
abstract contract PqzKeysKit is Tokens {
    bytes internal constant VPROOF = hex"c0de";
    uint64 internal constant WIN = 10_000; // validUntilBlock windows: the simulation lags the chain by the run's sends

    OpenFactory internal fp; // this group's factory
    uint256 internal vk; // the verifier EOA's key (derived from test key 1; it signs only, no funds)
    bytes32 internal vA; // its native id
    bytes32 internal bobSeed;
    bytes32 internal carolSeed;
    bytes32 internal bob;
    bytes32 internal carol;
    address internal c2; // kind 4, class 2 (scope 0, the opening)
    address internal c3o; // kind 4, class 3 with the opening
    address internal c3; // kind 4, class 3 without the opening
    address internal t5; // kind 5, class 3 without the opening
    address internal t12; // kind 12, class 3 without the opening
    address internal t13; // kind 13, class 3 without the opening
    MockERC20 internal leg; // the confidential wrapped kinds' leg
    uint256 internal keySeed;

    function _vInit() internal {
        vk = uint256(keccak256(abi.encode("scaas.onchain.pqzkeys.verifier", k1))) % (type(uint128).max) + 1;
        vA = _pad(vm.addr(vk));
    }

    function _state() internal view returns (string memory) {
        return string.concat("deployments/pqzkeys-", net, "-state.json");
    }

    // ------------------------------------------------------------------ ML-DSA-65 holders

    function _mlBy(bytes32 seed, bytes32 uaMsg) internal returns (bytes memory) {
        return _ml(string.concat("sign 65 ", _bare(seed), " ", _bare(PqUA.pqMessage(PqUA.tag(ML65), uaMsg))));
    }

    function _uaSig(bytes32 seed, bytes32 purpose, bytes32 digest) internal returns (IUARegistry.UASig memory s) {
        s.signature = _mlBy(seed, IUARegistry(registry).uaMessage(ML65, purpose, digest));
    }

    function _seedOf(bytes32 ua) internal view returns (bytes32) {
        return ua == uaM ? mlSeed : ua == bob ? bobSeed : carolSeed;
    }

    // ------------------------------------------------------------------ the client's bytes

    /// `n` canonical bytes from `seed` (every 64-bit lane < 2^40 < q at every set).
    function _blob(uint256 seed, uint256 n) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i; i < n; i += 32) {
            uint256 w = uint256(keccak256(abi.encode(seed, i))) & 0x000000ffffffffff000000ffffffffff000000ffffffffff000000ffffffffff;
            assembly ("memory-safe") { mstore(add(add(b, 32), i), w) }
        }
    }

    function _opening(uint256 seed) internal pure returns (IPqzToken.PqzOpening memory o) {
        (o.mlkemCt, o.x25519Eph, o.sealedSeed) =
            (_blob(seed, PqzCore.MLKEM_CT), keccak256(abi.encode("eph", seed)), _blob(seed + 1, PqzCore.SEALED_SEED));
    }

    function _opens(address t) internal view returns (bool) {
        return IPqzToken(t).pqzVerifyConfig().pqzOpening;
    }

    /// Op 1 of `from` to `to` at its `pendingCount` (no fee, no auditor); on an opening token `uFrom` and `openingTo`.
    function _op1(address t, bytes32 from, bytes32 to, uint256 seed) internal view returns (IPqzToken.PqzTransferArgs memory a) {
        (a.p, a.validUntilBlock, a.fromUA, a.toUA) = (IPqzToken(t).pqzAccount(from, 0).pendingCount, block.number + WIN, from, to);
        (a.salt, a.u, a.vTo, a.vFrom) = (bytes16(keccak256(abi.encode(seed))), _blob(seed, PqzCt.PK), _blob(seed + 1, PqzCt.V),
            _blob(seed + 2, PqzCt.V));
        if (_opens(t)) (a.uFrom, a.openingTo) = (_blob(seed + 7, PqzCt.PK), _opening(seed));
    }

    /// Op 7 of `from` to `to` and a decoy leg (`M = 2`), no auditor.
    function _op7(address t, bytes32 from, bytes32 to, bytes32 decoy, uint256 seed) internal view returns (IPqzToken.PqzMultiArgs memory a) {
        (a.p, a.validUntilBlock, a.fromUA) = (IPqzToken(t).pqzAccount(from, 0).pendingCount, block.number + WIN, from);
        (a.salt, a.vFrom) = (bytes16(keccak256(abi.encode(seed))), _blob(seed + 2, PqzCt.V));
        a.u = new bytes[](1);
        a.u[0] = _blob(seed, PqzCt.PK);
        a.legs = new IPqzToken.PqzLeg[](2);
        a.legs[0] = IPqzToken.PqzLeg(to, _blob(seed + 3, PqzCt.V), "");
        a.legs[1] = IPqzToken.PqzLeg(decoy, _blob(seed + 4, PqzCt.V), "");
    }

    /// A burn of `from` at its `pendingCount`.
    function _burnArgs(address t, bytes32 from, uint256 seed) internal view returns (IPqzToken.PqzBurnArgs memory b) {
        (b.p, b.validUntilBlock, b.fromUA) = (IPqzToken(t).pqzAccount(from, 0).pendingCount, block.number + WIN, from);
        (b.u, b.vFrom) = (_blob(seed, PqzCt.PK), _blob(seed + 1, PqzCt.V));
    }

    /// The holder's `PqzAuth` digest of statement `st` under op byte `op` (PqzCore.authDigest), in `t`'s domain.
    function _authDigest(address t, uint8 op, bytes memory st) internal view returns (bytes32) {
        bytes memory head = new bytes(640);
        for (uint256 i; i < 640; ++i) head[i] = st[i];
        bytes memory body = new bytes(st.length - 640);
        for (uint256 i; i < body.length; ++i) body[i] = st[640 + i];
        return _digest(t, keccak256(abi.encodePacked(PqzCore.AUTH_TYPEHASH, uint256(op), head, keccak256(body))));
    }

    function _auth(address t, bytes32 from, uint8 op, bytes memory st) internal returns (IUARegistry.UASig memory) {
        return _uaSig(_seedOf(from), UAKinds.PURPOSE_ZETHER_AUTH, _authDigest(t, op, st));
    }

    /// The verifier's signed verdict over `st` and `VPROOF` on `t` (its epoch; a day).
    function _sv(address t, bytes memory st) internal view returns (IPqzToken.PqzSignedVerdict memory sv) {
        IPqzToken.PqzVerdict memory v = IPqzToken.PqzVerdict(t, block.chainid, NormalPqzToken(t).proofSystemId(), keccak256(st),
            keccak256(VPROOF), IPqzToken(t).pqzVerifyConfig().pqzVerifierEpoch, uint64(block.timestamp + 1 days));
        bytes32 d = _digest(t, keccak256(abi.encode(PqzCore.VERDICT_TYPEHASH, v)));
        (uint8 w, bytes32 r, bytes32 s) = vm.sign(vk, IUARegistry(registry).uaAuthDigest(vA, UAKinds.PURPOSE_PQZ_VERDICT, d));
        sv.pqzVerdict = v;
        sv.sig.signature = abi.encodePacked(r, s, w);
    }

    // ------------------------------------------------------------------ the confidential entries, direct (sent by test key 2)

    function _send1(address t, IPqzToken.PqzTransferArgs memory a, bool compact) internal {
        if (compact) a.sealedMemo = _blob(uint256(keccak256(abi.encode(a.salt))), PqzCore.SEALED); // the commit-reveal memo
        bytes memory st = NormalPqzToken(t).transferSingleStatement(a, 0);
        IUARegistry.UASig memory au = _auth(t, a.fromUA, 1, st);
        IPqzToken.PqzSignedVerdict memory sv = _sv(t, st);
        vm.broadcast(k2);
        if (compact) IPqzToken(t).mtxConfidentialTransferSingleCompact(a, VPROOF, au, "", sv);
        else IPqzToken(t).mtxConfidentialTransferSingle(a, VPROOF, au, "", sv);
    }

    function _send7(address t, IPqzToken.PqzMultiArgs memory a, bool compact) internal {
        if (compact) a.sealedMemo = _blob(uint256(keccak256(abi.encode(a.salt))), 2 + 40 * a.legs.length);
        bytes memory st = NormalPqzToken(t).transferStatement(a, 0);
        IUARegistry.UASig memory au = _auth(t, a.fromUA, 7, st);
        IPqzToken.PqzSignedVerdict memory sv = _sv(t, st);
        vm.broadcast(k2);
        if (compact) IPqzToken(t).mtxConfidentialTransferCompact(a, VPROOF, au, "", sv);
        else IPqzToken(t).mtxConfidentialTransfer(a, VPROOF, au, "", sv);
    }

    function _unshield(address t, bytes32 from, uint256 amount, bytes32 recipient, uint256 seed) internal {
        IPqzToken.PqzBurnArgs memory b = _burnArgs(t, from, seed);
        bytes memory st = NormalPqzToken(t).burnStatement(b, amount, recipient, 0);
        IUARegistry.UASig memory au = _auth(t, from, 2, st);
        IPqzToken.PqzSignedVerdict memory sv = _sv(t, st);
        vm.broadcast(k2);
        IPqzToken(t).mtxUnshield(b, amount, recipient, VPROOF, au, "", sv);
    }

    function _unshieldUnwrap(address t, bytes32 from, uint256 amount, uint256 seed) internal {
        IPqzToken.PqzBurnArgs memory b = _burnArgs(t, from, seed);
        IConfidentialWrappedToken.Unwrap memory x = IConfidentialWrappedToken.Unwrap(address(leg), _pad(a3), amount, 0);
        bytes memory st = WrappedPqzToken(payable(t)).unshieldUnwrapStatement(b, x, 0);
        IUARegistry.UASig memory au = _auth(t, from, 2, st);
        IPqzToken.PqzSignedVerdict memory sv = _sv(t, st);
        vm.broadcast(k2);
        IPqzWrappedToken(t).mtxUnshieldUnwrap(b, x, VPROOF, au, "", sv);
    }

    // ------------------------------------------------------------------ the signed rollover (CTR-PQZ-41)

    bytes32 internal constant ROLL_TH = keccak256(
        "PqzRollOver(bytes32 ua,uint64 keyVersion,uint64 rollSeq,uint64 rolled,uint64 n,uint64[] skip,bytes32 entriesHash,uint64 validUntilBlock,bytes32 chainUid)"
    );

    /// The client's `h(i)`: the slot without the mark, the blob's code hash or 0 for a TRIVIAL entry.
    function _eh(address t, bytes32 ua, uint256 i) internal view returns (bytes32) {
        uint256 e = IPqzToken(t).pqzPending(ua, 0, uint64(i)) & ~uint256(PqzCore.SKIP);
        bytes32 c = uint16(e >> 64) == 0 ? bytes32(0) : address(uint160(e >> 96)).codehash;
        return keccak256(abi.encode(i, e, c));
    }

    function _entries(address t, bytes32 ua, uint64 n, uint64[] memory skip) internal view returns (bytes32) {
        uint64 r = IPqzToken(t).pqzAccount(ua, 0).rolled;
        bytes32[] memory h = new bytes32[](n + skip.length);
        for (uint256 k_; k_ < n; ++k_) h[k_] = _eh(t, ua, r + k_);
        for (uint256 j; j < skip.length; ++j) h[n + j] = _eh(t, ua, skip[j]);
        return keccak256(abi.encodePacked(h));
    }

    function _rollDigest(address t, bytes32 ua, uint64 n, uint64[] memory skip, uint64 vub, bytes32 eh)
        internal view returns (bytes32)
    {
        IPqzToken.AccountState memory s = IPqzToken(t).pqzAccount(ua, 0);
        return _digest(t, keccak256(bytes.concat(abi.encode(ROLL_TH, ua, uint64(0), s.rollSeq, s.rolled, n),
            abi.encode(keccak256(abi.encodePacked(skip)), eh, vub, NormalPqzToken(t).chainUid()))));
    }

    function _rollSig(address t, bytes32 ua, uint64 n, uint64[] memory skip, uint64 vub) internal returns (IUARegistry.UASig memory) {
        return _uaSig(_seedOf(ua), UAKinds.PURPOSE_ZETHER_AUTH, _rollDigest(t, ua, n, skip, vub, _entries(t, ua, n, skip)));
    }

    function _sk(uint64 a) internal pure returns (uint64[] memory s) {
        s = new uint64[](1);
        s[0] = a;
    }

    // ------------------------------------------------------------------ the PQZ kinds of `Tokens`' sweep

    function _pqzKind(uint8 kind) internal pure returns (bool) {
        return kind == 4 || kind == 5 || kind == 12 || kind == 13;
    }

    function _label(uint8 kind) internal pure override returns (string memory) {
        if (kind == 4) return "NormalPqzToken";
        if (kind == 5) return "WrappedPqzToken";
        if (kind == 12) return "NormalPqzRegulatedToken";
        if (kind == 13) return "WrappedPqzRegulatedToken";
        return super._label(kind);
    }

    /// A PQZ kind: `OFFCHAIN`, class 3 without the opening (the verifier `vA`, transferable).
    function _conf(bool own, bool open) internal view returns (IFactoryToken.ConfidentialConfig memory) {
        return IFactoryToken.ConfidentialConfig("", 10_000, uint256(1) << 40, 0, 0, 0, 0, 1, vA, false, 0, 0, 0, own, open);
    }

    function _base(uint8 kind, string memory sym) internal view override returns (IFactoryToken.TokenConfig memory c) {
        c = super._base(kind, sym);
        if (_pqzKind(kind)) c.conf = _conf(true, false);
    }

    function _create(uint8 kind, IFactoryToken.TokenConfig memory c, string memory what) internal override returns (address x) {
        if (!_pqzKind(kind)) return super._create(kind, c, what);
        vm.broadcast(k1);
        x = fp.createToken(IOpenFactory.TokenKind(kind), 1, abi.encode(c), _salt(what));
        _book(x, _label(kind));
    }
}

/// @notice Run 1: the factory and the releases, the holders and their records, the public layer of the PQZ kinds, the
///         confidential layer per class, the negatives.
contract PqzKeysSetup is PqzKeysKit {
    function setup() external {
        _init("pqzkeys");
        _vInit();
        f = OpenFactory(_dep("token_factory"));
        router = _dep("relay_fee_router");
        registry = _dep("ua_registry");
        compliance = _dep("compliance_registry");
        _book(address(f), "OpenFactory");
        _book(router, "RelayFeeRouter");
        _book(_dep("relay_fee_executor"), "RelayFeeExecutor");
        _book(registry, "UARegistry");
        _fixtures();
        _registerDerived();
        _registerMl();
        (bobSeed, bob) = _holder("bob");
        (carolSeed, carol) = _holder("carol");
        _factory();
        _publicLayer();
        _confidential();
        _registryNegatives();
        _factoryNegatives();
        _save();
        _writeBook();
    }

    /// An ML-DSA-65 UA registered as `_registerMl` (Tokens), its seed from this run.
    function _holder(string memory who) internal returns (bytes32 seed, bytes32 ua) {
        seed = keccak256(abi.encode(runSalt, "pqzkeys", who));
        bytes memory pk = _ml(string.concat("keygen 65 ", _bare(seed)));
        ua = UAKinds.uaOf(ML65, pk);
        bytes32 rd = UAKinds.registrationDigest(ua, ML65, 0, UAKinds.kemRecordHash(ua, 0, bytes("")), 0);
        bytes memory pop = _mlBy(seed, IUARegistry(registry).uaMessage(ML65, UAKinds.PURPOSE_POP_V2, rd));
        IUARegistry.UAAttrs memory none;
        vm.startBroadcast(k1);
        IUARegistry(registry).cacheExpandedKey{gas: 56_000_000}(ML65, pk, 0);
        IUARegistry(registry).cacheExpandedKey{gas: 56_000_000}(ML65, pk, 1);
        require(IUARegistry(registry).register{gas: 56_000_000}(ML65, pk, none, pop, "") == ua, "holder UA");
        vm.stopBroadcast();
    }

    // ------------------------------------------------------------------ the factory: kinds 4, 5, 12, 13 on deps [0]

    function _factory() internal {
        vm.broadcast(k1);
        fp = new OpenFactory(_pad(a1));
        _book(address(fp), "OpenFactory");
        bytes32 uid = vm.parseJsonBytes32(dj, ".chain_uid");
        address gr = _dep("governance_router");
        vm.broadcast(k1);
        fp.configureChain(uid, 0, gr, gr.codehash, 0, bytes32(0));
        IFactoryToken.Env memory e = f.tokenEnvOf(IOpenFactory.TokenKind.WRAPPED, 1);
        uint8[4] memory ks = [uint8(4), 5, 12, 13];
        for (uint256 i; i < 4; ++i) _release(ks[i], e);
        vm.startBroadcast(k1);
        leg = new MockERC20("Onchain PQZ leg", "oPQL", 6);
        leg.mint(a1, 1e18);
        vm.stopBroadcast();
        _book(address(leg), "MockERC20");
    }

    function _libs(uint8 k_) internal pure returns (address[] memory l) {
        l = new address[](k_ >= 12 ? 10 : 9);
        (l[0], l[1], l[2], l[3]) = (address(GovernanceLib), address(HederaLib), address(MtxPipelineLib), address(WrappedLib));
        (l[4], l[5], l[6], l[7], l[8]) =
            (address(PqzStateLib), address(PqzTransferLib), address(PqzBurnLib), address(PqzViewLib), address(PqzWrappedLib));
        if (k_ >= 12) l[9] = address(RegulatedLib);
    }

    function _release(uint8 k_, IFactoryToken.Env memory e) internal {
        bytes memory core = k_ >= 12 ? abi.encode(vm.parseJsonBytes32(dj, ".compliance_registry_codehash")) : bytes("");
        address[] memory ms = _modules(k_, core);
        IOpenFactory.TokenKind kind = IOpenFactory.TokenKind(k_);
        bytes32 uid = fp.chainUid();
        vm.broadcast(k1);
        fp.publishTokenEnv(kind, 1, uid, _envOf(k_, e, ms));
        _implement(k_, kindImplArgs(k_, ms, core), uid);
    }

    function _modules(uint8 k_, bytes memory core) internal returns (address[] memory ms) {
        string[] memory n = kindModuleNames(k_);
        ms = new address[](n.length);
        for (uint256 j; j < n.length; ++j) {
            bytes memory init = bytes.concat(vm.getCode(n[j]), abi.encode(address(fp), core));
            bytes32 sl = _salt(string.concat("pqzkeys-module-", n[j]));
            ms[j] = vm.computeCreate2Address(sl, keccak256(init), CREATE2_FACTORY);
            vm.broadcast(k1);
            (bool ok,) = CREATE2_FACTORY.call(bytes.concat(sl, init));
            require(ok && ms[j].code.length != 0, n[j]);
        }
    }

    function _envOf(uint8 k_, IFactoryToken.Env memory e, address[] memory ms) internal view returns (IFactoryToken.Env memory) {
        address[] memory libs = _libs(k_);
        address[] memory l = new address[](libs.length + ms.length);
        bytes32[] memory h = new bytes32[](l.length);
        for (uint256 j; j < l.length; ++j) {
            l[j] = j < libs.length ? libs[j] : ms[j - libs.length];
            h[j] = l[j].codehash;
        }
        return IFactoryToken.Env(e.registry, e.smartKeyAccountImpl, false, new address[](1), new bytes32[](0), l, h);
    }

    function _implement(uint8 k_, bytes memory implArgs, bytes32 uid) internal {
        IOpenFactory.TokenKind kind = IOpenFactory.TokenKind(k_);
        bytes memory code = vm.getCode(string.concat(_label(k_), ".sol:", _label(k_)));
        vm.startBroadcast(k1);
        fp.deployTokenImplementation{gas: 56_000_000}(kind, 1, 1, code, implArgs, uid);
        fp.setTokenKindEnabled(kind, true, uid);
        vm.stopBroadcast();
    }

    // ------------------------------------------------------------------ the public layer (Tokens' sweep on the PQZ kinds)

    function _publicLayer() internal {
        // W2's SCaaS ledger leg: a kind-0 token of the Step 5 factory
        IFactoryToken.TokenConfig memory c = super._base(0, "oNb");
        c.features = 1 << GovernanceBits.PAYABLE;
        (c.initialSupply, c.initialHolder) = (1e15, a1);
        base = _create(0, c, "pqzkeys-base");
        _normalKind(4);
        _normalKind(12);
        _wrappedKind(5);
        _wrappedKind(13);
    }

    // ------------------------------------------------------------------ the confidential layer

    function _token(uint8 kind, bool own, bool open, string memory what) internal returns (address x) {
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.admin) = (string.concat("Onchain PQZ ", what), "oPQ", 6, _pad(a1));
        c.features = 1 << GovernanceBits.PAYABLE;
        if (kind == 4 || kind == 12) (c.initialSupply, c.initialHolder) = (1e15, a1);
        c.conf = _conf(own, open);
        if (kind == 5 || kind == 13) {
            c.legs = new IFactoryToken.Leg[](1);
            c.legs[0] = IFactoryToken.Leg(address(leg), 1, 1);
        }
        if (kind >= 12) c.reg.termsHash = keccak256("onchain pqzkeys terms");
        if (kind == 12) c.features |= 1 << GovernanceBits.PQZ_PROOF; // t12: the proof store's switch (`_verifierOps`)
        x = _create(kind, c, string.concat("pqzkeys-", what));
        if (kind == 5 || kind == 13) {
            vm.startBroadcast(k1);
            leg.approve(x, type(uint256).max);
            WrappedPqzToken(payable(x)).wrap(uint256(1e15));
            vm.stopBroadcast();
        }
    }

    /// K3-3: `ua`'s scoped record of `scope` at version `v` (fresh key bytes; `kem`: the opening KEM key), signed by its
    /// ML-DSA key, then its proof bytes stored (unchecked: no 0x0142 verifier on anvil).
    function _scoped(bytes32 ua, address scope, uint64 v, bool kem) internal {
        (bytes memory key, IUARegistry.KemKey memory k, bytes memory pop) = _record(ua, scope, v, kem);
        uint64 vub = uint64(block.number + WIN);
        IUARegistry.UASig memory s = _recordSig(ua, scope, v, key, k, pop, vub, IUARegistry(registry).chainUid());
        vm.startBroadcast(k1);
        IUARegistry(registry).setPqzScopedKey{gas: 56_000_000}(ua, scope, v, key, keccak256(pop), k, vub, s);
        IUARegistry(registry).storePqzScopedPop{gas: 56_000_000}(ua, scope, v, pop);
        vm.stopBroadcast();
    }

    function _record(bytes32 ua, address scope, uint64 v, bool kem)
        internal returns (bytes memory key, IUARegistry.KemKey memory k, bytes memory pop)
    {
        key = new bytes(PqzCt.PK);
        (key[13], key[14], key[15]) = (bytes1(0x5c), bytes1(uint8(++keySeed >> 8)), bytes1(uint8(keySeed)));
        if (kem) (k.scheme, k.mlkemEk, k.x25519) = (1, _blob(uint256(keccak256(abi.encode(ua, scope, v))), 1568), keccak256(abi.encode(ua, scope, v)));
        pop = abi.encodePacked(keccak256(abi.encode(runSalt, ua, scope, v)));
    }

    struct RecDigest {
        bytes32 ua;
        address scope;
        uint64 v;
        bytes32 keyHash;
        bytes32 popHash;
        bytes32 kemHash;
        uint64 vub;
        bytes32 uid;
    }

    function _recordSig(bytes32 ua, address scope, uint64 v, bytes memory key, IUARegistry.KemKey memory k, bytes memory pop,
        uint64 vub, bytes32 uid) internal returns (IUARegistry.UASig memory)
    {
        bytes memory kp = UAKinds.kemPk(k);
        RecDigest memory r = RecDigest(ua, scope, v, UAKinds.keyHashOf(UAKinds.PQZ_MLWE, key), keccak256(pop),
            kp.length == 0 ? bytes32(0) : keccak256(kp), vub, uid);
        return _uaSig(_seedOf(ua), UAKinds.PURPOSE_PQZ_SCOPED_KEY, _rd(r));
    }

    function _rd(RecDigest memory r) internal view returns (bytes32) {
        return IUARegistry(registry).pqzScopedKeyRecordDigest(r.ua, r.scope == address(0) ? 2 : 3, r.uid, r.scope, r.v,
            r.keyHash, r.popHash, r.kemHash, r.vub);
    }

    function _shield(address t, bytes32 ua, uint256 amount) internal {
        vm.broadcast(k1);
        NormalPqzToken(t).mtxShield(ua, amount);
    }

    function _confidential() internal {
        c2 = _token(4, false, true, "c2");
        c3o = _token(4, true, true, "c3o");
        c3 = _token(4, true, false, "c3");
        t5 = _token(5, true, false, "t5");
        t12 = _token(12, true, false, "t12");
        t13 = _token(13, true, false, "t13");
        bytes32[3] memory hs = [uaM, bob, carol];
        for (uint256 i; i < 3; ++i) {
            _scoped(hs[i], address(0), 0, true); // class 2: the shared key, its opening KEM key
            _scoped(hs[i], c3o, 0, true);
            _scoped(hs[i], c3, 0, false);
            _scoped(hs[i], t5, 0, false);
            _scoped(hs[i], t12, 0, false);
            _scoped(hs[i], t13, 0, false);
        }
        // the scoped views
        require(IUARegistry(registry).pqzScopedKeyLatest(bob, c3o) == 0 && IUARegistry(registry).pqzScopedCount(c3) == 3, "scoped");
        address[6] memory ts = [c2, c3o, c3, t5, t12, t13];
        for (uint256 i; i < 6; ++i) _life(ts[i], i);
        _relayedShield(c3);
        _wrapShield(t5);
        _wrapShield(t13);
        _rotation();
        _verifierOps(t12);
        console2.log(string.concat("pqzkeys setup c2 ", vm.toString(c2), " c3o ", vm.toString(c3o), " c3 ", vm.toString(c3)));
    }

    /// A token's life before its rollovers: three shields (the holder's TRIVIAL entry first), credits to the holder uaM from bob
    /// (op 1, op 1 compact) and carol (op 1: on an opening token the planted credit the holder marks), then the forms each
    /// class takes: op 7 and its compact form without the opening (`OpUnsupported` with it, a negative), an unshield and a
    /// refresh, an unshield-unwrap on a wrapped kind.
    function _life(address t, uint256 i) internal {
        uint256 s = 0x7c00 + 0x100 * i;
        _shield(t, bob, 50);
        _shield(t, carol, 50);
        _shield(t, uaM, 100);
        _send1(t, _op1(t, bob, uaM, s + 1), false);
        _send1(t, _op1(t, carol, uaM, s + 11), false);
        _send1(t, _op1(t, bob, uaM, s + 21), true);
        if (_opens(t)) {
            IPqzToken.PqzMultiArgs memory m = _op7(t, carol, bob, uaM, s + 41);
            IPqzToken.PqzSignedVerdict memory none;
            _neg(a2, t, abi.encodeCall(IPqzToken.mtxConfidentialTransfer, (m, VPROOF, _pqStub(), "", none)),
                IPqzToken.OpUnsupported.selector, string.concat(_label(t), ": op 7 with the opening on"));
        } else {
            _send7(t, _op7(t, carol, bob, uaM, s + 31), false);
            _send7(t, _op7(t, carol, bob, uaM, s + 41), true);
        }
        _unshield(t, bob, 5, _pad(a3), s + 51);
        _unshield(t, bob, 0, bytes32(0), s + 61);
        if (t == t5 || t == t13) _unshieldUnwrap(t, carol, 3, s + 71);
        // bob's credit after his debits (each sets his `rolled` to its p): run 2's mark-only account
        if (_opens(t)) {
            _send1(t, _op1(t, carol, bob, s + 31), false);
            _shield(t, bob, 10); // bob's entry 2, TRIVIAL and above his `rolled`: run 2's SkipTrivial negative
        }
        vm.startBroadcast(k1);
        IPqzToken(t).mtxPrepareAcc(uaM, 0, 0);
        IPqzToken(t).mtxPrepareAcc(uaM, 0, 1);
        vm.stopBroadcast();
    }

    function _label(address t) internal view returns (string memory) {
        return t == c2 ? "c2" : t == c3o ? "c3o" : t == c3 ? "c3" : t == t5 ? "t5" : t == t12 ? "t12" : "t13";
    }

    function _pqStub() internal pure returns (IUARegistry.UASig memory s) {
        s.signature = new bytes(3309);
    }

    string internal constant UA_SHIELD =
        "UAShield(bytes32 from,bytes32 toUA,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
    string internal constant WRAP_SHIELD =
        "WrapShield(address from,address underlying,uint256 amountIn,bytes32 toUA,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";

    /// `mtxShield` relayed: test key 1's native id signs, test key 2 sends.
    function _relayedShield(address t) internal {
        MetaTxLib.UAEnvelope memory e = _env(a1, 13, NormalPqzToken(t).mtxNonce(_pad(a1), 13));
        IUARegistry.UASig memory s = _sig(k1, _named(t, UA_SHIELD, abi.encode(bob, uint256(5)), e));
        vm.broadcast(k2);
        NormalPqzToken(t).mtxShield(e, bob, 5, s);
    }

    /// `mtxWrapShield` direct and relayed (the leg wrapped and shielded in one call).
    function _wrapShield(address t) internal {
        vm.broadcast(k1);
        WrappedPqzToken(payable(t)).mtxWrapShield(address(leg), 100_000, carol);
        MetaTxLib.Envelope memory e = _aenv(a1, 14, NormalPqzToken(t).mtxNonce(_pad(a1), 14));
        bytes memory s = _ecdsa(k1, _namedA(t, WRAP_SHIELD, abi.encode(address(leg), uint256(100_000), carol), e));
        vm.broadcast(k2);
        WrappedPqzToken(payable(t)).mtxWrapShield(e, address(leg), 100_000, carol, s);
    }

    /// Key rotation on a class-3 token: carol's scoped version 1, then her migration to herself from version 0 (op 1, KV-9).
    function _rotation() internal {
        _scoped(carol, c3, 1, false);
        require(IUARegistry(registry).pqzScopedKeyLatest(carol, c3) == 1, "carol v1");
        IPqzToken.PqzTransferArgs memory a = _op1(c3, carol, carol, 0x7f01);
        _send1(c3, a, false);
    }

    /// The owner's verifier ops: propose another verifier, cancel it; the verifier fee down; LOG for the next debit and back;
    /// then the revocation (last on this token).
    function _verifierOps(address t) internal {
        bytes32 uid = NormalPqzToken(t).chainUid();
        vm.startBroadcast(k1);
        IPqzToken(t).pqzSetVerifier(_pad(a3), uid);
        IPqzToken(t).pqzCancelVerifier(uid);
        NormalPqzToken(t).grantRole(GovernanceBits.PQZ_PROOF, _pad(a1), uid);
        IPqzToken(t).setProofStore(1);
        IPqzToken(t).setProofStore(0);
        IPqzToken(t).pqzRevokeVerifier(uid);
        vm.stopBroadcast();
        require(IPqzToken(t).pqzVerifyConfig().verifier == 0, "revoked");
    }

    // ------------------------------------------------------------------ negatives: the scoped records (§15.2)

    struct RecNeg {
        bytes32 ua;
        address scope; // the record's scope as sent
        address signedScope; // the scope the signature is for
        bool kem;
        bytes32 uid;
        uint64 vub;
        uint256 keyLen;
    }

    /// A `setPqzScopedKey` call (eth_call at the run's end) at `ua`'s next version, one thing changed: refused with `want`.
    function _recNeg(RecNeg memory r, bytes memory want, string memory what) internal {
        _negData(a1, registry, _recCall(r, IUARegistry(registry).pqzScopedKeyLatest(r.ua, r.scope) + 1), want, what);
    }

    function _recCall(RecNeg memory r, uint64 v) internal returns (bytes memory) {
        (bytes memory key, IUARegistry.KemKey memory k, bytes memory pop) = _record(r.ua, r.scope, v, r.kem);
        if (r.keyLen != key.length) key = _resized(key, r.keyLen);
        IUARegistry.UASig memory s = _recordSig(r.ua, r.signedScope, v, key, k, pop, r.vub, r.uid);
        return abi.encodeCall(IUARegistry.setPqzScopedKey, (r.ua, r.scope, v, key, keccak256(pop), k, r.vub, s));
    }

    function _resized(bytes memory key, uint256 n) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i; i < 16; ++i) b[i] = key[i];
    }

    function _registryNegatives() internal {
        bytes32 uid = IUARegistry(registry).chainUid();
        uint64 vub = uint64(block.number + WIN);
        uint256 pk = PqzCt.PK;
        bytes32 sib = SIBLING_WORD;
        bytes memory unauth = abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, bob);
        _recNeg(RecNeg(bob, address(0), address(0), false, uid, vub, pk),
            abi.encodeWithSelector(IUARegistry.UAPqzOpenKem.selector, address(0)), "class 2 record without openKem");
        _recNeg(RecNeg(bob, address(0), address(0), true, sib, vub, pk), unauth, "class 2 record signed for another chainUid");
        _recNeg(RecNeg(bob, address(0), address(0), true, uid, uint64(block.number - 1), pk),
            abi.encodeWithSelector(IUARegistry.UAPqzRecordExpired.selector, bob), "class 2 record expired");
        _recNeg(RecNeg(bob, address(0), address(0), true, uid, vub, pk == 18_432 ? 16_384 : 18_432),
            abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.PQZ_MLWE), "class 2 version 1 of another key length");
        _recNeg(RecNeg(bob, c3o, c3o, false, uid, vub, pk), abi.encodeWithSelector(IUARegistry.UAPqzOpenKem.selector, c3o),
            "class 3 opening on: record without openKem");
        _recNeg(RecNeg(bob, c3o, c3o, true, sib, vub, pk), unauth, "class 3 opening on: another chainUid");
        _recNeg(RecNeg(bob, c3, c3, true, uid, vub, pk), abi.encodeWithSelector(IUARegistry.UAPqzOpenKem.selector, c3),
            "class 3 opening off: record with openKem");
        _recNeg(RecNeg(bob, c3, c3, false, sib, vub, pk), unauth, "class 3 opening off: another chainUid");
        _recNeg(RecNeg(bob, t5, c3, false, uid, vub, pk), unauth, "class 3: the record of another token");
        // the public rollover on an opening token, the signed one without the opening
        _neg(a2, c2, abi.encodeCall(IPqzToken.mtxRollOver, (uaM, 0, 1)), IPqzToken.RollOverSignedOnly.selector,
            "c2: the public rollover with the opening on");
        _neg(a2, c3o, abi.encodeCall(IPqzToken.mtxRollOver, (uaM, 0, 1)), IPqzToken.RollOverSignedOnly.selector,
            "c3o: the public rollover with the opening on");
        _neg(a2, c3, abi.encodeCall(IPqzToken.mtxRollOverSigned, (uaM, 0, 1, new uint64[](0), vub, _pqStub())),
            IPqzToken.OpUnsupported.selector, "c3: the signed rollover without the opening");
        // disclosures: with the opening on, RECEIVER_X and AUDITOR refused, SENDER_S answers
        bytes32 ref = IPqzToken(c2).pqzAccount(uaM, 0).accHash; // any ref: the form is refused before the entry is read
        _neg(a2, c2, abi.encodeCall(NormalPqzToken.disclosureStatement, (ref, 0, 1, 1, 0)), IPqzToken.OpUnsupported.selector,
            "c2: a RECEIVER_X disclosure with the opening on");
        _neg(a2, c2, abi.encodeCall(NormalPqzToken.disclosureStatement, (ref, 0, 1, 2, 0)), IPqzToken.OpUnsupported.selector,
            "c2: an AUDITOR disclosure with the opening on");
    }

    // ------------------------------------------------------------------ negatives: the factory's key classes

    function _factoryNegatives() internal {
        bytes memory bad = abi.encodeWithSelector(IPqzToken.PqzVerifyConfigInvalid.selector);
        _cfgNeg(4, 1, false, false, bad, "OFFCHAIN class 2 without the opening (pqzOpening = false)");
        _cfgNeg(4, 0, true, false, bad, "PRECOMPILE with pqzOwnKey");
        _cfgNeg(4, 0, false, true, bad, "PRECOMPILE with pqzOpening");
    }

    function _cfgNeg(uint8 kind, uint8 mode, bool own, bool open, bytes memory want, string memory what) internal {
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.admin, c.features) = ("Onchain PQZ neg", "oPQN", 6, _pad(a1), 1 << GovernanceBits.PAYABLE);
        c.conf = _conf(own, open);
        if (mode == 0) (c.conf.pqzVerifyMode, c.conf.pqzVerifierUA) = (0, bytes32(0));
        _negData(a1, address(fp), abi.encodeCall(OpenFactory.createToken, (IOpenFactory.TokenKind(kind), 1, abi.encode(c),
            _salt(what))), want, what);
    }

    function _save() internal {
        vm.serializeAddress("pk", "fp", address(fp));
        vm.serializeAddress("pk", "c2", c2);
        vm.serializeAddress("pk", "c3o", c3o);
        vm.serializeAddress("pk", "c3", c3);
        vm.serializeAddress("pk", "t5", t5);
        vm.serializeAddress("pk", "t12", t12);
        vm.serializeAddress("pk", "t13", t13);
        vm.serializeAddress("pk", "leg", address(leg));
        vm.serializeBytes32("pk", "uaM", uaM);
        vm.serializeBytes32("pk", "mlSeed", mlSeed);
        vm.serializeBytes32("pk", "bob", bob);
        vm.serializeBytes32("pk", "bobSeed", bobSeed);
        vm.serializeBytes32("pk", "carol", carol);
        vm.serializeAddress("pk", "registry", registry);
        string memory j = vm.serializeBytes32("pk", "carolSeed", carolSeed);
        vm.writeJson(j, _state());
    }
}

/// @notice Run 2 (after `ROLL_AGE` blocks): the rollovers. On the opening tokens the holder's signed form over the slots as
///         they are on chain: a mark-only call (`n = 0`) over the planted credit, a roll direct, a roll relayed by the UA
///         envelope (`mtxExecute`) and one by the address envelope (`executeMetaTransaction`), fee 0; negatives: a stale
///         `entriesHash`, the same call replayed (`rollSeq` moved), a mark on a TRIVIAL entry. Without the opening the public
///         rollover. Then a debit over the rolled `acc`.
contract PqzKeysRoll is PqzKeysKit {
    function roll() external {
        _init("pqzkeys");
        _vInit();
        registry = _dep("ua_registry");
        string memory j = vm.readFile(_state());
        (c2, c3o, c3) = (vm.parseJsonAddress(j, ".c2"), vm.parseJsonAddress(j, ".c3o"), vm.parseJsonAddress(j, ".c3"));
        (t5, t12, t13) = (vm.parseJsonAddress(j, ".t5"), vm.parseJsonAddress(j, ".t12"), vm.parseJsonAddress(j, ".t13"));
        (uaM, mlSeed) = (vm.parseJsonBytes32(j, ".uaM"), vm.parseJsonBytes32(j, ".mlSeed"));
        (bob, bobSeed) = (vm.parseJsonBytes32(j, ".bob"), vm.parseJsonBytes32(j, ".bobSeed"));
        (carol, carolSeed) = (vm.parseJsonBytes32(j, ".carol"), vm.parseJsonBytes32(j, ".carolSeed"));
        _signed(c2);
        _signed(c3o);
        address[3] memory pub = [c3, t5, t13];
        for (uint256 i; i < 3; ++i) {
            IPqzToken.AccountState memory a = IPqzToken(pub[i]).pqzAccount(uaM, 0);
            vm.broadcast(k2);
            IPqzToken(pub[i]).mtxRollOver(uaM, 0, a.pendingCount - a.rolled);
        }
        _send1(c2, _op1(c2, uaM, bob, 0x7e01), false); // a debit over the rolled acc (the book is run 1's)
    }

    /// On an opening token: uaM's entries 0 TRIVIAL (its shield), 1 bob, 2 carol (the planted credit), 3 bob (compact); bob's 0
    /// TRIVIAL, 1 carol, 2 TRIVIAL (a shield). uaM rolls 2 marking 2 (direct), then 1 relayed by the UA envelope (`mtxExecute`, test key 1's native id
    /// signs, test key 3 sends) and 1 by the address envelope (`executeMetaTransaction`), fee 0; bob marks 1 only (`n = 0`).
    /// The negatives hold on the final state (`coverage.py neg` runs after): bob's mark-only call replayed (`rollSeq` moved),
    /// a stale `entriesHash`, a mark on his TRIVIAL entry.
    function _signed(address t) internal {
        uint64 vub = uint64(block.number + WIN);
        IUARegistry.UASig memory s = _rollSig(t, uaM, 2, _sk(2), vub);
        vm.broadcast(k2);
        IPqzToken(t).mtxRollOverSigned(uaM, 0, 2, _sk(2), vub, s);
        require(IPqzToken(t).pqzSkipped(uaM, 0, 2) && !IPqzToken(t).pqzSkipped(uaM, 0, 1), "marked");
        s = _rollSig(t, uaM, 1, new uint64[](0), vub);
        MetaTxLib.UAMetaTransaction memory m;
        (m.from, m.data, m.batch, m.validUntil) =
            (_pad(a1), abi.encodeCall(IPqzToken.mtxRollOverSigned, (uaM, 0, 1, new uint64[](0), vub, s)), 15, vu);
        m.nonce = NormalPqzToken(t).mtxNonce(_pad(a1), 15);
        IUARegistry.UASig memory es = _sig(k1, NormalPqzToken(t).mtxDigest(m));
        vm.broadcast(k3);
        NormalPqzToken(t).mtxExecute(m, es);
        _rollByAddress(t, vub);
    }

    function _rollByAddress(address t, uint64 vub) internal {
        IUARegistry.UASig memory s = _rollSig(t, uaM, 1, new uint64[](0), vub);
        MetaTxLib.MetaTransaction memory mt;
        (mt.from, mt.data, mt.batch, mt.nonce, mt.validUntil) = (a1, abi.encodeCall(IPqzToken.mtxRollOverSigned,
            (uaM, 0, 1, new uint64[](0), vub, s)), 16, NormalPqzToken(t).mtxNonce(_pad(a1), 16), vu);
        bytes32 h = keccak256(abi.encode(MetaTxLib.METATX_TYPEHASH, mt.from, keccak256(mt.data), mt.batch, mt.nonce,
            mt.validUntil, mt.mode, address(0), mt.fee, address(0)));
        bytes memory sg = _ecdsa(k1, _digest(t, h));
        vm.broadcast(k3);
        NormalPqzToken(t).executeMetaTransaction(mt, sg);
        IPqzToken.AccountState memory st = IPqzToken(t).pqzAccount(uaM, 0);
        require(st.rolled == 4 && st.rolled == st.pendingCount && st.rollSeq == 3, "rolled");
        _signedBob(t);
    }

    function _signedBob(address t) internal {
        uint64 vub = uint64(block.number + WIN);
        // bob: mark only
        IUARegistry.UASig memory s = _rollSig(t, bob, 0, _sk(1), vub);
        uint64 r0 = IPqzToken(t).pqzAccount(bob, 0).rolled;
        vm.broadcast(k2);
        IPqzToken(t).mtxRollOverSigned(bob, 0, 0, _sk(1), vub, s);
        require(IPqzToken(t).pqzSkipped(bob, 0, 1) && IPqzToken(t).pqzAccount(bob, 0).rolled == r0, "bob marked, nothing rolled");
        _neg(a2, t, abi.encodeCall(IPqzToken.mtxRollOverSigned, (bob, 0, 0, _sk(1), vub, s)), IPqzToken.AuthRejected.selector,
            string.concat(_tag(t), ": the mark-only call replayed (rollSeq moved)"));
        IUARegistry.UASig memory stale = _uaSig(bobSeed, UAKinds.PURPOSE_ZETHER_AUTH,
            _rollDigest(t, bob, 0, _sk(1), vub, keccak256("another entry")));
        _neg(a2, t, abi.encodeCall(IPqzToken.mtxRollOverSigned, (bob, 0, 0, _sk(1), vub, stale)), IPqzToken.AuthRejected.selector,
            string.concat(_tag(t), ": a stale entriesHash"));
        IUARegistry.UASig memory triv = _rollSig(t, bob, 0, _sk(2), vub);
        _negData(a2, t, abi.encodeCall(IPqzToken.mtxRollOverSigned, (bob, 0, 0, _sk(2), vub, triv)),
            abi.encodeWithSelector(IPqzToken.SkipTrivial.selector, uint256(2)), string.concat(_tag(t), ": a mark on a TRIVIAL entry"));
    }

    function _tag(address t) internal view returns (string memory) {
        return t == c2 ? "c2" : "c3o";
    }
}
