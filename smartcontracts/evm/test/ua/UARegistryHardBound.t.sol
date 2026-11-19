// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UARegistryRegLib} from "../../src/ua/UARegistryRegLib.sol";
import {UARegistryBase} from "./UARegistryBase.sol";
import {VerifyOnlyStandIn} from "./UARegistryLine.t.sol";
import {UACall} from "./UACall.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";

/// The bounds of a line (spec 2026-11-19-registry-verify-only-kinds §4 P3, P9; plan Task 7): what a member held elsewhere costs
/// the consumer bound (`UARegistryRegLib._slotCap`: the walk, a verify-only member's reads, the holder's cap). UNAUDITED.
contract UARegistryHardBoundTest is UARegistryBase {
    uint16 internal constant ML87 = UAKinds.MLDSA87;
    uint64 internal constant CAP_VO = 250_000;

    UARegistry internal g1;
    bytes internal pk;
    bytes32 internal id;

    function setUp() public override {
        super.setUp();
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](1);
        // a verifier without a precompile and the mock rule (`PRECOMPILE() == 0`)
        k[0] = UARegistry.KindConfig(ML87, address(new VerifyOnlyStandIn(address(0), 0, 0)), 400_000, false, 0);
        g1 = _deploy(address(0x7f01), chainUidA, address(0), false, BUDGET, address(0), true, k);
        pk = new bytes(2592);
        pk[0] = 0x87;
        id = _register(g1, ML87, pk);
    }

    /// A gen-2 `msig` of the gen-1 `mldsa87` member (2,592 B key, the largest `keyOf` of a stored kind), the kind verify-only in gen
    /// 2: the consumer check's gas beyond the verifier's own work is within one hop, `VO_READ_GAS`, `MSIG_MEMBER_GAS` and
    /// `MSIG_ACCEPTED_GAS`, the terms `_slotCap` / `_worst` count beside the cap.
    function test_voMember_readsWithinConstant() public {
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](1);
        k[0] = UARegistry.KindConfig(ML87, address(new VerifyOnlyStandIn(address(0x5caa0014), 0, 0)), CAP_VO, true, 0);
        UARegistry g2 = _deploy(address(0x7f02), chainUidA, address(g1), false, BUDGET, address(0), true, k);
        Member[] memory m = new Member[](1);
        m[0] = Member(ML87, id, 1);
        bytes memory d = _msigKey(1, m);
        bytes32 ua = UAKinds.uaOf(UAKinds.MSIG, d);
        bytes32 pmd = _memberDigest(ua, UAKinds.PURPOSE_POP_V2, _regDigest(ua, UAKinds.MSIG));
        IUARegistry.MemberSig[] memory p = new IUARegistry.MemberSig[](1);
        p[0] = IUARegistry.MemberSig(
            0, new IUARegistry.InnerSig[](0), _sig(pk, UAKinds.uaMessage(ML87, UAKinds.PURPOSE_MEMBER, pmd))
        );
        UACall.register(g2, UAKinds.MSIG, d, _none(), abi.encode(p), "");
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX, DIGEST);
        IUARegistry.UASig memory a;
        a.members = new IUARegistry.MemberSig[](1);
        a.members[0] = IUARegistry.MemberSig(
            0, new IUARegistry.InnerSig[](0), _sig(pk, UAKinds.uaMessage(ML87, UAKinds.PURPOSE_MEMBER, md))
        );
        bytes memory call = abi.encodeCall(IUARegistry.requireAuthorized, (ua, UAKinds.PURPOSE_METATX, DIGEST, a));
        uint256 g = gasleft();
        (bool ok,) = address(g2).staticcall(call);
        g -= gasleft();
        assertTrue(ok, "the member by gen 2's verifier");
        emit log_named_uint("gen-2 msig, one verify-only mldsa87 member at gen 1 (cold, frame)", g);
        // the stand-in's own work (a keccak over the key and message) is below 10,000
        assertLe(
            g,
            UARegistryRegLib.LINE_HOP_GAS + UARegistryRegLib.VO_READ_GAS + UARegistryRegLib.MSIG_MEMBER_GAS
                + UARegistryRegLib.MSIG_ACCEPTED_GAS + 10_000,
            "within the terms the bound counts"
        );
    }

    /// One `mldsa87` member's `msig` registered on `r` (no PoP check needed beyond the member's, a write its holder checks).
    function _msigOn(UARegistry r) internal returns (bytes32 ua) {
        Member[] memory m = new Member[](1);
        m[0] = Member(ML87, id, 1);
        bytes memory d = _msigKey(1, m);
        ua = UAKinds.uaOf(UAKinds.MSIG, d);
        bytes32 pmd = _memberDigest(ua, UAKinds.PURPOSE_POP_V2, _regDigest(ua, UAKinds.MSIG));
        IUARegistry.MemberSig[] memory p = new IUARegistry.MemberSig[](1);
        p[0] = IUARegistry.MemberSig(
            0, new IUARegistry.InnerSig[](0), _sig(pk, UAKinds.uaMessage(ML87, UAKinds.PURPOSE_MEMBER, pmd))
        );
        UACall.register(r, UAKinds.MSIG, d, _none(), abi.encode(p), "");
    }

    function _registerReverts(UARegistry r) internal {
        Member[] memory m = new Member[](1);
        m[0] = Member(ML87, id, 1);
        bytes memory d = _msigKey(1, m);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        UACall.register(r, UAKinds.MSIG, d, _none(), "", "");
    }

    /// P3: a verify-only member counts this generation's cap, its walk and `VO_READ_GAS`: one gas below that sum, refused at
    /// registration (`UAKeyData(msig)`); at it, registered.
    function test_voMember_boundCountsReads() public {
        uint64 b = uint64(
            CAP_VO + UARegistryRegLib.LINE_HOP_GAS + UARegistryRegLib.VO_READ_GAS + UARegistryRegLib.MSIG_MEMBER_GAS
                + UARegistryRegLib.MSIG_ACCEPTED_GAS
        );
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](1);
        k[0] = UARegistry.KindConfig(ML87, address(new VerifyOnlyStandIn(address(0x5caa0014), 0, 0)), CAP_VO, true, 0);
        _registerReverts(_deploy(address(0x7f03), chainUidA, address(g1), false, b - 1, address(0), true, k));
        _msigOn(_deploy(address(0x7f04), chainUidA, address(g1), false, b, address(0), true, k));
    }

    /// N3: a member of a kind this generation does not carry counts its holder's cap (gen 1's 400,000), one hand-off and its
    /// walk (two generations), never the predecessor's cap (gen 2 does not carry it: 0).
    function test_notCarriedMember_boundUsesHoldersCap() public {
        UARegistry.KindConfig[] memory none = new UARegistry.KindConfig[](0);
        UARegistry g2 = _deploy(address(0x7f05), chainUidA, address(g1), false, BUDGET, address(0), true, none);
        uint256 c = 400_000;
        uint256 e = c + c / 63 + 5_000 + 2 * UARegistryRegLib.LINE_HOP_GAS; // the slot, also its largest held cap
        // `_membersWorst`: the caller's hold for a held cap above the 400 k `MSIG_MEMBER_GAS` covers
        uint64 b =
            uint64(e + UARegistryRegLib.MSIG_MEMBER_GAS + UARegistryRegLib.MSIG_ACCEPTED_GAS + (e - 400_000) / 63);
        _registerReverts(_deploy(address(0x7f06), chainUidA, address(g2), false, b - 1, address(0), true, none));
        _msigOn(_deploy(address(0x7f07), chainUidA, address(g2), false, b, address(0), true, none));
    }
}

/// The hard bound by `txGasCap` (spec §4 owner P9, X1; M2, M10 a – d; plan Task 7 part 2): a gen-2 `msig` of gen-1 ML-DSA members,
/// the kind verify-only in gen 2. Each boundary row deploys at the bound and one gas below it. UNAUDITED.
contract UARegistryHardBoundModesTest is UARegistryBase {
    uint16 internal constant ML44 = UAKinds.MLDSA44;
    uint16 internal constant ML65 = UAKinds.MLDSA65;
    uint16 internal constant ML87 = UAKinds.MLDSA87;
    uint16 internal constant K1 = UAKinds.BIP340; // a classical kind: no PQZ holder rule (CTR-UA-44 row 12)
    // the gen-1 caps of spec §13 (software path on the cache) and a verify-only cap
    uint64 internal constant HC44 = 4_250_000;
    uint64 internal constant HC65 = 5_950_000;
    uint64 internal constant HC87 = 8_990_000;
    uint64 internal constant VC = 250_000;
    address internal constant PC = address(0x5caa0014);

    UARegistry internal g1;
    mapping(uint16 => bytes32[4]) internal ids;
    mapping(bytes32 => bytes) internal keyOf_;
    uint160 internal next = 0x7e10;

    function _pk(uint16 kind, uint256 salt) internal returns (bytes memory pk) {
        if (kind == K1) {
            Vm.Wallet memory w = vm.createWallet(0xA000 + salt);
            return abi.encodePacked(w.publicKeyX);
        }
        pk = new bytes(kind == ML44 ? 1312 : kind == ML65 ? 1952 : 2592);
        (pk[0], pk[1]) = (bytes1(uint8(kind)), bytes1(uint8(salt)));
    }

    function setUp() public override {
        super.setUp();
        address v = address(new VerifyOnlyStandIn(address(0), 0, 0)); // the holder's software path: checks `_sig`
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](4);
        k[0] = UARegistry.KindConfig(ML44, v, HC44, false, 0);
        k[1] = UARegistry.KindConfig(ML65, v, HC65, false, 0);
        k[2] = UARegistry.KindConfig(ML87, v, HC87, false, 0);
        k[3] = UARegistry.KindConfig(K1, v, HC65, false, 0);
        g1 = _deploy(address(0x7e01), chainUidA, address(0), false, BUDGET, address(0), true, k);
        uint16[4] memory kinds = [ML44, ML65, ML87, K1];
        for (uint256 j; j < 4; ++j) {
            for (uint256 i; i < 4; ++i) {
                bytes memory pk = _pk(kinds[j], i);
                bytes32 id = _register(g1, kinds[j], pk);
                (ids[kinds[j]][i], keyOf_[id]) = (id, pk);
            }
        }
    }

    /// A gen 2 over `g1` at `cap`, carrying `kind` verify-only at `vc` (0: not carried), with `0x0142` when `pqz`.
    function _g2(uint16 kind, uint64 vc, uint256 cap, bool pqz) internal returns (UARegistry) {
        UARegistry.KindConfig[] memory k = _k2(kind, vc, pqz);
        txCap = uint64(cap);
        UARegistry r = _deploy(address(++next), chainUidA, address(g1), false, BUDGET, address(0), true, k);
        txCap = 1 << 24;
        return r;
    }

    function _k2(uint16 kind, uint64 vc, bool pqz) internal returns (UARegistry.KindConfig[] memory k) {
        k = new UARegistry.KindConfig[]((vc != 0 ? 1 : 0) + (pqz ? 1 : 0));
        if (vc != 0) k[0] = UARegistry.KindConfig(kind, address(new VerifyOnlyStandIn(PC, 0, 0)), vc, true, 0);
        if (pqz) k[k.length - 1] = UARegistry.KindConfig(UAKinds.PQZ_MLWE, address(mock), 1_000_000, false, 0);
    }

    function _d(uint16 kind, uint256 n, uint16 t) internal view returns (bytes memory d) {
        Member[] memory m = new Member[](n);
        for (uint256 i; i < n; ++i) {
            m[i] = Member(kind, ids[kind][i], 1);
        }
        d = _msigKey(t, m);
    }

    // ----- the model: the bound of `UARegistryRegLib._hard` / `_msigDebit` for `n` equal members of `kind`, `t` signing -----

    function _sigLen(uint16 kind) internal pure returns (uint256) {
        // `_sigBytes` rounded up to words
        return kind == ML44 ? 2_432 : kind == ML65 ? 3_328 : kind == ML87 ? 4_640 : 1_024;
    }

    /// (consumer mode, write mode, the debit bound's `w`) of a gen-2 `msig`, members one hop away, `vc` the verify-only cap.
    function _model(uint16 kind, uint256 hc, uint256 vc, uint256 n, uint256 t, bool pq)
        internal
        pure
        returns (uint256 c, uint256 w, uint256 fb)
    {
        uint256 slotW = hc + hc / 63 + 5_000 + UARegistryRegLib.LINE_HOP_GAS; // the holder's cap, one hand-off, the walk
        fb = vc != 0 ? _worstOf(t, vc + UARegistryRegLib.VO_READ_GAS + slotW, vc) : _worstOf(t, slotW, slotW);
        uint256 a = t * (192 + _sigLen(kind));
        c = _cd(fb, a) + 21_000 + UARegistryRegLib.UA_CONSUMER_RESERVE_GAS;
        w = _cd(_worstOf(t, slotW, slotW), a) + _writeGas(n, pq);
    }

    function _worstOf(uint256 t, uint256 slot, uint256 held) internal pure returns (uint256) {
        return t * (slot + UARegistryRegLib.MSIG_MEMBER_GAS) + UARegistryRegLib.MSIG_ACCEPTED_GAS
            + (held > 400_000 ? (held - 400_000) / 63 : 0);
    }

    function _writeGas(uint256 n, bool pq) internal pure returns (uint256 wr) {
        wr = UARegistryRegLib.MSIG_UPDATE_GAS + n * UARegistryRegLib.MSIG_UPDATE_SLOT_GAS;
        if (wr < UARegistryRegLib.MSIG_REGISTER_GAS) wr = UARegistryRegLib.MSIG_REGISTER_GAS;
        if (pq && wr < UARegistryRegLib.PQZ_KEY_WRITE_GAS) wr = UARegistryRegLib.PQZ_KEY_WRITE_GAS;
    }

    function _cd(uint256 x, uint256 a) internal pure returns (uint256) {
        return x + 16 * a > 64 * a ? x + 16 * a : 64 * a;
    }

    function _debit(uint256 fb, uint256 a) internal pure returns (uint256) {
        return fb + fb / 63 + 5_000 + PqzSet.PQZ_DEBIT_MIN_GAS + 16 * a;
    }

    function _max(uint256 x, uint256 y) internal pure returns (uint256) {
        return x > y ? x : y;
    }

    function _regRefused(UARegistry r, bytes memory d, bytes memory err) internal {
        _regA(r, d, _none(), err);
    }

    /// `d` registered on `r` with attributes `a`, its PoP by a quorum (the first `threshold` members); `err` empty: it passes.
    function _regA(UARegistry r, bytes memory d, IUARegistry.UAAttrs memory a, bytes memory err) internal returns (bytes32 ua) {
        ua = UAKinds.uaOf(UAKinds.MSIG, d);
        uint16 t = uint16(uint8(d[0])) << 8 | uint16(uint8(d[1]));
        // a PQ structure's PoP by a quorum; a classical one registers without (its members accept one by one)
        bytes memory pop = UAStoreKind.kindOf(d) == K1
            ? bytes("")
            : abi.encode(_sigs(d, ua, UAKinds.PURPOSE_POP_V2, _regDigest(ua, UAKinds.MSIG, a), t).members);
        if (err.length != 0) vm.expectRevert(err);
        UACall.register(r, UAKinds.MSIG, d, a, pop, "");
        if (err.length == 0 && pop.length == 0) {
            for (uint256 i; i < t; ++i) {
                _accept(r, d, ua, i);
            }
        }
    }

    function _reg(UARegistry r, bytes memory d) internal returns (bytes32) {
        return _regA(r, d, _none(), "");
    }

    function _keyData0120() internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG);
    }

    // ----- P9 -----

    /// §4's treasury `{mldsa65 ×3} t=2` on gen 2 fits 2^24 at registration; each mode alone fits, their sum does not
    /// (`test_bound_isMaxNotSum` pins the boundary). Its `updateMsig` passes the hard bound and meets CTR-UA-44 row 12 (a
    /// PQ-eligible target passes the PQZ debit bound) at the fallback worst: `UAPqzHolder` (owner M2, spec §3: "refused at
    /// registration and at `setPqzKey` / `updateMsig`"). The same structure of a classical kind (`secp256k1`, the same caps)
    /// registers and updates.
    function test_treasury_mldsa65x3_t2_fits() public {
        (uint256 c, uint256 w,) = _model(ML65, HC65, VC, 3, 2, true);
        emit log_named_uint("treasury consumer mode", c);
        emit log_named_uint("treasury write mode", w);
        assertLe(_max(c, w), 1 << 24);
        assertGt(c + w, 1 << 24, "the sum would refuse it");
        UARegistry r = _g2(ML65, VC, 1 << 24, false);
        bytes memory d = _d(ML65, 3, 2);
        bytes32 ua = _reg(r, d);
        _update(r, d, ua, 2, abi.encodeWithSelector(IUARegistry.UAPqzHolder.selector, ua));
        r = _g2(K1, VC, 1 << 24, false);
        d = _d(K1, 3, 2);
        ua = _reg(r, d);
        _update(r, d, ua, 2, ""); // the same structure again
    }

    /// M10 (a): the bound is the larger mode, never the sum: registered at `max(c, w)`, refused one gas below.
    function test_bound_isMaxNotSum() public {
        (uint256 c, uint256 w,) = _model(ML65, HC65, VC, 3, 2, true);
        bytes memory d = _d(ML65, 3, 2);
        _regRefused(_g2(ML65, VC, _max(c, w) - 1, false), d, _keyData0120());
        _reg(_g2(ML65, VC, _max(c, w), false), d);
    }

    /// The consumer mode binds (a verify-only cap of 1.5 M: the fallback pays it beside the holder's path): its reserve and
    /// intrinsic count, at the boundary.
    function test_bound_consumerModeBinds() public {
        (uint256 c, uint256 w,) = _model(ML65, HC65, 1_500_000, 3, 2, true);
        assertGt(c, w, "the consumer mode binds");
        bytes memory d = _d(ML65, 3, 2);
        _regRefused(_g2(ML65, 1_500_000, c - 1, false), d, _keyData0120());
        _reg(_g2(ML65, 1_500_000, c, false), d);
    }

    /// M10 (b): the write mode takes the dearest of the three writes: the treasury fits `updateMsig`'s constants and
    /// `MSIG_REGISTER_GAS` one gas below its bound, never `PQZ_KEY_WRITE_GAS` (a PQ-eligible structure): refused.
    function test_writeMode_dearestOfThree() public {
        (uint256 c, uint256 w,) = _model(ML65, HC65, VC, 3, 2, true);
        assertGt(w, c, "the write mode binds");
        uint256 upd = UARegistryRegLib.MSIG_UPDATE_GAS + 3 * UARegistryRegLib.MSIG_UPDATE_SLOT_GAS;
        assertGt(UARegistryRegLib.PQZ_KEY_WRITE_GAS, upd);
        assertGt(UARegistryRegLib.PQZ_KEY_WRITE_GAS, UARegistryRegLib.MSIG_REGISTER_GAS);
        _regRefused(_g2(ML65, VC, w - 1, false), _d(ML65, 3, 2), _keyData0120());
    }

    /// §4's `{mldsa87 ×2} t=2` (write mode ≈ 18.4 M) is refused at registration on a 2^24 chain.
    function test_mldsa87x2_t2_registration_UAKeyData0120() public {
        (, uint256 w,) = _model(ML87, HC87, VC, 2, 2, true);
        assertGt(w, 1 << 24);
        _regRefused(_g2(ML87, VC, 1 << 24, false), _d(ML87, 2, 2), _keyData0120());
    }

    /// §4's `{mldsa65 ×3} t=3` (write mode ≈ 18.6 M) is refused at registration on a 2^24 chain.
    function test_mldsa65x3_t3_registration_UAKeyData0120() public {
        (, uint256 w,) = _model(ML65, HC65, VC, 3, 3, true);
        assertGt(w, 1 << 24);
        _regRefused(_g2(ML65, VC, 1 << 24, false), _d(ML65, 3, 3), _keyData0120());
    }

    /// P9: `updateMsig` to a target over the bound (the classical treasury at t=3) is `UAMsigSlots(3)`; the stored one stays.
    function test_updateMsig_toOverBound_UAMsigSlots() public {
        (, uint256 w,) = _model(K1, HC65, VC, 3, 3, false);
        assertGt(w, 1 << 24);
        UARegistry r = _g2(K1, VC, 1 << 24, false);
        bytes memory d = _d(K1, 3, 2);
        bytes32 ua = _reg(r, d);
        _accept(r, d, ua, 0);
        _accept(r, d, ua, 1);
        _accept(r, d, ua, 2);
        _update(r, d, ua, 3, abi.encodeWithSelector(IUARegistry.UAMsigSlots.selector, uint256(3)));
        _update(r, d, ua, 2, ""); // the control
    }

    /// M10 (c): `acceptMembership` checks one slot and no structure bound: the treasury registered at its exact bound accepts each
    /// member there.
    function test_acceptMembership_oneSlot() public {
        (uint256 c, uint256 w,) = _model(ML65, HC65, VC, 3, 2, true);
        UARegistry r = _g2(ML65, VC, _max(c, w), false);
        bytes memory d = _d(ML65, 3, 2);
        bytes32 ua = _reg(r, d);
        for (uint16 i; i < 3; ++i) {
            _accept(r, d, ua, i);
            assertTrue(r.memberAccepted(ua, _indexOf(d, ids[ML65][i])));
        }
    }

    // ----- M2 -----

    /// M2: the treasury cannot hold a PQZ key (fallback worst + `PQZ_DEBIT_MIN_GAS` > 2^24): `UAPqzHolder` at registration and at
    /// `setPqzKey`.
    function test_treasury_withPqzKey_UAPqzHolder() public {
        (,, uint256 fb) = _model(ML65, HC65, VC, 3, 2, true);
        assertGt(_debit(fb, 2 * (192 + 3_328)), 1 << 24);
        UARegistry r = _g2(ML65, VC, 1 << 24, true);
        bytes memory d = _d(ML65, 3, 2);
        bytes32 ua = UAKinds.uaOf(UAKinds.MSIG, d);
        IUARegistry.UAAttrs memory a;
        a.pqzKey = new bytes(PqzSet.PK);
        a.pqzPopHash = keccak256("proof");
        _regA(r, d, a, abi.encodeWithSelector(IUARegistry.UAPqzHolder.selector, ua));
        _reg(r, d);
        _accept(r, d, ua, 0);
        _accept(r, d, ua, 1);
        bytes32 rd = UAKinds.pqzKeyRecordDigest(ua, UAKinds.keyHashOf(UAKinds.PQZ_MLWE, a.pqzKey), a.pqzPopHash);
        IUARegistry.UASig memory s = _sigs(d, ua, UAKinds.PURPOSE_PQZ_KEY, rd, 2);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzHolder.selector, ua));
        r.setPqzKey(ua, 0, a.pqzKey, a.pqzPopHash, s);
    }

    /// M2's other row: `{mldsa44 ×2} t=2` holds a PQZ key where the compiled set's debit fits (`n2304-kmax4096`, the default: it
    /// must); else `UAPqzHolder`. Spec §4 estimated it fits at `n2048-kmax1024` too; at the built figures it needs
    /// `PQZ_DEBIT_MIN_GAS` ≤ 2^24 less the fallback worst (≈ 9.5 M): only the default set's 6,074,000 is below that.
    function test_mldsa44x2_pqzKey_fitsAtDefaultSet() public {
        (,, uint256 fb) = _model(ML44, HC44, 200_000, 2, 2, true);
        bool fits = _debit(fb, 2 * (192 + 2_432)) <= 1 << 24;
        emit log_named_uint("mldsa44 x2 debit bound", _debit(fb, 2 * (192 + 2_432)));
        if (PqzSet.PQZ_DEBIT_MIN_GAS == 6_074_000) assertTrue(fits, "fits at the default set");
        UARegistry r = _g2(ML44, 200_000, 1 << 24, true);
        bytes memory d = _d(ML44, 2, 2);
        IUARegistry.UAAttrs memory a;
        a.pqzKey = new bytes(PqzSet.PK);
        a.pqzPopHash = keccak256("proof");
        _regA(r, d, a, fits ? bytes("") : abi.encodeWithSelector(IUARegistry.UAPqzHolder.selector, UAKinds.uaOf(UAKinds.MSIG, d)));
    }

    /// M2: `_msigDebit`'s `w` is the fallback worst (this generation's cap, the reads, the holder's path), not the write mode's
    /// (the holder's path only): a one-member `msig` with a PQZ key registers at the fallback's bound and is `UAPqzHolder` one gas
    /// below it, where the write mode's `w` would still fit.
    function test_msigDebit_wIsFallbackWorst() public {
        (uint256 c, uint256 w, uint256 fb) = _model(ML65, HC65, VC, 1, 1, true);
        uint256 a = 192 + 3_328;
        uint256 bound = _debit(fb, a);
        uint256 hp = HC65 + HC65 / 63 + 5_000 + UARegistryRegLib.LINE_HOP_GAS;
        uint256 ww = hp + UARegistryRegLib.MSIG_MEMBER_GAS + UARegistryRegLib.MSIG_ACCEPTED_GAS + (hp - 400_000) / 63;
        assertLt(_debit(ww, a), bound - 1, "the write mode's w would fit below the bound");
        assertLe(_max(c, w), bound - 1, "the hard bound fits");
        bytes memory d = _d(ML65, 1, 1);
        IUARegistry.UAAttrs memory at;
        at.pqzKey = new bytes(PqzSet.PK);
        at.pqzPopHash = keccak256("proof");
        UARegistry r = _g2(ML65, VC, bound - 1, true);
        _regA(r, d, at, abi.encodeWithSelector(IUARegistry.UAPqzHolder.selector, UAKinds.uaOf(UAKinds.MSIG, d)));
        _regA(_g2(ML65, VC, bound, true), d, at, "");
    }

    // ----- M10 (d) -----

    /// The single-key fallback of `mldsa87` (this generation's cap and hold, the walk, `VO_READ_GAS`, the home's cap and one
    /// hand-off) against the PQZ debit bound, where `0x0142` is on the line: the constructor takes the bound and refuses one gas
    /// below it, `UAConfig(0x0134)`.
    function test_constructor_verifyOnlyFallback_overDebitBound_UAConfig() public {
        uint256 bound = _single87();
        UARegistry.KindConfig[] memory k = _k2(ML87, VC, true);
        vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, ML87));
        new UARegistry(chainUidA, address(g1), false, BUDGET, uint64(bound - 1), address(0), true, k);
        _g2(ML87, VC, bound, true);
    }

    /// Without `0x0142` on the line the constructor does not check it: the same cap one gas below deploys.
    function test_constructor_debitCheck_skippedWithout0142() public {
        _g2(ML87, VC, _single87() - 1, false);
    }

    function _single87() internal pure returns (uint256) {
        uint256 w = VC + UARegistryRegLib.LINE_HOP_GAS + UARegistryRegLib.VO_READ_GAS + HC87 + HC87 / 63 + 5_000;
        return _debit(w, 192 + 4_640);
    }

    // ----- signatures of the gen-1 members (`_sig`, the stand-in's software rule) -----

    function _sigs(bytes memory d, bytes32 ua, bytes32 purpose, bytes32 digest, uint256 t)
        internal
        view
        returns (IUARegistry.UASig memory s)
    {
        bytes32 md = _memberDigest(ua, purpose, digest);
        uint16 kind = UAStoreKind.kindOf(d);
        s.members = new IUARegistry.MemberSig[](t);
        for (uint256 i; i < t; ++i) {
            bytes32 id = ids[kind][i];
            s.members[i] = IUARegistry.MemberSig(
                _indexOf(d, id), new IUARegistry.InnerSig[](0), _sig(keyOf_[id], UAKinds.uaMessage(kind, UAKinds.PURPOSE_MEMBER, md))
            );
        }
        for (uint256 i = 1; i < t; ++i) {
            for (uint256 j = i; j > 0 && s.members[j - 1].index > s.members[j].index; --j) {
                (s.members[j - 1], s.members[j]) = (s.members[j], s.members[j - 1]);
            }
        }
    }

    function _accept(UARegistry r, bytes memory d, bytes32 ua, uint256 i) internal {
        uint16 kind = UAStoreKind.kindOf(d);
        bytes32 id = ids[kind][i];
        if (r.memberAccepted(ua, _indexOf(d, id))) return;
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_MEMBERSHIP, UAKinds.membershipDigest(ua, id));
        r.acceptMembership(
            ua,
            IUARegistry.MemberSig(
                _indexOf(d, id), new IUARegistry.InnerSig[](0), _sig(keyOf_[id], UAKinds.uaMessage(kind, UAKinds.PURPOSE_MEMBER, md))
            )
        );
    }

    /// `updateMsig` of `ua` to threshold `t`, signed by the first two members; `err` empty: it passes.
    function _update(UARegistry r, bytes memory d, bytes32 ua, uint16 t, bytes memory err) internal {
        (uint64 v, uint256 en,) = r.msigStateOf(ua);
        IUARegistry.MsigStructure memory st = r.msigOf(ua);
        st.threshold = t;
        uint64 until = uint64(block.number + 100);
        bytes32 typed = UAKinds.msigUpdateDigest(ua, chainUidA, address(r), v + 1, st, en, until);
        IUARegistry.MemberSig[] memory s = _sigs(d, ua, UAKinds.PURPOSE_MSIG_UPDATE, typed, 2).members;
        if (err.length != 0) vm.expectRevert(err);
        r.updateMsig(ua, v + 1, st, en, until, s, chainUidA);
    }
}

/// The kind of an `msig` key's first slot (the tests' structures have one kind).
library UAStoreKind {
    function kindOf(bytes memory d) internal pure returns (uint16 k) {
        assembly {
            k := shr(240, mload(add(d, 36)))
        }
    }
}
