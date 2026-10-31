// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {console} from "forge-std/console.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {ZetherSchnorrBls12381Verifier} from "../../src/ua/verifiers/PairingVerifiers.sol";
import {ZetherKeys} from "../zether/helpers/ZetherKeys.sol";
import {UARegistryBase} from "./UARegistryBase.sol";

/// UA-6 (spec 2026-10-20-ua6-encryption-key-attributes U1–U6, U8 sets, U11; plan Review Focus 1–5): the PQZ key as an
/// attribute of a PQ signing UA given in `register`, the PQ-eligible `msig` PoP, the `0x0142` list, the Zether kind in
/// SIGNING. Stand-in verifiers for every kind (the `R_REG` stand-in is `MockVerifier` at slot 0x0142) except the
/// Zether Schnorr verifier, which is real.
contract UARegistryUA6Test is UARegistryBase {
    address internal constant REG_U = 0x5CA0000000000000000000000000000000000006;
    uint64 internal constant PQ_CAP = 1_000_000;
    uint256 internal constant ZX = 0xA11CE5;

    UARegistry internal r;
    bytes internal mlKey; // mldsa65 member key (no PQZ key)
    bytes32 internal mlUa;
    bytes internal p256Key;
    bytes32 internal p256Ua;

    function setUp() public override {
        super.setUp();
        UARegistry.KindConfig[] memory base = _cfgs(address(mock));
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](base.length + 7);
        for (uint256 i; i < base.length; ++i) c[i] = base[i];
        uint16[6] memory pq = [uint16(0x0108), 0x0130, 0x0131, 0x0132, 0x0133, 0x0142];
        for (uint256 i; i < 6; ++i) c[base.length + i] = UARegistry.KindConfig(pq[i], address(mock), i == 0 ? 50_000 : PQ_CAP);
        c[base.length + 6] =
            UARegistry.KindConfig(UAKinds.ZETHER_BLS12381, address(new ZetherSchnorrBls12381Verifier()), 70_000);
        r = _deploy(REG_U, chainUidA, address(0), false, BUDGET, address(0), true, c);
        mlKey = _pk(0x0131, 100);
        mlUa = _register(r, 0x0131, mlKey);
        p256Key = _key(0x0101);
        p256Ua = _register(r, 0x0101, p256Key);
    }

    // ----- helpers -----

    function _pk(uint16 kind, uint256 salt) internal pure returns (bytes memory pk) {
        uint256 len = kind == 0x0130 ? 1312 : kind == 0x0131 ? 1952 : kind == 0x0132 ? 897 : kind == 0x0133 ? 32 : 16384;
        pk = new bytes(len);
        for (uint256 i; i < len; i += 32) {
            bytes32 w = keccak256(abi.encode(kind, salt, i));
            for (uint256 j; j < 32 && i + j < len; ++j) pk[i + j] = w[j];
        }
        if (kind == 0x0132) {
            pk[0] = 0x09;
            for (uint256 i = 1; i < len; ++i) pk[i] = 0; // every h_i = 0 < q
        }
    }

    /// The PQZ keyHash `h = keccak256(GROUP("pqz-mlwe") ‖ pqzKey)`.
    function _h(bytes memory pqzKey) internal pure returns (bytes32) {
        return UAKinds.keyHashOf(UAKinds.PQZ_MLWE, pqzKey);
    }

    /// The `R_REG` stand-in over the portable `uaMessage(0x0142, POP_V2, portableRecordDigest(ua, kind, h, zero KEM record))` (UA-8 P1, typed-signing TS-D3).
    function _rReg(bytes32 ua, uint16 kind, bytes memory pqzKey) internal pure returns (bytes memory) {
        bytes32 d = UAKinds.portableRecordDigest(ua, kind, _h(pqzKey), UAKinds.kemRecordHash(ua, 0, ""));
        return _sig(pqzKey, UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_POP_V2, d));
    }

    /// The attributes of `ua` holding `pqzKey` with its `R_REG` stand-in (`pqzPopHash = keccak256(rReg)`).
    function _a(bytes32 ua, uint16 kind, bytes memory pqzKey) internal pure returns (IUARegistry.UAAttrs memory) {
        return IUARegistry.UAAttrs(pqzKey, keccak256(_rReg(ua, kind, pqzKey)), 0, "");
    }

    /// A PQZ key with the proof hash of the filler `0x01` (holder checks run before the PoP).
    function _pqzOnly(bytes memory pqzKey) internal pure returns (IUARegistry.UAAttrs memory) {
        return IUARegistry.UAAttrs(pqzKey, keccak256(hex"01"), 0, "");
    }

    /// The signer's PoP (stand-in) over the registration digest of `a` (UA-8).
    function _sPop(uint16 kind, bytes memory pk, IUARegistry.UAAttrs memory a) internal view returns (bytes memory) {
        return _pop(r, kind, pk, a);
    }

    function _holder(uint16 kind, bytes memory pk, bytes memory pqzKey) internal returns (bytes32) {
        bytes32 ua = r.uaOf(kind, pk);
        IUARegistry.UAAttrs memory a = _a(ua, kind, pqzKey);
        return r.register(kind, pk, a, _sPop(kind, pk, a), _rReg(ua, kind, pqzKey));
    }

    /// `{mlUa wm, p256Ua wp}` with `threshold`.
    function _msig(uint16 threshold, uint16 wm, uint16 wp) internal view returns (bytes memory d, bytes32 ua) {
        Member[] memory m = new Member[](2);
        m[0] = Member(0x0131, mlUa, wm);
        m[1] = Member(0x0101, p256Ua, wp);
        d = _msigKey(threshold, m);
        ua = r.uaOf(UAKinds.MSIG, d);
    }

    /// The m-of-n PoP: `abi.encode(MemberSig[])` over `memberDigest(ua, uaMessage(MSIG, POP_V2, registrationDigest))`
    /// of `a`; the p256 member signs only if `both`.
    function _msigPop(bytes memory d, bytes32 ua, IUARegistry.UAAttrs memory a, bool both)
        internal
        view
        returns (bytes memory)
    {
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_POP_V2, _regDigest(ua, UAKinds.MSIG, a));
        uint16 mi = _indexOf(d, mlUa);
        uint16 pi = _indexOf(d, p256Ua);
        UARegistry.MemberSig memory ms = UARegistry.MemberSig(mi, "", _sig(mlKey, r.uaMessage(0x0131, UAKinds.PURPOSE_MEMBER, md)));
        UARegistry.MemberSig memory ps =
            UARegistry.MemberSig(pi, "", _sig(p256Key, r.uaMessage(0x0101, UAKinds.PURPOSE_MEMBER, md)));
        UARegistry.MemberSig[] memory sigs = new UARegistry.MemberSig[](both ? 2 : 1);
        if (!both) sigs[0] = ms;
        else (sigs[0], sigs[1]) = mi < pi ? (ms, ps) : (ps, ms);
        return abi.encode(sigs);
    }

    /// `pop` (`abi.encode(MemberSig[])`) with the member at `index` carrying key data `k`.
    function _withMemberKey(bytes memory pop, uint16 index, bytes memory k) internal pure returns (bytes memory) {
        UARegistry.MemberSig[] memory ms = abi.decode(pop, (UARegistry.MemberSig[]));
        for (uint256 i; i < ms.length; ++i) {
            if (ms[i].index == index) ms[i].keyData = k;
        }
        return abi.encode(ms);
    }

    function _zetherUa() internal returns (bytes32 ua) {
        bytes memory y = ZetherKeys.pub(ZX, true);
        ua = r.uaOf(UAKinds.ZETHER_BLS12381, y);
        bytes memory pop =
            ZetherKeys.schnorr(ZX, r.uaMessage(UAKinds.ZETHER_BLS12381, UAKinds.PURPOSE_POP_V2, UAKinds.registrationDigest(ua, UAKinds.ZETHER_BLS12381, 0, UAKinds.kemRecordHash(ua, 0, ""), 0)), true);
        assertEq(r.register(UAKinds.ZETHER_BLS12381, y, _none(), pop, ""), ua);
    }

    // ----- U2/U4: holder registration -----

    /// `mldsa44`, `mldsa65`, `fndsa512` register with a PQZ key and its proof in one call (proven: slot 0x0142 has the
    /// stand-in): the record keeps the signer's kind and key, `recordOf` returns the key's SSTORE2 pointer, the keyHash
    /// `h` is claimed, the event carries the attributes and `checkedPqzPop = CHAIN`, the UA is in its kind's list and in
    /// the `0x0142` list.
    function test_UA6_holderWithKey() public {
        uint16[3] memory ks = [uint16(0x0130), 0x0131, 0x0132];
        for (uint256 i; i < 3; ++i) {
            bytes memory pk = _pk(ks[i], i);
            bytes memory pqzKey = _pk(0x0142, i);
            vm.recordLogs();
            uint256 g = gasleft();
            bytes32 ua = _holder(ks[i], pk, pqzKey);
            g -= gasleft();
            if (ks[i] == 0x0131) console.log("register mldsa65 + PQZ key (stand-in verifiers)", g);
            (IUARegistry.Record memory rec, address ptr) = r.recordOf(ua);
            assertEq(rec.kind, ks[i]);
            assertEq(ptr.code, bytes.concat(hex"00", pqzKey), "SSTORE2(pqzKey)");
            assertEq(r.keyOf(ua), pk, "keyOf: the signer's key");
            assertEq(r.keyOwner(_h(pqzKey)), ua);
            assertEq(r.keyOwner(r.keyHashOf(ks[i], pk)), ua);
            assertEq(r.uaCount(UAKinds.PQZ_MLWE), i + 1);
            assertEq(r.uaAt(UAKinds.PQZ_MLWE, i), ua);
            assertEq(r.uaAt(ks[i], rec.index), ua);
            assertEq(r.uaIndex(ua), rec.index, "uaIndex: the kind-list position");
            Vm.Log[] memory logs = vm.getRecordedLogs();
            Vm.Log memory e = logs[logs.length - 1];
            assertEq(e.topics[0], IUARegistry.UARegistered.selector);
            assertEq(e.topics[1], ua);
            assertEq(uint256(e.topics[2]), ks[i]);
            (bytes memory kd, IUARegistry.UAAttrs memory ea, bytes32 popHash,, uint8 cp, uint8 cq, uint8 ck) =
                abi.decode(e.data, (bytes, IUARegistry.UAAttrs, bytes32, bytes, uint8, uint8, uint8));
            assertEq(kd, pk);
            assertEq(popHash, keccak256(r.popOf(ua)), "CTR-UA-33: the event carries keccak256(pop), pop is in state");
            assertEq(ea.pqzKey, pqzKey, "the event carries the key");
            assertEq(abi.encode(cp, cq, ck), abi.encode(1, 1, 0));
        }
    }

    /// A holder kind without a key: pointer 0, not in the `0x0142` list; its PoP is over the attribute-free digest.
    function test_UA6_holderWithoutKey() public {
        (, address ptr) = r.recordOf(mlUa);
        assertEq(ptr, address(0));
        assertEq(r.uaCount(UAKinds.PQZ_MLWE), 0);
        bytes memory pk = _pk(0x0130, 7);
        bytes32 ua = r.register(0x0130, pk, _none(), _sPop(0x0130, pk, _none()), "");
        (, ptr) = r.recordOf(ua);
        assertEq(ptr, address(0));
        assertEq(r.uaCount(UAKinds.PQZ_MLWE), 0);
    }

    // ----- Review Focus 1: front-running a holder registration (U4) -----

    function test_UA6_frontRun() public {
        bytes memory pk = _pk(0x0131, 1);
        bytes32 ua = r.uaOf(0x0131, pk);
        bytes memory key = _pk(0x0142, 1);
        IUARegistry.UAAttrs memory a = _a(ua, 0x0131, key);
        bytes memory pop = _sPop(0x0131, pk, a);
        // stripped: the PoP over h ≠ 0 fails with h = 0
        vm.expectRevert(IUARegistry.UAPoP.selector);
        r.register(0x0131, pk, _none(), pop, "");
        // swapped key (with a valid R_REG for it): the PoP binds h and the proof hash
        bytes memory rReg2 = _rReg(ua, 0x0131, _pk(0x0142, 2));
        vm.expectRevert(IUARegistry.UAPoP.selector);
        r.register(0x0131, pk, _a(ua, 0x0131, _pk(0x0142, 2)), pop, rReg2);
        _frontRunOther(pk, key);
        // a PoP signed over h = 0 submitted with a key; an R_REG without a key
        bytes memory pop0 = _sPop(0x0131, pk, _none());
        vm.expectRevert(IUARegistry.UAPoP.selector);
        r.register(0x0131, pk, a, pop0, _rReg(ua, 0x0131, key));
        bytes memory rReg = _rReg(ua, 0x0131, key);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzPopHash.selector, ua));
        r.register(0x0131, pk, _none(), pop0, rReg);
        // a key without its R_REG registers unproven (UA8-D8: it claims nothing)
        uint256 snap = vm.snapshotState();
        r.register(0x0131, pk, a, pop, "");
        (,, bool proven) = r.pqzKeyOf(ua);
        assertFalse(proven);
        assertEq(r.keyOwner(_h(key)), bytes32(0));
        vm.revertToState(snap);
        // the signed data registers, whoever relays it
        vm.prank(address(0xBEEF));
        assertEq(r.register(0x0131, pk, a, pop, rReg), ua);
        assertEq(r.keyOwner(_h(key)), ua);
    }

    /// R_REG over another UA's digest, with a PoP that covers its hash: the proof is refused (`UAPoP`).
    function _frontRunOther(bytes memory pk, bytes memory key) internal {
        bytes memory rRegOther = _rReg(mlUa, 0x0131, key);
        IUARegistry.UAAttrs memory aOther = IUARegistry.UAAttrs(key, keccak256(rRegOther), 0, "");
        bytes memory popOther = _sPop(0x0131, pk, aOther);
        vm.expectRevert(IUARegistry.UAPoP.selector);
        r.register(0x0131, pk, aOther, popOther, rRegOther);
    }

    // ----- Review Focus 2: msig squatting (U5) -----

    function test_UA6_msigSquatting() public {
        (bytes memory d, bytes32 ua) = _msig(2, 1, 1); // PQ-eligible: classical weight 1 < 2
        bytes memory key = _pk(0x0142, 3);
        bytes32 h = _h(key);
        IUARegistry.UAAttrs memory a = _a(ua, UAKinds.MSIG, key);
        bytes memory rReg = _rReg(ua, UAKinds.MSIG, key);
        // without pop, with or without a key
        vm.expectRevert(IUARegistry.UAPoP.selector);
        r.register(UAKinds.MSIG, d, _none(), "", "");
        vm.expectRevert(IUARegistry.UAPoP.selector);
        r.register(UAKinds.MSIG, d, a, "", rReg);
        // pop over another key
        bytes memory other = _msigPop(d, ua, _a(ua, UAKinds.MSIG, _pk(0x0142, 4)), true);
        vm.expectRevert(IUARegistry.UAPoP.selector);
        r.register(UAKinds.MSIG, d, a, other, rReg);
        // below the threshold (one member of weight 1, t = 2)
        bytes memory weak = _msigPop(d, ua, a, false);
        vm.expectRevert(IUARegistry.UAPoP.selector);
        r.register(UAKinds.MSIG, d, a, weak, rReg);
        // CTR-UA-33: the registered p256 member's MemberSig carrying its own key data
        weak = _withMemberKey(_msigPop(d, ua, a, true), _indexOf(d, p256Ua), p256Key);
        vm.expectRevert(IUARegistry.UAPoP.selector);
        r.register(UAKinds.MSIG, d, a, weak, rReg);
        // the members' pop: without a key and with one
        uint256 snap = vm.snapshotState();
        assertEq(r.register(UAKinds.MSIG, d, _none(), _msigPop(d, ua, _none(), true), ""), ua);
        (, address ptr) = r.recordOf(ua);
        assertEq(ptr, address(0));
        vm.revertToState(snap);
        bytes memory pop = _msigPop(d, ua, a, true);
        uint256 g = gasleft();
        assertEq(r.register(UAKinds.MSIG, d, a, pop, rReg), ua);
        console.log("register PQ-eligible msig {mldsa65, p256} t=2 + PQZ key (stand-in verifiers)", g - gasleft());
        (, ptr) = r.recordOf(ua);
        assertEq(ptr.code, bytes.concat(hex"00", key));
        assertEq(r.keyOwner(h), ua);
        assertEq(r.uaAt(UAKinds.PQZ_MLWE, 0), ua);
        // a classical-dominant msig keeps an empty pop (unchanged)
        (bytes memory c,) = _msig(2, 1, 2);
        vm.expectRevert(IUARegistry.UAPoP.selector);
        r.register(UAKinds.MSIG, c, _none(), hex"01", "");
        r.register(UAKinds.MSIG, c, _none(), "", "");
    }

    // ----- Review Focus 3: uniqueness across kinds and generations -----

    function test_UA6_keyUniqueAcrossKinds() public {
        bytes memory key = _pk(0x0142, 5);
        bytes32 h = _h(key);
        (bytes memory d, bytes32 msUa) = _msig(2, 1, 1);
        IUARegistry.UAAttrs memory msA = _a(msUa, UAKinds.MSIG, key);
        bytes memory msPop = _msigPop(d, msUa, msA, true);
        bytes memory msReg = _rReg(msUa, UAKinds.MSIG, key);
        bytes memory pk = _pk(0x0131, 5);
        bytes32 mua = r.uaOf(0x0131, pk);
        IUARegistry.UAAttrs memory mA = _a(mua, 0x0131, key);
        bytes memory mPop = _sPop(0x0131, pk, mA);
        bytes memory mReg = _rReg(mua, 0x0131, key);
        uint256 snap = vm.snapshotState();
        // ML-DSA first, then the msig (both proven: one UA per proven key, UA8-D8)
        r.register(0x0131, pk, mA, mPop, mReg);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyInUse.selector, h, mua));
        r.register(UAKinds.MSIG, d, msA, msPop, msReg);
        vm.revertToState(snap);
        // the msig first, then ML-DSA
        r.register(UAKinds.MSIG, d, msA, msPop, msReg);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyInUse.selector, h, msUa));
        r.register(0x0131, pk, mA, mPop, mReg);
    }

    /// 0x0142 lives in one generation: gen 2 may not enable it when gen 1 does, and refuses a PQZ key then
    /// (`UAKindDisabled(0x0142)`, ruling A5-I1); gen 2 forwards `recordOf` (the pointer included) and the `0x0142` list
    /// to gen 1.
    function test_UA6_generations() public {
        bytes32 holder = _holder(0x0130, _pk(0x0130, 9), _pk(0x0142, 9));
        (, address ptr) = r.recordOf(holder);
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        c[0] = UARegistry.KindConfig(UAKinds.PQZ_MLWE, address(mock), PQ_CAP);
        vm.expectRevert(abi.encodeWithSelector(UARegistry.UAConfig.selector, UAKinds.PQZ_MLWE));
        new UARegistry(chainUidA, address(r), false, BUDGET, address(0), true, c);
        UARegistry.KindConfig[] memory none = new UARegistry.KindConfig[](0);
        UARegistry g2 = new UARegistry(chainUidA, address(r), false, BUDGET, address(0), true, none);
        (IUARegistry.Record memory rec, address p2) = g2.recordOf(holder);
        assertEq(rec.kind, 0x0130);
        assertEq(p2, ptr, "gen 2 forwards the pointer");
        assertEq(g2.uaCount(UAKinds.PQZ_MLWE), 1);
        assertEq(g2.uaAt(UAKinds.PQZ_MLWE, 0), holder);
        assertFalse(g2.kindEnabled(UAKinds.PQZ_MLWE));
        // a gen-2 msig with a key and its proof: 0x0142 lives in gen 1 only (ruling A5-I1), so gen 2 refuses the key
        (bytes memory d, bytes32 msUa) = _msig(2, 1, 1);
        bytes memory key = _pk(0x0142, 10);
        IUARegistry.UAAttrs memory a = _a(msUa, UAKinds.MSIG, key);
        bytes memory pop = _msigPop(d, msUa, a, true);
        bytes memory rReg = _rReg(msUa, UAKinds.MSIG, key);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, UAKinds.PQZ_MLWE));
        g2.register(UAKinds.MSIG, d, a, pop, rReg);
        // without the key the structure registers in gen 2 as before
        assertEq(g2.register(UAKinds.MSIG, d, _none(), _msigPop(d, msUa, _none(), true), ""), msUa);
    }

    /// Ruling A5-I1: the portable PoP lets anyone pick the generation, so a griefer who submits a PQ-eligible msig's
    /// registration (PQZ key and proof) to gen 2 first must be refused, else the key would stay unproven in gen 2 for
    /// good; the same bytes then register in gen 1, proven.
    function test_UA6_gen2GrieferRefused() public {
        UARegistry g2 = new UARegistry(chainUidA, address(r), false, BUDGET, address(0), true, new UARegistry.KindConfig[](0));
        (bytes memory d, bytes32 msUa) = _msig(2, 1, 1);
        bytes memory key = _pk(0x0142, 20);
        IUARegistry.UAAttrs memory a = _a(msUa, UAKinds.MSIG, key);
        bytes memory pop = _msigPop(d, msUa, a, true);
        bytes memory rReg = _rReg(msUa, UAKinds.MSIG, key);
        vm.prank(address(0x6219EF), address(0x6219EF));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKindDisabled.selector, UAKinds.PQZ_MLWE));
        g2.register(UAKinds.MSIG, d, a, pop, rReg);
        assertEq(g2.kindOf(msUa), 0);
        assertEq(r.register(UAKinds.MSIG, d, a, pop, rReg), msUa);
        (,, bool proven) = g2.pqzKeyOf(msUa); // gen 2 forwards gen 1's record
        assertTrue(proven);
        assertEq(g2.keyOwner(_h(key)), msUa);
    }

    /// UA8-D8: where 0x0142 has no verifier (every chain but 7622; formerly `UAKindDisabled(0x0142)`) a holder's key and
    /// proof are stored unproven; a non-holder's key is still `UAPqzHolder`.
    function test_UA6_pqzDisabled() public {
        bytes memory p = _key(0x0101);
        assertFalse(reg.kindEnabled(UAKinds.PQZ_MLWE));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzHolder.selector, reg.uaOf(0x0101, p)));
        reg.register(0x0101, p, _pqzOnly(_pk(0x0142, 1)), "", hex"01");
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        c[0] = UARegistry.KindConfig(0x0131, address(mock), PQ_CAP);
        UARegistry n = _deploy(address(0x5ca7), chainUidA, address(0), false, BUDGET, address(0), true, c);
        bytes memory pk = _pk(0x0131, 77);
        bytes32 ua = n.uaOf(0x0131, pk);
        bytes memory key = _pk(0x0142, 77);
        IUARegistry.UAAttrs memory a = _a(ua, 0x0131, key);
        n.register(0x0131, pk, a, _pop(n, 0x0131, pk, a), _rReg(ua, 0x0131, key));
        (, bytes32 ph, bool proven) = n.pqzKeyOf(ua);
        assertEq(ph, a.pqzPopHash);
        assertFalse(proven);
        assertEq(n.pqzPopOf(ua), _rReg(ua, 0x0131, key));
        assertEq(n.keyOwner(_h(key)), bytes32(0));
        assertEq(n.uaCount(UAKinds.PQZ_MLWE), 0);
    }

    // ----- U3: the holder set -----

    /// `secp256k1`, `bip340`, `slhdsa128s`, the Zether kind and a classical-dominant `msig` may not hold a key.
    function test_UA6_nonHolders() public {
        bytes memory key = _pk(0x0142, 6);
        bytes memory secp = vm.parseJsonBytes(_kindsJson(), ".valid[25].keyData");
        bytes memory slh = _pk(0x0133, 6);
        bytes memory y = ZetherKeys.pub(ZX, true);
        (bytes memory c, bytes32 cUa) = _msig(2, 1, 2);
        uint16[4] memory ks = [uint16(0x0108), 0x0103, 0x0133, UAKinds.ZETHER_BLS12381];
        bytes[4] memory kd = [secp, _key(0x0103), slh, y];
        for (uint256 i; i < 4; ++i) {
            bytes32 ua = r.uaOf(ks[i], kd[i]);
            vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzHolder.selector, ua));
            r.register(ks[i], kd[i], _pqzOnly(key), "", hex"01");
        }
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzHolder.selector, cUa));
        r.register(UAKinds.MSIG, c, _pqzOnly(key), "", hex"01");
    }

    /// 0x0142 is a scheme id, not a kind: `register(0x0142, …)` is refused; its tag and keyHash group stay.
    function test_UA6_pqzNotAKind() public {
        bytes memory key = _pk(0x0142, 1);
        vm.expectRevert(abi.encodeWithSelector(UAKinds.UAKindNotDerived.selector, UAKinds.PQZ_MLWE));
        r.register(UAKinds.PQZ_MLWE, key, _none(), hex"01", "");
        assertFalse(UAKinds.isZether(UAKinds.PQZ_MLWE));
        assertFalse(UAKinds.isDerived(UAKinds.PQZ_MLWE));
        assertEq(UAKinds.tag(UAKinds.PQZ_MLWE), keccak256("scaas.ua.pqz-mlwe.v1"));
        assertEq(UAKinds.groupName(UAKinds.PQZ_MLWE), "pqz-mlwe");
        // uaOf refuses it too (CTR-PQZ-13): the PQZ key is an attribute, never an id
        vm.expectRevert(abi.encodeWithSelector(UAKinds.UAKindNotDerived.selector, UAKinds.PQZ_MLWE));
        r.uaOf(UAKinds.PQZ_MLWE, key);
    }

    // ----- Review Focus 4/5: the Zether kind in SIGNING, not MEMBER (U8) -----

    function test_UA6_zetherSets() public {
        assertTrue(UAKinds.isSigning(UAKinds.ZETHER_BLS12381));
        assertTrue(UAKinds.isZether(UAKinds.ZETHER_BLS12381));
        assertFalse(UAKinds.isMember(UAKinds.ZETHER_BLS12381, false));
        assertFalse(UAKinds.isMember(UAKinds.ZETHER_BLS12381, true));
        bytes32 z = _zetherUa();
        Member[] memory m = new Member[](2);
        m[0] = Member(UAKinds.ZETHER_BLS12381, z, 1);
        m[1] = Member(0x0101, p256Ua, 1);
        bytes memory d = _msigKey(1, m);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        r.register(UAKinds.MSIG, d, _none(), "", "");
    }

    /// `requireAuthorized` on a Zether UA: `auth.keyData` empty (stored kind), Schnorr by `x` on `Y` from `keyPtr`
    /// under any purpose; key data in `auth`, another purpose or another key: `UAUnauthorized`.
    function test_UA6_zetherRequireAuthorized() public {
        bytes32 z = _zetherUa();
        bytes32[3] memory ps = [UAKinds.PURPOSE_METATX, UAKinds.PURPOSE_ZETHER_OWNER, UAKinds.PURPOSE_TRADE];
        for (uint256 i; i < 3; ++i) {
            bytes memory sig = ZetherKeys.schnorr(ZX, r.uaMessage(UAKinds.ZETHER_BLS12381, ps[i], DIGEST), true);
            uint256 g = gasleft();
            r.requireAuthorized(z, ps[i], DIGEST, abi.encode(bytes(""), sig));
            if (i == 0) console.log("requireAuthorized zether-bls12381 (metatx)", g - gasleft());
        }
        bytes memory s = ZetherKeys.schnorr(ZX, r.uaMessage(UAKinds.ZETHER_BLS12381, UAKinds.PURPOSE_METATX, DIGEST), true);
        bytes memory withY = abi.encode(ZetherKeys.pub(ZX, true), s); // before expectRevert: pub() calls a precompile
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, z));
        r.requireAuthorized(z, UAKinds.PURPOSE_METATX, DIGEST, withY);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, z));
        r.requireAuthorized(z, UAKinds.PURPOSE_TRADE, DIGEST, abi.encode(bytes(""), s));
        bytes memory other = ZetherKeys.schnorr(0xB0B5, r.uaMessage(UAKinds.ZETHER_BLS12381, UAKinds.PURPOSE_METATX, DIGEST), true);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, z));
        r.requireAuthorized(z, UAKinds.PURPOSE_METATX, DIGEST, abi.encode(bytes(""), other));
    }

    // ----- U11: the 0x0142 list -----

    /// Holders of every kind in registration order; non-holders never in it.
    function test_UA6_pqzListOrder() public {
        bytes32 a = _holder(0x0130, _pk(0x0130, 11), _pk(0x0142, 11));
        r.register(0x0130, _pk(0x0130, 12), _none(), _sPop(0x0130, _pk(0x0130, 12), _none()), "");
        (bytes memory d, bytes32 b) = _msig(2, 1, 1);
        bytes memory key = _pk(0x0142, 12);
        IUARegistry.UAAttrs memory ab = _a(b, UAKinds.MSIG, key);
        r.register(UAKinds.MSIG, d, ab, _msigPop(d, b, ab, true), _rReg(b, UAKinds.MSIG, key));
        bytes32 c = _holder(0x0132, _pk(0x0132, 13), _pk(0x0142, 13));
        assertEq(r.uaCount(UAKinds.PQZ_MLWE), 3);
        bytes32[] memory page = r.uaPage(UAKinds.PQZ_MLWE, 0, 10);
        assertEq(page.length, 3);
        assertEq(page[0], a);
        assertEq(page[1], b);
        assertEq(page[2], c);
        assertEq(r.uaCount(0x0130), 2);
    }
}
