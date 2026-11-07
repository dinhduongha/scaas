// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {SSTORE2} from "../../src/common/SSTORE2.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {UARegistryBase} from "./UARegistryBase.sol";
import {UACall} from "./UACall.sol";

/// Group 3g, T51 (spec 2026-11-06-pqz-key-versions §2, §14 registry rows; CTR-UA-41 draft): versioned PQZ key records.
/// Version 0 is today's key, write-once (R2); a version v ≥ 1 needs version 0 and `v == latest + 1`, the UA's own `UASig`
/// (the `msig`'s minimal m-of-n) over typed `UAPqzKeyVersionRecord`, distinct key bytes per UA (`pqzKeyUsed`), its own
/// `R_REG` over typed `UAPqzKeyVersion`, `proven`, `keyOwner`; `current` = the highest eligible version, moving only where
/// proof bytes are stored. The stand-in verifier (`MockVerifier`) answers exactly `keccak256(abi.encode(key, message))`, so
/// every message the registry builds is what these tests check; slot 0x0142 has it on `pv`, is empty on `nv`. UNAUDITED.
contract PqzKeyVersionsTest is UARegistryBase {
    uint16 internal constant ML = 0x0131; // mldsa65, stored, a PQZ holder
    address internal constant REG_V = 0x5Ca0000000000000000000000000000000000031;
    address internal constant REG_N = 0x5CA0000000000000000000000000000000000032;
    address internal constant REG_H = 0x5Ca0000000000000000000000000000000000033;
    address internal constant REG_B2 = 0x5ca0000000000000000000000000000000000034;

    UARegistry internal pv; // slot 0x0142 has the verifier
    UARegistry internal nv; // slot 0x0142 empty
    bytes internal ml1;
    bytes internal ml2;
    bytes internal ml3;
    bytes internal op; // an operator's key: a UA of its own, no member of the `msig`

    /// One PQZ key version as the client builds it: its key, `R_REG` proof over the version's message, the proof's hash.
    struct V {
        uint64 version;
        bytes key;
        bytes32 h;
        bytes proof;
        bytes32 ph;
    }

    function setUp() public override {
        super.setUp();
        pv = _deploy(REG_V, chainUidA, address(0), false, BUDGET, address(0), true, _kinds(true));
        nv = _deploy(REG_N, chainUidA, address(0), false, BUDGET, address(0), true, _kinds(false));
        (ml1, ml2, ml3, op) = (_ml(1), _ml(2), _ml(3), _ml(4));
    }

    // ----- fixtures -----

    function _kinds(bool pqz) internal view returns (UARegistry.KindConfig[] memory c) {
        c = new UARegistry.KindConfig[](pqz ? 2 : 1);
        c[0] = UARegistry.KindConfig(ML, address(mock), 400_000);
        if (pqz) c[1] = UARegistry.KindConfig(UAKinds.PQZ_MLWE, address(mock), 1_000_000);
    }

    /// Gen 2 enabling 0x0142 in front of `g1` (which does not): the host of gen-1 records' PQZ attachment.
    function _host(UARegistry g1) internal returns (UARegistry) {
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](1);
        c[0] = UARegistry.KindConfig(UAKinds.PQZ_MLWE, address(mock), 1_000_000);
        return _deploy(REG_H, chainUidA, address(g1), false, BUDGET, address(0), true, c);
    }

    function _ml(uint256 salt) internal pure returns (bytes memory) {
        return _bytes(salt, 1952);
    }

    function _bytes(uint256 salt, uint256 n) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i; i < n; i += 32) {
            bytes32 w = keccak256(abi.encode(salt, i));
            for (uint256 j; j < 32 && i + j < n; ++j) b[i + j] = w[j];
        }
    }

    /// A PQZ key of this build's set (`PqzSet.PK`).
    function _pk(uint256 salt) internal pure returns (bytes memory) {
        return _bytes(0x9e2 + salt, PqzSet.PK);
    }

    /// A PQZ key of another set's length.
    function _pkOther(uint256 salt) internal pure returns (bytes memory) {
        return _bytes(0x9e3 + salt, PqzSet.PK == 16_384 ? 18_432 : 16_384);
    }

    function _h(bytes memory pqzKey) internal pure returns (bytes32) {
        return UAKinds.keyHashOf(UAKinds.PQZ_MLWE, pqzKey);
    }

    /// `R_REG` of a `register` key: over `uaMessage(0x0142, PURPOSE_POP_V2, typed(UAPortableRecord))`, no KEM record.
    function _regProof(bytes32 ua, uint16 kind, bytes memory pqzKey) internal pure returns (bytes memory) {
        bytes32 d = UAKinds.portableRecordDigest(ua, kind, _h(pqzKey), UAKinds.kemRecordHash(ua, 0, ""));
        return _sig(pqzKey, UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_POP_V2, d));
    }

    /// The `R_REG` message of version `v` ≥ 1.
    function _vMsg(bytes32 ua, uint64 v, bytes32 h) internal pure returns (bytes32) {
        return UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_PQZ_KEY, UAKinds.pqzKeyVersionDigest(ua, v, h));
    }

    function _ver(bytes32 ua, uint64 v, bytes memory pqzKey) internal pure returns (V memory x) {
        (x.version, x.key, x.h) = (v, pqzKey, _h(pqzKey));
        x.proof = _sig(pqzKey, _vMsg(ua, v, x.h));
        x.ph = keccak256(x.proof);
    }

    /// The consent digest of version `x` (version 0: today's `UAPqzKeyRecord`).
    function _rd(bytes32 ua, V memory x) internal pure returns (bytes32) {
        return x.version == 0
            ? UAKinds.pqzKeyRecordDigest(ua, x.h, x.ph)
            : UAKinds.pqzKeyVersionRecordDigest(ua, x.version, x.h, x.ph);
    }

    /// A single-key holder's consent: its signature over `uaMessage(ML, PURPOSE_PQZ_KEY, rd)`.
    function _one(bytes memory key, bytes32 rd) internal pure returns (IUARegistry.UASig memory s) {
        s.signature = _sig(key, UAKinds.uaMessage(ML, UAKinds.PURPOSE_PQZ_KEY, rd));
    }

    /// The single-key holder of `key`, registered on `r` with version 0 `pqzKey` (none if empty), proven with `withPop`.
    function _single(UARegistry r, bytes memory key, bytes memory pqzKey, bool withPop) internal returns (bytes32 ua) {
        ua = UAKinds.uaOf(ML, key);
        IUARegistry.UAAttrs memory a;
        bytes memory proof;
        if (pqzKey.length != 0) {
            proof = _regProof(ua, ML, pqzKey);
            (a.pqzKey, a.pqzPopHash) = (pqzKey, keccak256(proof));
        }
        UACall.register(r, ML, key, a, _pop(r, ML, key, a), withPop ? proof : bytes(""));
    }

    /// `setPqzKey` of `x` for the single-key holder of `key`.
    function _set(UARegistry r, bytes memory key, V memory x) internal {
        bytes32 ua = UAKinds.uaOf(ML, key);
        r.setPqzKey(ua, x.version, x.key, x.ph, _one(key, _rd(ua, x)));
    }

    /// 2-of-(ml1, ml2, ml3): PQ-eligible.
    function _msig() internal view returns (bytes memory d, bytes32 ua) {
        Member[] memory m = new Member[](3);
        m[0] = Member(ML, UAKinds.uaOf(ML, ml1), 1);
        m[1] = Member(ML, UAKinds.uaOf(ML, ml2), 1);
        m[2] = Member(ML, UAKinds.uaOf(ML, ml3), 1);
        d = _msigKey(2, m);
        ua = UAKinds.uaOf(UAKinds.MSIG, d);
    }

    function _mlSig(bytes memory d, bytes memory key, bytes32 purpose, bytes32 digest)
        internal
        pure
        returns (IUARegistry.MemberSig memory)
    {
        bytes32 md = _memberDigest(UAKinds.uaOf(UAKinds.MSIG, d), purpose, digest);
        return IUARegistry.MemberSig(
            _indexOf(d, UAKinds.uaOf(ML, key)),
            new IUARegistry.InnerSig[](0),
            _sig(key, UAKinds.uaMessage(ML, UAKinds.PURPOSE_MEMBER, md))
        );
    }

    function _two(IUARegistry.MemberSig memory a, IUARegistry.MemberSig memory b)
        internal
        pure
        returns (IUARegistry.UASig memory s)
    {
        s.members = new IUARegistry.MemberSig[](2);
        (s.members[0], s.members[1]) = a.index < b.index ? (a, b) : (b, a);
    }

    /// The `msig` holder registered on `r` (members first) with version 0 `pqzKey`, by the `pop` of ml1 + ml2.
    function _msigHolder(UARegistry r, bytes memory pqzKey, bool withPop) internal returns (bytes memory d, bytes32 ua) {
        (_register(r, ML, ml1), _register(r, ML, ml2), _register(r, ML, ml3));
        (d, ua) = _msig();
        bytes memory proof = _regProof(ua, UAKinds.MSIG, pqzKey);
        IUARegistry.UAAttrs memory a;
        (a.pqzKey, a.pqzPopHash) = (pqzKey, keccak256(proof));
        bytes32 rd = _regDigest(ua, UAKinds.MSIG, a);
        bytes memory pop = abi.encode(
            _two(_mlSig(d, ml1, UAKinds.PURPOSE_POP_V2, rd), _mlSig(d, ml2, UAKinds.PURPOSE_POP_V2, rd)).members
        );
        UACall.register(r, UAKinds.MSIG, d, a, pop, withPop ? proof : bytes(""));
    }

    function _current(UARegistry r, bytes32 ua) internal view returns (uint64 v) {
        (v,,,) = r.pqzKeyOf(ua);
    }

    function _keyAt(UARegistry r, bytes32 ua, uint64 v) internal view returns (bytes memory) {
        (address p,,) = r.pqzKeyAt(ua, v);
        return SSTORE2.read(p);
    }

    function _provenAt(UARegistry r, bytes32 ua, uint64 v) internal view returns (bool proven) {
        (,, proven) = r.pqzKeyAt(ua, v);
    }

    function _versionErr(bytes32 ua, uint64 v) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IUARegistry.UAPqzKeyVersion.selector, ua, v);
    }

    function _count(Vm.Log[] memory logs, bytes32 topic0) internal pure returns (uint256 n) {
        for (uint256 i; i < logs.length; ++i) if (logs[i].topics.length != 0 && logs[i].topics[0] == topic0) ++n;
    }

    // ----- the records: consent (KV-1) -----

    /// Positive control: version 1 signed by the single key, stored unproven with its event, its signature, `latest`,
    /// the marker; version 0 untouched.
    function test_v1_single_stored() public {
        bytes32 ua = _single(pv, ml1, _pk(0), true);
        V memory x = _ver(ua, 1, _pk(1));
        IUARegistry.UASig memory s = _one(ml1, _rd(ua, x));
        vm.expectEmit(address(pv));
        emit IUARegistry.UAPqzKeyAdded(ua, 1, x.h, x.ph, x.key, s.signature);
        vm.prank(address(0xBEEF)); // anyone submits
        pv.setPqzKey(ua, 1, x.key, x.ph, s);
        assertEq(_keyAt(pv, ua, 1), x.key);
        (, bytes32 ph, bool proven) = pv.pqzKeyAt(ua, 1);
        assertEq(abi.encode(ph, proven), abi.encode(x.ph, false));
        assertEq(pv.pqzKeySigOf(ua, 1), s.signature);
        assertEq(pv.pqzKeySigOf(ua, 0), "", "version 0 came with register");
        assertEq(pv.pqzKeyLatest(ua), 1);
        assertTrue(pv.pqzKeyUsed(ua, x.h));
        assertTrue(pv.pqzKeyUsed(ua, _h(_pk(0))));
        assertEq(_keyAt(pv, ua, 0), _pk(0));
        assertEq(_current(pv, ua), 0);
    }

    /// Positive control: version 1 of an `msig` signed by its minimal m-of-n (ml1 + ml3), stored as `abi.encode(members)`.
    function test_v1_msig_stored() public {
        (bytes memory d, bytes32 ua) = _msigHolder(pv, _pk(0), true);
        V memory x = _ver(ua, 1, _pk(1));
        bytes32 rd = _rd(ua, x);
        IUARegistry.UASig memory s =
            _two(_mlSig(d, ml1, UAKinds.PURPOSE_PQZ_KEY, rd), _mlSig(d, ml3, UAKinds.PURPOSE_PQZ_KEY, rd));
        _acceptMl3(d, ua);
        vm.expectEmit(address(pv));
        emit IUARegistry.UAPqzKeyAdded(ua, 1, x.h, x.ph, x.key, abi.encode(s.members));
        pv.setPqzKey(ua, 1, x.key, x.ph, s);
        assertEq(_keyAt(pv, ua, 1), x.key);
        assertEq(pv.pqzKeySigOf(ua, 1), abi.encode(s.members));
    }

    /// ml3 did not sign the `pop`: it accepts its slot (CTR-UA-37) so the m-of-n may use it.
    function _acceptMl3(bytes memory d, bytes32 ua) internal {
        pv.acceptMembership(ua, _acceptKeySig(d, ML, ml3));
    }

    /// Fewer than m members: one member's signature alone is refused; its control is `test_v1_msig_stored`.
    function test_v1_fewMembers_refused() public {
        (bytes memory d, bytes32 ua) = _msigHolder(pv, _pk(0), true);
        V memory x = _ver(ua, 1, _pk(1));
        IUARegistry.UASig memory s;
        s.members = new IUARegistry.MemberSig[](1);
        s.members[0] = _mlSig(d, ml1, UAKinds.PURPOSE_PQZ_KEY, _rd(ua, x));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        pv.setPqzKey(ua, 1, x.key, x.ph, s);
    }

    /// An operator that is no quorum cannot add a version (O4): its own signature (as `signature`), or its signature in a
    /// member's slot, is refused.
    function test_v1_operator_refused() public {
        (bytes memory d, bytes32 ua) = _msigHolder(pv, _pk(0), true);
        _register(pv, ML, op);
        V memory x = _ver(ua, 1, _pk(1));
        bytes32 rd = _rd(ua, x);
        IUARegistry.UASig memory s;
        s.signature = _sig(op, UAKinds.uaMessage(ML, UAKinds.PURPOSE_PQZ_KEY, rd));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        pv.setPqzKey(ua, 1, x.key, x.ph, s);
        IUARegistry.UASig memory t = _two(_mlSig(d, ml1, UAKinds.PURPOSE_PQZ_KEY, rd), _mlSig(d, ml2, UAKinds.PURPOSE_PQZ_KEY, rd));
        IUARegistry.UASig memory u = _operatorIn(t, d, ml2, rd);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        pv.setPqzKey(ua, 1, x.key, x.ph, u);
        pv.setPqzKey(ua, 1, x.key, x.ph, t); // control
    }

    /// `t` with the operator's signature in `key`'s slot.
    function _operatorIn(IUARegistry.UASig memory t, bytes memory d, bytes memory key, bytes32 rd)
        internal
        view
        returns (IUARegistry.UASig memory u)
    {
        bytes32 md = _memberDigest(UAKinds.uaOf(UAKinds.MSIG, d), UAKinds.PURPOSE_PQZ_KEY, rd);
        uint16 i = _indexOf(d, UAKinds.uaOf(ML, key));
        u.members = new IUARegistry.MemberSig[](2);
        for (uint256 j; j < 2; ++j) {
            IUARegistry.MemberSig memory m = t.members[j];
            u.members[j] = IUARegistry.MemberSig(m.index, m.members,
                m.index == i ? _sig(op, UAKinds.uaMessage(ML, UAKinds.PURPOSE_MEMBER, md)) : m.sig);
        }
    }

    /// A portable `UASig` never carries `keyData`.
    function test_v1_keyData_refused() public {
        bytes32 ua = _single(pv, ml1, _pk(0), true);
        V memory x = _ver(ua, 1, _pk(1));
        IUARegistry.UASig memory s = _one(ml1, _rd(ua, x));
        s.keyData = ml1;
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        pv.setPqzKey(ua, 1, x.key, x.ph, s);
        s.keyData = "";
        pv.setPqzKey(ua, 1, x.key, x.ph, s);
    }

    /// The version-0 struct `UAPqzKeyRecord` signed for the same key never serves version 1.
    function test_v1_v0Struct_refused() public {
        bytes32 ua = _single(pv, ml1, _pk(0), true);
        V memory x = _ver(ua, 1, _pk(1));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        pv.setPqzKey(ua, 1, x.key, x.ph, _one(ml1, UAKinds.pqzKeyRecordDigest(ua, x.h, x.ph)));
    }

    /// The consent for version 2 never serves version 1.
    function test_v1_forV2_refused() public {
        bytes32 ua = _single(pv, ml1, _pk(0), true);
        V memory x = _ver(ua, 1, _pk(1));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        pv.setPqzKey(ua, 1, x.key, x.ph, _one(ml1, UAKinds.pqzKeyVersionRecordDigest(ua, 2, x.h, x.ph)));
    }

    /// F-11: a version-1 consent replayed as another UA's version-1 consent (`ua` is in the struct).
    function test_consent_otherUA_refused() public {
        bytes32 ua = _single(pv, ml1, _pk(0), true);
        bytes32 other = _single(pv, ml2, _pk(9), true);
        V memory x = _ver(ua, 1, _pk(1));
        IUARegistry.UASig memory s = _one(ml1, _rd(ua, x));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, other));
        pv.setPqzKey(other, 1, x.key, x.ph, s);
    }

    /// F-11, the portability control: a version-1 record and its proof from chain A replay on chain B (another chainUid).
    function test_record_crossChain_accepted() public {
        bytes32 ua = _single(pv, ml1, _pk(0), true);
        V memory x = _ver(ua, 1, _pk(1));
        _set(pv, ml1, x);
        pv.storePqzPop(ua, 1, x.proof);
        bytes32 uidB = keccak256("chain B");
        UARegistry b = _deploy(REG_B2, uidB, address(0), false, BUDGET, address(0), true, _kinds(true));
        _single(b, ml1, _pk(0), true);
        vm.chainId(4242);
        b.setPqzKey(ua, 1, SSTORE2.read(_ptrAt(pv, ua, 1)), x.ph, UACall.sig(pv.pqzKeySigOf(ua, 1)));
        b.storePqzPop(ua, 1, pv.pqzPopOf(ua, 1));
        assertEq(_current(b, ua), 1);
        assertTrue(_provenAt(b, ua, 1));
    }

    function _ptrAt(UARegistry r, bytes32 ua, uint64 v) internal view returns (address p) {
        (p,,) = r.pqzKeyAt(ua, v);
    }

    // ----- sequence (KV-1) -----

    function test_sequence_gap_refused() public {
        bytes32 ua = _single(pv, ml1, _pk(0), true);
        V memory x = _ver(ua, 2, _pk(2));
        IUARegistry.UASig memory s = _one(ml1, _rd(ua, x));
        vm.expectRevert(_versionErr(ua, 2));
        pv.setPqzKey(ua, 2, x.key, x.ph, s);
        _set(pv, ml1, _ver(ua, 1, _pk(1)));
        pv.setPqzKey(ua, 2, x.key, x.ph, s); // control: latest + 1
        assertEq(pv.pqzKeyLatest(ua), 2);
    }

    /// Version 1 needs version 0: a holder registered without a PQZ key adds version 0 first.
    function test_sequence_noV0_refused() public {
        bytes32 ua = _single(pv, ml1, "", false);
        V memory x = _ver(ua, 1, _pk(1));
        IUARegistry.UASig memory s = _one(ml1, _rd(ua, x));
        vm.expectRevert(_versionErr(ua, 1));
        pv.setPqzKey(ua, 1, x.key, x.ph, s);
        V memory z = _ver(ua, 0, _pk(0));
        z.proof = _sig(z.key, UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_PQZ_KEY, UAKinds.pqzKeyDigest(ua, z.h)));
        z.ph = keccak256(z.proof);
        _set(pv, ml1, z);
        pv.setPqzKey(ua, 1, x.key, x.ph, s);
    }

    function test_sequence_twice_refused() public {
        bytes32 ua = _single(pv, ml1, _pk(0), true);
        V memory x = _ver(ua, 1, _pk(1));
        _set(pv, ml1, x);
        V memory y = _ver(ua, 1, _pk(2));
        IUARegistry.UASig memory s = _one(ml1, _rd(ua, y));
        vm.expectRevert(_versionErr(ua, 1));
        pv.setPqzKey(ua, 1, y.key, y.ph, s);
        vm.expectRevert(_versionErr(ua, 1));
        _set(pv, ml1, x); // the same record again
    }

    // ----- R_REG per version (KV-2) -----

    /// Version 1's record whose proof was made over `m`: stored (the hash is the record's), refused by the verifier.
    function _rregRefused(bytes32 m) internal {
        bytes32 ua = _single(pv, ml1, _pk(0), true);
        V memory x = _ver(ua, 1, _pk(1));
        x.proof = _sig(x.key, m == 0 ? _vMsg(ua, 1, x.h) : m);
        x.ph = keccak256(x.proof);
        _set(pv, ml1, x);
        if (m != 0) vm.expectRevert(IUARegistry.UAPoP.selector);
        pv.storePqzPop(ua, 1, x.proof);
    }

    function test_rreg_control_accepted() public {
        _rregRefused(0);
    }

    function test_rreg_v2Message_refused() public {
        bytes32 ua = UAKinds.uaOf(ML, ml1);
        _rregRefused(_vMsg(ua, 2, _h(_pk(1))));
    }

    function test_rreg_unversioned_refused() public {
        bytes32 ua = UAKinds.uaOf(ML, ml1);
        _rregRefused(UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_PQZ_KEY, UAKinds.pqzKeyDigest(ua, _h(_pk(1)))));
    }

    function test_rreg_popV2_refused() public {
        bytes32 ua = UAKinds.uaOf(ML, ml1);
        bytes32 d = UAKinds.portableRecordDigest(ua, ML, _h(_pk(1)), UAKinds.kemRecordHash(ua, 0, ""));
        _rregRefused(UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_POP_V2, d));
    }

    /// M-R1: version 2's record whose proof was made over version 1's message (a v1 proof accepted for v2).
    function test_rreg_v1MessageForV2_refused() public {
        bytes32 ua = _single(pv, ml1, _pk(0), true);
        _set(pv, ml1, _ver(ua, 1, _pk(1)));
        V memory y = _ver(ua, 2, _pk(2));
        y.proof = _sig(y.key, _vMsg(ua, 1, y.h));
        y.ph = keccak256(y.proof);
        _set(pv, ml1, y);
        vm.expectRevert(IUARegistry.UAPoP.selector);
        pv.storePqzPop(ua, 2, y.proof);
    }

    function test_rreg_otherUA_refused() public {
        _rregRefused(_vMsg(UAKinds.uaOf(ML, ml2), 1, _h(_pk(1))));
    }

    // ----- distinct keys per UA (KV-1 marker, KV-2 keyOwner; Codex #1) -----

    /// Version 1 with version 0's bytes: `UAKeyInUse(h, ua)` at `setPqzKey`, with the verifier.
    function test_repeatedKey_refused_verifier() public {
        _repeated(pv);
    }

    /// The same without the verifier, where no `keyOwner` is ever written.
    function test_repeatedKey_refused_noVerifier() public {
        _repeated(nv);
    }

    function _repeated(UARegistry r) internal {
        bytes32 ua = _single(r, ml1, _pk(0), false);
        V memory x = _ver(ua, 1, _pk(0));
        IUARegistry.UASig memory s = _one(ml1, _rd(ua, x));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyInUse.selector, x.h, ua));
        r.setPqzKey(ua, 1, x.key, x.ph, s);
        _set(r, ml1, _ver(ua, 1, _pk(1)));
        V memory y = _ver(ua, 2, _pk(1)); // version 2 with version 1's bytes
        s = _one(ml1, _rd(ua, y));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyInUse.selector, y.h, ua));
        r.setPqzKey(ua, 2, y.key, y.ph, s);
        _set(r, ml1, _ver(ua, 2, _pk(2))); // control
    }

    /// On a host whose gen 1 stores the key: the marker is read on the predecessor too.
    function test_repeatedKey_refused_host() public {
        bytes32 ua = _single(nv, ml1, _pk(0), false);
        UARegistry g2 = _host(nv);
        V memory x = _ver(ua, 1, _pk(0));
        IUARegistry.UASig memory s = _one(ml1, _rd(ua, x));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyInUse.selector, x.h, ua));
        g2.setPqzKey(ua, 1, x.key, x.ph, s);
        _set(g2, ml1, _ver(ua, 1, _pk(1)));
        assertTrue(g2.pqzKeyUsed(ua, x.h), "gen 1's marker read through the host");
        assertFalse(nv.pqzKeyUsed(ua, _h(_pk(1))), "gen 1 does not see the host");
    }

    /// Version 1 with another UA's proven key: the cross-UA rule stays the proof-time `keyOwner` check.
    function test_otherUAsKey_refusedAtProof() public {
        bytes32 a = _single(pv, ml1, _pk(0), true);
        bytes32 b = _single(pv, ml2, _pk(5), true);
        V memory x = _ver(b, 1, _pk(0)); // a's proven key
        _set(pv, ml2, x);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyInUse.selector, x.h, a));
        pv.storePqzPop(b, 1, x.proof);
    }

    // ----- current (KV-3) -----

    /// `setPqzKey` never moves `current`, on either registry kind.
    function test_current_notAtSetPqzKey() public {
        bytes32 ua = _single(pv, ml1, _pk(0), true);
        assertEq(_current(pv, ua), 0);
        _set(pv, ml1, _ver(ua, 1, _pk(1)));
        assertEq(_current(pv, ua), 0);
        bytes32 ub = _single(nv, ml1, _pk(0), true);
        _set(nv, ml1, _ver(ub, 1, _pk(1)));
        assertEq(_current(nv, ub), 0);
        (uint64 v, address ptr,, bool proven) = nv.pqzKeyOf(ub);
        assertEq(abi.encode(v, SSTORE2.read(ptr), proven), abi.encode(uint64(0), _pk(0), false));
    }

    /// `storePqzPop` moves it, with `UAPqzKeyCurrent`; `pqzKeyOf`, `recordOf`, `checkedOf` follow.
    function test_current_atStorePqzPop() public {
        bytes32 ua = _single(pv, ml1, _pk(0), true);
        V memory x = _ver(ua, 1, _pk(1));
        _set(pv, ml1, x);
        vm.expectEmit(address(pv));
        emit IUARegistry.UAPqzPopStored(ua, 1, UAKinds.CHECKED_CHAIN, x.proof);
        vm.expectEmit(address(pv));
        emit IUARegistry.UAPqzKeyCurrent(ua, 1);
        pv.storePqzPop(ua, 1, x.proof);
        (uint64 v, address ptr, bytes32 ph, bool proven) = pv.pqzKeyOf(ua);
        assertEq(abi.encode(v, SSTORE2.read(ptr), ph, proven), abi.encode(uint64(1), x.key, x.ph, true));
        (, address rp) = pv.recordOf(ua);
        assertEq(rp, ptr);
        assertEq(pv.keyOwner(x.h), ua);
        assertEq(pv.pqzPopOf(ua, 1), x.proof);
    }

    /// A version of another set's length is stored, its bytes too, and never becomes current here (no verifier: the length
    /// rule; with the verifier the real `R_REG` refuses it); version 2 of this set follows it.
    function test_current_otherSetNever() public {
        bytes32 ua = _single(nv, ml1, _pk(0), true);
        assertEq(_current(nv, ua), 0);
        V memory x = _ver(ua, 1, _pkOther(1));
        _set(nv, ml1, x);
        vm.recordLogs();
        nv.storePqzPop(ua, 1, x.proof);
        assertEq(_count(vm.getRecordedLogs(), IUARegistry.UAPqzKeyCurrent.selector), 0);
        assertEq(_current(nv, ua), 0);
        V memory y = _ver(ua, 2, _pk(2));
        _set(nv, ml1, y);
        nv.storePqzPop(ua, 2, y.proof);
        assertEq(_current(nv, ua), 2);
    }

    /// Without the verifier a version of this set's length is not current until its proof bytes are stored (F-1).
    function test_current_noBytesNotCurrent() public {
        bytes32 ua = _single(nv, ml1, _pk(0), false);
        assertEq(_current(nv, ua), 0);
        V memory x = _ver(ua, 1, _pk(1));
        _set(nv, ml1, x);
        assertEq(_current(nv, ua), 0);
        vm.expectEmit(address(nv));
        emit IUARegistry.UAPqzKeyCurrent(ua, 1);
        nv.storePqzPop(ua, 1, x.proof);
        (uint64 v,,, bool proven) = nv.pqzKeyOf(ua);
        assertEq(abi.encode(v, proven), abi.encode(uint64(1), false), "eligible without the verifier, never proven");
    }

    /// `current` is the highest eligible version, not the latest stored (M-R3).
    function test_current_highestEligibleNotLatest() public {
        bytes32 ua = _single(pv, ml1, _pk(0), true);
        V memory x = _ver(ua, 1, _pk(1));
        _set(pv, ml1, x);
        _set(pv, ml1, _ver(ua, 2, _pk(2)));
        pv.storePqzPop(ua, 1, x.proof);
        assertEq(_current(pv, ua), 1);
        assertEq(pv.pqzKeyLatest(ua), 2);
    }

    /// A late proof below `current` keeps `current` (non-decreasing) and emits no `UAPqzKeyCurrent`.
    function test_current_lateProofKeeps() public {
        bytes32 ua = _single(pv, ml1, _pk(0), true);
        V memory x = _ver(ua, 1, _pk(1));
        V memory y = _ver(ua, 2, _pk(2));
        _set(pv, ml1, x);
        _set(pv, ml1, y);
        pv.storePqzPop(ua, 2, y.proof);
        assertEq(_current(pv, ua), 2);
        vm.recordLogs();
        pv.storePqzPop(ua, 1, x.proof);
        assertEq(_count(vm.getRecordedLogs(), IUARegistry.UAPqzKeyCurrent.selector), 0);
        assertEq(_current(pv, ua), 2);
        assertTrue(_provenAt(pv, ua, 1), "readable, proven");
    }

    /// `register` with `pqzPop` emits `UAPqzKeyCurrent(ua, 0)`; never `UAPqzKeyAdded` (F-10).
    function test_current_registerWithPop() public {
        bytes32 ua = UAKinds.uaOf(ML, ml1);
        vm.recordLogs();
        _single(pv, ml1, _pk(0), true);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(_count(logs, IUARegistry.UAPqzKeyCurrent.selector), 1);
        assertEq(_count(logs, IUARegistry.UAPqzKeyAdded.selector), 0);
        (uint64 v,,, bool proven) = pv.pqzKeyOf(ua);
        assertEq(abi.encode(v, proven), abi.encode(uint64(0), true));
    }

    function test_register_noPqzKeyAdded() public {
        vm.recordLogs();
        _single(pv, ml1, _pk(0), false);
        _msigHolder(nv, _pk(1), true);
        assertEq(_count(vm.getRecordedLogs(), IUARegistry.UAPqzKeyAdded.selector), 0);
    }

    /// The `0x0142` list holds the UA once after version 0 and version 1 are proven (J9).
    function test_list_once() public {
        bytes32 ua = _single(pv, ml1, _pk(0), true);
        V memory x = _ver(ua, 1, _pk(1));
        _set(pv, ml1, x);
        pv.storePqzPop(ua, 1, x.proof);
        assertEq(pv.uaCount(UAKinds.PQZ_MLWE), 1);
        assertEq(pv.uaAt(UAKinds.PQZ_MLWE, 0), ua);
    }

    // ----- R2: version 0 write-once -----

    /// R2 retires R-cross-set's replacement: a second version-0 key, even where the first is of another set and can
    /// never be proven here, is `UAPqzKeySet`; this chain's set gets version 1.
    function test_v0_secondKey_refused() public {
        bytes32 ua = _single(pv, ml1, _pkOther(0), false);
        V memory z = _ver(ua, 0, _pk(0));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzKeySet.selector, ua));
        pv.setPqzKey(ua, 0, z.key, z.ph, _one(ml1, _rd(ua, z)));
        V memory x = _ver(ua, 1, _pk(1));
        _set(pv, ml1, x);
        pv.storePqzPop(ua, 1, x.proof);
        assertEq(_current(pv, ua), 1);
        assertEq(_keyAt(pv, ua, 0), _pkOther(0), "nothing replaced");
        (, bytes memory kd, IUARegistry.UAAttrs memory a,,) = pv.registrationOf(ua);
        assertEq(abi.encode(kd, a.pqzKey), abi.encode(ml1, _pkOther(0)), "registrationOf: the register arguments");
    }

    /// Control: without the verifier nothing was ever replaced; the same refusal.
    function test_v0_noVerifier_nothingReplaced() public {
        bytes32 ua = _single(nv, ml1, _pkOther(0), false);
        V memory z = _ver(ua, 0, _pk(0));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzKeySet.selector, ua));
        nv.setPqzKey(ua, 0, z.key, z.ph, _one(ml1, _rd(ua, z)));
        assertEq(_keyAt(nv, ua, 0), _pkOther(0));
    }

    // ----- generations: the host rules 1–4 (§2.3) -----

    /// Rule 1: the host's sequence reads `max(latest_host, latest_gen1)`; a version stored in either is refused there.
    function test_host_latestMax() public {
        bytes32 ua = _single(nv, ml1, _pk(0), false);
        _set(nv, ml1, _ver(ua, 1, _pk(1)));
        UARegistry g2 = _host(nv);
        assertEq(g2.pqzKeyLatest(ua), 1);
        V memory x = _ver(ua, 1, _pk(7));
        IUARegistry.UASig memory s = _one(ml1, _rd(ua, x));
        vm.expectRevert(_versionErr(ua, 1));
        g2.setPqzKey(ua, 1, x.key, x.ph, s);
        V memory z = _ver(ua, 0, _pk(8));
        s = _one(ml1, _rd(ua, z));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzKeySet.selector, ua));
        g2.setPqzKey(ua, 0, z.key, z.ph, s);
        _set(g2, ml1, _ver(ua, 2, _pk(2)));
        assertEq(g2.pqzKeyLatest(ua), 2);
        assertEq(nv.pqzKeyLatest(ua), 1);
        _set(g2, ml1, _ver(ua, 3, _pk(3)));
        assertEq(g2.pqzKeyLatest(ua), 3);
    }

    /// Rule 2: the host reads its own record of a version first, gen 1's otherwise.
    function test_host_readsOwnFirst() public {
        bytes32 ua = _single(nv, ml1, _pk(0), false);
        UARegistry g2 = _host(nv);
        V memory x = _ver(ua, 1, _pk(1));
        _set(g2, ml1, x);
        assertEq(_keyAt(g2, ua, 1), x.key);
        assertEq(_keyAt(g2, ua, 0), _pk(0), "gen 1's version 0");
        assertEq(g2.pqzKeySigOf(ua, 1), _one(ml1, _rd(ua, x)).signature);
        (address p1,,) = nv.pqzKeyAt(ua, 1);
        assertEq(p1, address(0), "gen 1 untouched");
    }

    /// Rule 2: once the host holds a version its answer never changes as gen 1 grows.
    function test_host_stableAsGen1Grows() public {
        bytes32 ua = _single(nv, ml1, _pk(0), false);
        UARegistry g2 = _host(nv);
        bytes memory proof = _regProof(ua, ML, _pk(0));
        g2.storePqzPop(ua, 0, proof); // the host proves gen 1's version 0 and holds it
        (address before,,) = g2.pqzKeyAt(ua, 0);
        _set(nv, ml1, _ver(ua, 1, _pk(1)));
        (address afterward,, bool proven) = g2.pqzKeyAt(ua, 0);
        assertEq(abi.encode(afterward, proven), abi.encode(before, true));
        assertEq(g2.pqzKeyLatest(ua), 1, "gen 1's version 1 counts for the sequence");
        assertEq(_keyAt(g2, ua, 1), _pk(1));
        assertEq(_current(g2, ua), 0);
    }

    /// Rule 3: the host proves a version only by checking the bytes itself; gen 1's stored, unchecked bytes are no proof.
    function test_host_provesBytesItself() public {
        bytes32 ua = _single(nv, ml1, _pk(0), false);
        V memory x = _ver(ua, 1, _pk(1));
        x.proof = hex"0badbadbad"; // a proof the verifier refuses, its hash the record's
        x.ph = keccak256(x.proof);
        _set(nv, ml1, x);
        nv.storePqzPop(ua, 1, x.proof); // stored in gen 1 (no verifier)
        assertEq(_current(nv, ua), 1, "eligible on gen 1 by length and bytes");
        UARegistry g2 = _host(nv);
        (,,, bool proven) = g2.pqzKeyOf(ua);
        assertFalse(proven);
        assertEq(_current(g2, ua), 0, "the host's current is the host's");
        bytes memory stored = nv.pqzPopOf(ua, 1);
        assertEq(stored, x.proof);
        vm.expectRevert(IUARegistry.UAPoP.selector);
        g2.storePqzPop(ua, 1, stored);
        V memory y = _ver(ua, 2, _pk(2)); // control: a good proof of a gen-1 version, checked here
        _set(nv, ml1, y);
        g2.storePqzPop(ua, 2, y.proof);
        assertEq(_current(g2, ua), 2);
        assertTrue(_provenAt(g2, ua, 2));
        assertFalse(_provenAt(nv, ua, 2));
    }

    /// Rule 4, the accepted divergence: gen 1 cannot see the host, so a gen-1 write of a version the host holds stores a
    /// second record at that number in gen 1; each generation answers its own.
    function test_host_gen1Divergence() public {
        bytes32 ua = _single(nv, ml1, _pk(0), false);
        UARegistry g2 = _host(nv);
        V memory x = _ver(ua, 1, _pk(1));
        _set(g2, ml1, x);
        V memory y = _ver(ua, 1, _pk(2));
        _set(nv, ml1, y);
        assertEq(_keyAt(g2, ua, 1), x.key);
        assertEq(_keyAt(nv, ua, 1), y.key);
    }

    // ----- typehashes -----

    function test_UAPqzKeyVersionTypehashIsPinned() public pure {
        bytes32 th = keccak256("UAPqzKeyVersion(bytes32 ua,uint64 version,bytes32 pqzKeyHash)");
        assertEq(UAKinds.UA_PQZ_KEY_VERSION_TYPEHASH, th);
        assertEq(th, 0x56bb760a3968427f1aa06b0497de42c05374beae46765175b61976c12e38b158);
        (bytes32 ua, bytes32 h) = (keccak256("ua"), keccak256("h"));
        assertEq(UAKinds.pqzKeyVersionDigest(ua, 3, h),
            keccak256(abi.encodePacked(hex"1901", UAKinds.PORTABLE_DOMAIN_SEPARATOR, keccak256(abi.encode(th, ua, uint64(3), h)))));
    }

    function test_UAPqzKeyVersionRecordTypehashIsPinned() public pure {
        bytes32 th = keccak256(
            "UAPqzKeyVersionRecord(UAPqzKeyVersion key,bytes32 pqzPopHash)UAPqzKeyVersion(bytes32 ua,uint64 version,bytes32 pqzKeyHash)"
        );
        assertEq(UAKinds.UA_PQZ_KEY_VERSION_RECORD_TYPEHASH, th);
        assertEq(th, 0x2e00b7c0ff5cfbca3f50e0445bcd02bb227e0154c239c812b38d9b8fa6e7d6e5);
        (bytes32 ua, bytes32 h, bytes32 ph) = (keccak256("ua"), keccak256("h"), keccak256("ph"));
        bytes32 k = keccak256(abi.encode(UAKinds.UA_PQZ_KEY_VERSION_TYPEHASH, ua, uint64(3), h));
        assertEq(UAKinds.pqzKeyVersionRecordDigest(ua, 3, h, ph),
            keccak256(abi.encodePacked(hex"1901", UAKinds.PORTABLE_DOMAIN_SEPARATOR, keccak256(abi.encode(th, k, ph)))));
        assertTrue(_distinctFromV0(ua, h, ph));
    }

    function _distinctFromV0(bytes32 ua, bytes32 h, bytes32 ph) internal pure returns (bool) {
        return UAKinds.pqzKeyVersionDigest(ua, 1, h) != UAKinds.pqzKeyDigest(ua, h)
            && UAKinds.pqzKeyVersionRecordDigest(ua, 1, h, ph) != UAKinds.pqzKeyRecordDigest(ua, h, ph);
    }

    /// The registry's two pure views equal `UAKinds`'s.
    function test_versionDigestViews() public view {
        (bytes32 ua, bytes32 h, bytes32 ph) = (keccak256("ua"), keccak256("h"), keccak256("ph"));
        assertEq(pv.pqzKeyVersionDigest(ua, 2, h), UAKinds.pqzKeyVersionDigest(ua, 2, h));
        assertEq(pv.pqzKeyVersionRecordDigest(ua, 2, h, ph), UAKinds.pqzKeyVersionRecordDigest(ua, 2, h, ph));
    }
}
