// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {SSTORE2} from "../../src/common/SSTORE2.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {UARegistryBase} from "./UARegistryBase.sol";
import {UACall} from "./UACall.sol";

/// A token as the registry sees it for a class-3 record: `pqzVerifyConfig()` answers the static `PqzVerifyConfig` tuple whose
/// word 12 is `pqzOpening` (K3-1: `pqzOwnKey`, `pqzOpening` appended after `verifierFeeEta`). `words` < 13 answers short, more
/// pads with zero words; `opening` any word (2 = not a bool); `own` word 11 (Fable P3-1: 0 is a token without its own key).
contract MockScopeToken {
    uint256 public opening;
    uint256 public words = 13;
    uint256 public own = 1;

    function setOwn(uint256 own_) external {
        own = own_;
    }

    constructor(uint256 opening_) {
        opening = opening_;
    }

    function setShape(uint256 opening_, uint256 words_) external {
        (opening, words) = (opening_, words_);
    }

    fallback() external {
        if (msg.sig != bytes4(keccak256("pqzVerifyConfig()"))) revert("no");
        uint256 n = words;
        uint256 w = opening;
        uint256 o = own;
        assembly {
            for { let i := 0 } lt(i, n) { i := add(i, 1) } { mstore(mul(i, 32), 0) }
            if gt(n, 11) { mstore(mul(11, 32), o) } // pqzOwnKey: a 12-word answer carries it, only pqzOpening is missing
            if gt(n, 12) { mstore(mul(12, 32), w) }
            return(0, mul(n, 32))
        }
    }
}

/// A `PqzKeyVerifier` stand-in as it answers at one set: `verifyPop` refuses a key of any other length (the real verifier's
/// `pk.length == PqzSet.PK` check), else the base mock's rule (the signature is `keccak256(abi.encode(key, message))`).
contract SetVerifierStandIn {
    function verifyPop(bytes calldata key, bytes32 message, bytes calldata sig) external pure returns (bool) {
        return key.length == PqzSet.PK && sig.length == 32 && bytes32(sig) == keccak256(abi.encode(key, message));
    }
}

/// The PQZ three-key model, step 3 (spec 2026-11-13-pqz-three-keys K3-3, §14 items 3, 6, 17 — the registry parts): the scoped
/// PQZ key records `(ua, scope, version)`, scope 0 class `offchain-shared`, a token class `offchain-token`. The stand-in
/// verifier answers exactly `keccak256(abi.encode(key, message))` (`UARegistryBase`), so every message the registry builds is
/// what these tests check; slot 0x0142 has it on `pv`, is empty on `nv`. Each negative changes one thing against a positive
/// control named beside it. UNAUDITED.
contract PqzScopedKeysTest is UARegistryBase {
    uint16 internal constant ML = 0x0131; // mldsa65, stored, a PQZ and KEM holder
    address internal constant REG_V = 0x5cA0000000000000000000000000000000000041;
    address internal constant REG_N = 0x5ca0000000000000000000000000000000000042;
    uint64 internal constant FAR = type(uint64).max;

    UARegistry internal pv; // slot 0x0142 has the verifier
    UARegistry internal nv; // slot 0x0142 empty
    MockScopeToken internal tOn; // pqzOpening = true
    MockScopeToken internal tOff; // pqzOpening = false
    bytes internal ml1;
    bytes internal ml2;
    bytes internal ml3;

    /// One scoped record as the client builds it.
    struct R {
        bytes32 ua;
        address scope;
        uint64 version;
        bytes key;
        bytes32 h;
        bytes proof;
        bytes32 ph;
        IUARegistry.KemKey kem;
        uint64 until;
        bytes32 chainUid;
    }

    function setUp() public override {
        super.setUp();
        pv = _deploy(REG_V, chainUidA, address(0), false, BUDGET, address(0), true, _kinds(true));
        nv = _deploy(REG_N, chainUidA, address(0), false, BUDGET, address(0), true, _kinds(false));
        (ml1, ml2, ml3) = (_bytes(1, 1952), _bytes(2, 1952), _bytes(3, 1952));
        (tOn, tOff) = (new MockScopeToken(1), new MockScopeToken(0));
    }

    // ----- fixtures -----

    function _kinds(bool pqz) internal view returns (UARegistry.KindConfig[] memory c) {
        c = new UARegistry.KindConfig[](pqz ? 2 : 1);
        c[0] = UARegistry.KindConfig(ML, address(mock), 400_000);
        if (pqz) c[1] = UARegistry.KindConfig(UAKinds.PQZ_MLWE, address(mock), 1_000_000);
    }

    function _bytes(uint256 salt, uint256 n) internal pure returns (bytes memory b) {
        b = new bytes(n);
        for (uint256 i; i < n; i += 32) {
            bytes32 w = keccak256(abi.encode(salt, i));
            for (uint256 j; j < 32 && i + j < n; ++j) b[i + j] = w[j];
        }
    }

    function _pk(uint256 salt) internal pure returns (bytes memory) {
        return _bytes(0x5c0 + salt, PqzSet.PK);
    }

    function _pkOther(uint256 salt) internal pure returns (bytes memory) {
        return _bytes(0x5c1 + salt, PqzSet.PK == 16_384 ? 18_432 : 16_384);
    }

    function _h(bytes memory k) internal pure returns (bytes32) {
        return UAKinds.keyHashOf(UAKinds.PQZ_MLWE, k);
    }

    function _kem(uint256 salt) internal pure returns (IUARegistry.KemKey memory k) {
        (k.scheme, k.mlkemEk, k.x25519) = (1, _bytes(0xcee + salt, 1568), keccak256(abi.encode("x", salt)));
    }

    function _class(address scope) internal pure returns (uint8) {
        return scope == address(0) ? 2 : 3;
    }

    function _proofMsg(R memory x) internal pure returns (bytes32) {
        return UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_PQZ_SCOPED_KEY,
            UAKinds.pqzScopedKeyDigest(x.ua, _class(x.scope), x.chainUid, x.scope, x.version, x.h));
    }

    /// The record of `key` for `(ua, scope, version)`: its `R_REG` over the scoped message, the opening KEM key when `withKem`.
    function _rec(bytes32 ua, address scope, uint64 version, bytes memory key, bool withKem) internal view returns (R memory x) {
        (x.ua, x.scope, x.version, x.key, x.h, x.until, x.chainUid) = (ua, scope, version, key, _h(key), FAR, chainUidA);
        x.proof = _sig(key, _proofMsg(x));
        x.ph = keccak256(x.proof);
        if (withKem) x.kem = _kem(version + uint256(uint160(scope)));
    }

    function _rd(R memory x) internal pure returns (bytes32) {
        bytes memory pk = UAKinds.kemPk(x.kem);
        return UAKinds.pqzScopedKeyRecordDigest(x.ua, _class(x.scope), x.chainUid, x.scope, x.version, x.h, x.ph,
            pk.length == 0 ? bytes32(0) : keccak256(pk), x.until);
    }

    function _one(bytes memory key, R memory x) internal pure returns (IUARegistry.UASig memory s) {
        s.signature = _sig(key, UAKinds.uaMessage(ML, UAKinds.PURPOSE_PQZ_SCOPED_KEY, _rd(x)));
    }

    function _set(UARegistry r, bytes memory key, R memory x) internal {
        r.setPqzScopedKey(x.ua, x.scope, x.version, x.key, x.ph, x.kem, x.until, _one(key, x));
    }

    function _setReverts(UARegistry r, bytes memory key, R memory x, bytes memory err) internal {
        IUARegistry.UASig memory s = _one(key, x);
        vm.expectRevert(err);
        r.setPqzScopedKey(x.ua, x.scope, x.version, x.key, x.ph, x.kem, x.until, s);
    }

    /// The single-key holder of `key` on `r`, no class-1 PQZ key.
    function _single(UARegistry r, bytes memory key) internal returns (bytes32) {
        return _register(r, ML, key);
    }

    /// The single-key holder with class-1 version 0 `pqzKey`, proven (on `pv`).
    function _singleClass1(UARegistry r, bytes memory key, bytes memory pqzKey) internal returns (bytes32 ua) {
        ua = UAKinds.uaOf(ML, key);
        bytes32 d = UAKinds.portableRecordDigest(ua, ML, _h(pqzKey), UAKinds.kemRecordHash(ua, 0, ""));
        bytes memory proof = _sig(pqzKey, UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_POP_V2, d));
        IUARegistry.UAAttrs memory a;
        (a.pqzKey, a.pqzPopHash) = (pqzKey, keccak256(proof));
        UACall.register(r, ML, key, a, _pop(r, ML, key, a), proof);
    }

    /// 2-of-(ml1, ml2, ml3), PQ-eligible, registered on `r` (members first) by the `pop` of ml1 + ml2.
    function _msigHolder(UARegistry r) internal returns (bytes memory d, bytes32 ua) {
        (_register(r, ML, ml1), _register(r, ML, ml2), _register(r, ML, ml3));
        Member[] memory m = new Member[](3);
        m[0] = Member(ML, UAKinds.uaOf(ML, ml1), 1);
        m[1] = Member(ML, UAKinds.uaOf(ML, ml2), 1);
        m[2] = Member(ML, UAKinds.uaOf(ML, ml3), 1);
        d = _msigKey(2, m);
        ua = UAKinds.uaOf(UAKinds.MSIG, d);
        bytes32 rd = _regDigest(ua, UAKinds.MSIG);
        UACall.register(r, UAKinds.MSIG, d, _none(), abi.encode(_two(d, ml1, ml2, UAKinds.PURPOSE_POP_V2, rd).members), "");
    }

    function _two(bytes memory d, bytes memory a, bytes memory b, bytes32 purpose, bytes32 digest)
        internal
        pure
        returns (IUARegistry.UASig memory s)
    {
        s.members = new IUARegistry.MemberSig[](2);
        IUARegistry.MemberSig memory x = _mlSig(d, a, purpose, digest);
        IUARegistry.MemberSig memory y = _mlSig(d, b, purpose, digest);
        (s.members[0], s.members[1]) = x.index < y.index ? (x, y) : (y, x);
    }

    function _mlSig(bytes memory d, bytes memory key, bytes32 purpose, bytes32 digest)
        internal
        pure
        returns (IUARegistry.MemberSig memory)
    {
        bytes32 md = _memberDigest(UAKinds.uaOf(UAKinds.MSIG, d), purpose, digest);
        return IUARegistry.MemberSig(
            _indexOf(d, UAKinds.uaOf(ML, key)), new IUARegistry.InnerSig[](0), _sig(key, UAKinds.uaMessage(ML, UAKinds.PURPOSE_MEMBER, md))
        );
    }

    function _msigSet(UARegistry r, bytes memory d, R memory x) internal {
        r.setPqzScopedKey(x.ua, x.scope, x.version, x.key, x.ph, x.kem, x.until,
            _two(d, ml1, ml2, UAKinds.PURPOSE_PQZ_SCOPED_KEY, _rd(x)));
    }

    function _err(bytes4 sel, bytes32 ua) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(sel, ua);
    }

    function _openErr(address scope) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IUARegistry.UAPqzOpenKem.selector, scope);
    }

    function _keyAt(UARegistry r, bytes32 ua, address scope, uint64 v) internal view returns (bytes memory) {
        (address p,,) = r.pqzScopedKeyAt(ua, scope, v);
        return SSTORE2.read(p);
    }

    // ----- pins -----

    function test_scopedTypehashesArePinned() public pure {
        assertEq(UAKinds.UA_PQZ_SCOPED_KEY_TYPEHASH, keccak256(
            "UAPqzScopedKey(bytes32 ua,uint8 keyClass,bytes32 chainUid,address token,uint64 version,bytes32 pqzKeyHash)"
        ));
        assertEq(UAKinds.UA_PQZ_SCOPED_KEY_TYPEHASH, 0x723f4ada3187b381bd56093531d88191f240abb45021dab25f09594d9fefe70e);
        assertEq(UAKinds.UA_PQZ_SCOPED_KEY_RECORD_TYPEHASH, keccak256(
            "UAPqzScopedKeyRecord(bytes32 ua,uint8 keyClass,bytes32 chainUid,address token,uint64 version,bytes32 pqzKeyHash,bytes32 pqzPopHash,bytes32 openKemHash,uint64 validUntilBlock)"
        ));
        assertEq(UAKinds.UA_PQZ_SCOPED_KEY_RECORD_TYPEHASH, 0xf672ed3c480fca7f0350c09663dfe02629420a7724f791624bd048e532fe1eaa);
        assertEq(UAKinds.PURPOSE_PQZ_SCOPED_KEY, keccak256("scaas.ua.purpose.pqz-scoped-key.v1"));
    }

    /// The registry's pure digest views answer `UAKinds`' (what clients and vectors reproduce).
    function test_scopedDigestViews() public view {
        assertEq(pv.pqzScopedKeyDigest(bytes32(uint256(7)), 3, chainUidA, address(tOn), 5, bytes32(uint256(9))),
            UAKinds.pqzScopedKeyDigest(bytes32(uint256(7)), 3, chainUidA, address(tOn), 5, bytes32(uint256(9))));
        assertEq(pv.pqzScopedKeyRecordDigest(bytes32(uint256(7)), 2, chainUidA, address(0), 1, bytes32(uint256(9)),
                bytes32(uint256(10)), bytes32(uint256(11)), 12),
            UAKinds.pqzScopedKeyRecordDigest(bytes32(uint256(7)), 2, chainUidA, address(0), 1, bytes32(uint256(9)),
                bytes32(uint256(10)), bytes32(uint256(11)), 12));
    }

    // ----- class 2 (scope 0): positive controls -----

    /// Positive control: a class-2 record with its opening KEM key, stored unproven (event, views, marker); then its proof
    /// proves it, it becomes current and the UA joins the scope-0 holder list. Class 1 untouched.
    function test_class2_stored_then_proven() public {
        bytes32 ua = _single(pv, ml1);
        R memory x = _rec(ua, address(0), 0, _pk(0), true);
        IUARegistry.UASig memory s = _one(ml1, x);
        vm.expectEmit(address(pv));
        emit IUARegistry.UAPqzScopedKeyAdded(ua, address(0), 0, x.h, x.ph, x.key, x.kem, FAR, s.signature);
        vm.prank(address(0xBEEF)); // anyone submits
        pv.setPqzScopedKey(ua, address(0), 0, x.key, x.ph, x.kem, FAR, s);
        assertEq(_keyAt(pv, ua, address(0), 0), x.key);
        (, bytes32 ph, bool proven) = pv.pqzScopedKeyAt(ua, address(0), 0);
        assertEq(abi.encode(ph, proven), abi.encode(x.ph, false));
        assertEq(abi.encode(pv.pqzOpenKemAt(ua, address(0), 0)), abi.encode(x.kem));
        assertTrue(pv.pqzKeyUsed(ua, x.h));
        assertEq(pv.pqzScopedCount(address(0)), 0, "listed only when eligible");
        (address p1,,) = pv.pqzKeyAt(ua, 0);
        assertEq(p1, address(0), "class 1 untouched");

        vm.expectEmit(address(pv));
        emit IUARegistry.UAPqzScopedPopStored(ua, address(0), 0, UAKinds.CHECKED_CHAIN, x.proof);
        vm.expectEmit(address(pv));
        emit IUARegistry.UAPqzScopedKeyCurrent(ua, address(0), 0);
        pv.storePqzScopedPop(ua, address(0), 0, x.proof);
        (uint64 v, address p, bytes32 ph2, bool pr) = pv.pqzScopedKeyOf(ua, address(0));
        assertEq(abi.encode(v, SSTORE2.read(p), ph2, pr), abi.encode(uint64(0), x.key, x.ph, true));
        assertEq(pv.pqzScopedPopOf(ua, address(0), 0), x.proof);
        assertEq(pv.keyOwner(x.h), ua);
        assertEq(pv.pqzScopedCount(address(0)), 1);
        assertEq(pv.pqzScopedAt(address(0), 0), ua);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAIndex.selector, UAKinds.PQZ_MLWE, uint256(1)));
        pv.pqzScopedAt(address(0), 1);
        pv.storePqzScopedPop(ua, address(0), 0, x.proof); // stored: a no-op
        assertEq(pv.pqzScopedCount(address(0)), 1);
    }

    /// Without the verifier: the proof bytes are stored unproven (CTR-PQZ-30, length only), the set-length key is current.
    function test_class2_noVerifier_eligibleBySetLength() public {
        bytes32 ua = _single(nv, ml1);
        R memory x = _rec(ua, address(0), 0, _pk(0), true);
        _set(nv, ml1, x);
        vm.expectEmit(address(nv));
        emit IUARegistry.UAPqzScopedPopStored(ua, address(0), 0, UAKinds.CHECKED_NONE, x.proof);
        nv.storePqzScopedPop(ua, address(0), 0, x.proof);
        (uint64 v, address p,, bool pr) = nv.pqzScopedKeyOf(ua, address(0));
        assertEq(abi.encode(v, SSTORE2.read(p), pr), abi.encode(uint64(0), x.key, false));
        assertEq(nv.pqzScopedCount(address(0)), 1);
        assertEq(nv.keyOwner(x.h), bytes32(0), "no owner without a proof check");
    }

    /// Fable P3-2: a class-3 key of another set than the registry's build (the token's set) is listed and becomes current on
    /// its proof bytes, versions 0 and 1, as a key of the build's set; class 2 (scope 0) keeps the set-length rule (control).
    function test_class3_otherSet_becomesCurrent() public {
        bytes32 ua = _single(nv, ml1);
        for (uint64 v; v < 2; ++v) {
            R memory x = _rec(ua, address(tOn), v, _pkOther(v), true);
            _set(nv, ml1, x);
            nv.storePqzScopedPop(ua, address(tOn), v, x.proof);
            (uint64 cur,,,) = nv.pqzScopedKeyOf(ua, address(tOn));
            assertEq(cur, v, "current moves with the token's set");
        }
        assertEq(nv.pqzScopedCount(address(tOn)), 1, "listed once");
        R memory y = _rec(ua, address(0), 0, _pkOther(9), true);
        _set(nv, ml1, y);
        nv.storePqzScopedPop(ua, address(0), 0, y.proof);
        assertEq(nv.pqzScopedCount(address(0)), 0, "scope 0: another set's key is not listed");
    }

    /// Rotation (positive control of the version rule): version 1 of the same length, its own opening KEM key; current moves.
    function test_class2_rotation() public {
        bytes32 ua = _single(pv, ml1);
        R memory x0 = _rec(ua, address(0), 0, _pk(0), true);
        _set(pv, ml1, x0);
        pv.storePqzScopedPop(ua, address(0), 0, x0.proof);
        R memory x1 = _rec(ua, address(0), 1, _pk(1), true);
        _set(pv, ml1, x1);
        assertEq(pv.pqzScopedKeyLatest(ua, address(0)), 1);
        (uint64 v,,,) = pv.pqzScopedKeyOf(ua, address(0));
        assertEq(v, 0, "not current before its proof");
        pv.storePqzScopedPop(ua, address(0), 1, x1.proof);
        (v,,,) = pv.pqzScopedKeyOf(ua, address(0));
        assertEq(v, 1);
        assertEq(abi.encode(pv.pqzOpenKemAt(ua, address(0), 1)), abi.encode(x1.kem));
        assertTrue(keccak256(abi.encode(x0.kem)) != keccak256(abi.encode(x1.kem)), "the opening key rotates");
        assertEq(pv.pqzScopedCount(address(0)), 1, "once per UA");
    }

    /// `current` never goes down: version 0's proof stored after version 1 became current leaves it at 1 (KV-3 per scope).
    function test_current_neverDown() public {
        bytes32 ua = _single(pv, ml1);
        R memory x0 = _rec(ua, address(0), 0, _pk(0), true);
        R memory x1 = _rec(ua, address(0), 1, _pk(1), true);
        _set(pv, ml1, x0);
        _set(pv, ml1, x1);
        pv.storePqzScopedPop(ua, address(0), 1, x1.proof);
        pv.storePqzScopedPop(ua, address(0), 0, x0.proof);
        (uint64 v,,,) = pv.pqzScopedKeyOf(ua, address(0));
        assertEq(v, 1);
        (,, bool p0) = pv.pqzScopedKeyAt(ua, address(0), 0);
        assertTrue(p0, "version 0 proven all the same");
    }

    // ----- class 2: negatives -----

    function test_class2_withoutOpenKem_refused() public {
        bytes32 ua = _single(pv, ml1);
        _setReverts(pv, ml1, _rec(ua, address(0), 0, _pk(0), false), _openErr(address(0)));
    }

    function test_class2_openKemWrongLength_refused() public {
        bytes32 ua = _single(pv, ml1);
        R memory x = _rec(ua, address(0), 0, _pk(0), true);
        x.kem.mlkemEk = _bytes(0xbad, 1567);
        _setReverts(pv, ml1, x, abi.encodeWithSelector(IUARegistry.UAKemKeyLength.selector, uint256(1600)));
    }

    function test_class2_openKemWrongScheme_refused() public {
        bytes32 ua = _single(pv, ml1);
        R memory x = _rec(ua, address(0), 0, _pk(0), true);
        x.kem.scheme = 2;
        _setReverts(pv, ml1, x, abi.encodeWithSelector(IUARegistry.UAKemScheme.selector, uint8(2)));
    }

    /// Ruling 9: no `msig` holds the shared key at first. Control: the same `msig` gets a class-3 record
    /// (`test_class3_msig_withOpenKem_onOpeningToken`).
    function test_class2_msig_refused() public {
        (bytes memory d, bytes32 ua) = _msigHolder(pv);
        R memory x = _rec(ua, address(0), 0, _pk(0), true);
        IUARegistry.UASig memory s = _two(d, ml1, ml2, UAKinds.PURPOSE_PQZ_SCOPED_KEY, _rd(x));
        vm.expectRevert(_err(IUARegistry.UAPqzHolder.selector, ua));
        pv.setPqzScopedKey(ua, address(0), 0, x.key, x.ph, x.kem, FAR, s);
    }

    /// A record signed for another chain is refused (its signature is over another `chainUid`).
    function test_otherChainUid_refused() public {
        bytes32 ua = _single(pv, ml1);
        R memory x = _rec(ua, address(0), 0, _pk(0), true);
        x.chainUid = keccak256("another chain");
        _setReverts(pv, ml1, x, _err(IUARegistry.UAUnauthorized.selector, ua));
    }

    /// `validUntilBlock`: at the block accepted (control), one block later refused.
    function test_validUntilBlock() public {
        bytes32 ua = _single(pv, ml1);
        R memory x = _rec(ua, address(0), 0, _pk(0), true);
        x.until = uint64(block.number);
        IUARegistry.UASig memory s = _one(ml1, x);
        vm.roll(block.number + 1);
        vm.expectRevert(_err(IUARegistry.UAPqzRecordExpired.selector, ua));
        pv.setPqzScopedKey(ua, address(0), 0, x.key, x.ph, x.kem, x.until, s);
        vm.roll(x.until);
        pv.setPqzScopedKey(ua, address(0), 0, x.key, x.ph, x.kem, x.until, s);
    }

    /// Another purpose's signature over the same digest is refused (`pqz-key` is not `pqz-scoped-key`).
    function test_otherPurpose_refused() public {
        bytes32 ua = _single(pv, ml1);
        R memory x = _rec(ua, address(0), 0, _pk(0), true);
        IUARegistry.UASig memory s;
        s.signature = _sig(ml1, UAKinds.uaMessage(ML, UAKinds.PURPOSE_PQZ_KEY, _rd(x)));
        vm.expectRevert(_err(IUARegistry.UAUnauthorized.selector, ua));
        pv.setPqzScopedKey(ua, address(0), 0, x.key, x.ph, x.kem, FAR, s);
    }

    function test_unregistered_refused() public {
        bytes32 ua = UAKinds.uaOf(ML, ml1);
        _setReverts(pv, ml1, _rec(ua, address(0), 0, _pk(0), true), _err(IUARegistry.UAUnauthorized.selector, ua));
    }

    function test_version_rules() public {
        bytes32 ua = _single(pv, ml1);
        bytes memory e1 = abi.encodeWithSelector(IUARegistry.UAPqzKeyVersion.selector, ua, uint64(1));
        _setReverts(pv, ml1, _rec(ua, address(0), 1, _pk(1), true), e1); // no version 0
        _set(pv, ml1, _rec(ua, address(0), 0, _pk(0), true));
        _setReverts(pv, ml1, _rec(ua, address(0), 0, _pk(2), true),
            abi.encodeWithSelector(IUARegistry.UAPqzKeyVersion.selector, ua, uint64(0))); // version 0 again
        _setReverts(pv, ml1, _rec(ua, address(0), 2, _pk(2), true),
            abi.encodeWithSelector(IUARegistry.UAPqzKeyVersion.selector, ua, uint64(2))); // a gap
        _set(pv, ml1, _rec(ua, address(0), 1, _pk(1), true)); // control
    }

    /// Review S-5: every version of a scope has version 0's key length. Control: `test_class2_rotation`.
    function test_v1_otherLength_refused() public {
        bytes32 ua = _single(pv, ml1);
        _set(pv, ml1, _rec(ua, address(0), 0, _pk(0), true));
        _setReverts(pv, ml1, _rec(ua, address(0), 1, _pkOther(1), true),
            abi.encodeWithSelector(UAKinds.UAKeyData.selector, UAKinds.PQZ_MLWE));
    }

    function test_popHash_zero_refused() public {
        bytes32 ua = _single(pv, ml1);
        R memory x = _rec(ua, address(0), 0, _pk(0), true);
        x.ph = 0;
        _setReverts(pv, ml1, x, _err(IUARegistry.UAPqzPopHash.selector, ua));
        x.ph = keccak256("");
        _setReverts(pv, ml1, x, _err(IUARegistry.UAPqzPopHash.selector, ua));
    }

    /// `storePqzScopedPop`: empty bytes, bytes of another hash, no record: `UAPqzPopHash`.
    function test_pop_hash_rules() public {
        bytes32 ua = _single(pv, ml1);
        R memory x = _rec(ua, address(0), 0, _pk(0), true);
        vm.expectRevert(_err(IUARegistry.UAPqzPopHash.selector, ua));
        pv.storePqzScopedPop(ua, address(0), 0, x.proof); // no record yet
        _set(pv, ml1, x);
        vm.expectRevert(_err(IUARegistry.UAPqzPopHash.selector, ua));
        pv.storePqzScopedPop(ua, address(0), 0, "");
        vm.expectRevert(_err(IUARegistry.UAPqzPopHash.selector, ua));
        pv.storePqzScopedPop(ua, address(0), 0, abi.encodePacked(x.proof, uint8(0)));
        pv.storePqzScopedPop(ua, address(0), 0, x.proof); // control
    }

    // ----- the R_REG message binds class, chain, token and version -----

    /// A proof made for another scope, version, chain or as a class-1 version proof hashes to its own `pqzPopHash`; signed
    /// into the record it fails the verifier: `UAPoP`. Control: `test_class2_stored_then_proven`.
    function test_proofOfAnotherScope_fails() public {
        bytes32 ua = _single(pv, ml1);
        R memory x = _rec(ua, address(0), 0, _pk(0), true);
        R memory other = _rec(ua, address(tOn), 0, _pk(0), true);
        _proofSwap(x, other.proof);
    }

    function test_proofOfAnotherVersion_fails() public {
        bytes32 ua = _single(pv, ml1);
        R memory x = _rec(ua, address(0), 0, _pk(0), true);
        R memory other = _rec(ua, address(0), 1, _pk(0), true);
        _proofSwap(x, other.proof);
    }

    function test_proofOfAnotherChain_fails() public {
        bytes32 ua = _single(pv, ml1);
        R memory x = _rec(ua, address(0), 0, _pk(0), true);
        R memory other = _rec(ua, address(0), 0, _pk(0), true);
        other.chainUid = keccak256("another chain");
        _proofSwap(x, _sig(other.key, _proofMsg(other)));
    }

    function test_class1ProofForScoped_fails() public {
        bytes32 ua = _single(pv, ml1);
        R memory x = _rec(ua, address(0), 0, _pk(0), true);
        bytes32 m = UAKinds.uaMessage(UAKinds.PQZ_MLWE, UAKinds.PURPOSE_PQZ_KEY, UAKinds.pqzKeyDigest(ua, x.h));
        _proofSwap(x, _sig(x.key, m));
    }

    function _proofSwap(R memory x, bytes memory proof) internal {
        (x.proof, x.ph) = (proof, keccak256(proof));
        _set(pv, ml1, x);
        vm.expectRevert(IUARegistry.UAPoP.selector);
        pv.storePqzScopedPop(x.ua, x.scope, x.version, proof);
    }

    // ----- class 3 (scope = a token) -----

    /// Positive control: an opening-on token's record carries the opening KEM key; an opening-off token's does not.
    function test_class3_openingOn_withOpenKem() public {
        bytes32 ua = _single(pv, ml1);
        R memory x = _rec(ua, address(tOn), 0, _pk(0), true);
        _set(pv, ml1, x);
        pv.storePqzScopedPop(ua, address(tOn), 0, x.proof);
        (uint64 v, address p,, bool pr) = pv.pqzScopedKeyOf(ua, address(tOn));
        assertEq(abi.encode(v, SSTORE2.read(p), pr), abi.encode(uint64(0), x.key, true));
        assertEq(abi.encode(pv.pqzOpenKemAt(ua, address(tOn), 0)), abi.encode(x.kem));
        assertEq(pv.pqzScopedAt(address(tOn), 0), ua);
    }

    function test_class3_openingOff_noOpenKem() public {
        bytes32 ua = _single(pv, ml1);
        R memory x = _rec(ua, address(tOff), 0, _pk(0), false);
        _set(pv, ml1, x);
        IUARegistry.KemKey memory none;
        assertEq(abi.encode(pv.pqzOpenKemAt(ua, address(tOff), 0)), abi.encode(none));
    }

    function test_class3_openingOff_withOpenKem_refused() public {
        bytes32 ua = _single(pv, ml1);
        _setReverts(pv, ml1, _rec(ua, address(tOff), 0, _pk(0), true), _openErr(address(tOff)));
    }

    function test_class3_openingOn_withoutOpenKem_refused() public {
        bytes32 ua = _single(pv, ml1);
        _setReverts(pv, ml1, _rec(ua, address(tOn), 0, _pk(0), false), _openErr(address(tOn)));
    }

    /// A scope that does not answer `pqzVerifyConfig()` (no code, another contract, a short tuple, a non-bool word): refused,
    /// with or without the opening KEM key.
    function test_class3_scopeNotAnswering_refused() public {
        bytes32 ua = _single(pv, ml1);
        _setReverts(pv, ml1, _rec(ua, address(0xC0DE), 0, _pk(0), false), _openErr(address(0xC0DE)));
        _setReverts(pv, ml1, _rec(ua, address(mock), 0, _pk(0), false), _openErr(address(mock)));
        MockScopeToken t = new MockScopeToken(0);
        t.setShape(0, 12);
        _setReverts(pv, ml1, _rec(ua, address(t), 0, _pk(0), false), _openErr(address(t)));
        t.setShape(2, 13);
        _setReverts(pv, ml1, _rec(ua, address(t), 0, _pk(0), true), _openErr(address(t)));
        _setReverts(pv, ml1, _rec(ua, address(t), 0, _pk(0), false), _openErr(address(t)));
        t.setShape(0, 13);
        _set(pv, ml1, _rec(ua, address(t), 0, _pk(0), false)); // control
    }

    /// Fable P3-1: a class-3 record names a token that reads one: `pqzOwnKey` (word 11) 0 (a class-2 or `PRECOMPILE` token) is
    /// refused, with its control; a scope answering a 4,000-word tuple is read up to word 12 (accepted; the registry copies no more).
    function test_class3_scopeMustOwnItsKey_longAnswerRead() public {
        bytes32 ua = _single(pv, ml1);
        MockScopeToken t = new MockScopeToken(1);
        t.setOwn(0);
        _setReverts(pv, ml1, _rec(ua, address(t), 0, _pk(0), true), _openErr(address(t)));
        t.setOwn(1);
        _set(pv, ml1, _rec(ua, address(t), 0, _pk(0), true)); // control
        MockScopeToken big = new MockScopeToken(1);
        big.setShape(1, 4_000);
        _set(pv, ml1, _rec(ua, address(big), 0, _pk(1), true));
    }

    /// An `msig` on an opening-on token: with the opening KEM key accepted, without it refused; the same `msig` is credited
    /// on class 1 too (its class-1 record is untouched by the scoped one).
    function test_class3_msig_withOpenKem_onOpeningToken() public {
        (bytes memory d, bytes32 ua) = _msigHolder(pv);
        R memory bad = _rec(ua, address(tOn), 0, _pk(0), false);
        IUARegistry.UASig memory s = _two(d, ml1, ml2, UAKinds.PURPOSE_PQZ_SCOPED_KEY, _rd(bad));
        vm.expectRevert(_openErr(address(tOn)));
        pv.setPqzScopedKey(ua, address(tOn), 0, bad.key, bad.ph, bad.kem, FAR, s);
        R memory x = _rec(ua, address(tOn), 0, _pk(0), true);
        _msigSet(pv, d, x);
        pv.storePqzScopedPop(ua, address(tOn), 0, x.proof);
        (,,, bool pr) = pv.pqzScopedKeyOf(ua, address(tOn));
        assertTrue(pr);
        R memory off = _rec(ua, address(tOff), 0, _pk(1), false);
        _msigSet(pv, d, off); // and an opening-off token's, without
    }

    /// A class-3 record of token A is not token B's.
    function test_class3_recordIsPerToken() public {
        bytes32 ua = _single(pv, ml1);
        R memory x = _rec(ua, address(tOn), 0, _pk(0), true);
        _set(pv, ml1, x);
        pv.storePqzScopedPop(ua, address(tOn), 0, x.proof);
        MockScopeToken b = new MockScopeToken(1);
        (uint64 v, address p,,) = pv.pqzScopedKeyOf(ua, address(b));
        assertEq(abi.encode(v, p), abi.encode(uint64(0), address(0)));
        (, p,,) = pv.pqzScopedKeyOf(ua, address(0));
        assertEq(p, address(0), "nor class 2's");
    }

    // ----- never the registry key: one marker and one owner across the three record spaces -----

    /// Class-1 key bytes refused as a class-2 key of the same UA; control: another key.
    function test_class1Key_asClass2_refused() public {
        bytes32 ua = _singleClass1(pv, ml1, _pk(0));
        R memory x = _rec(ua, address(0), 0, _pk(0), true);
        _setReverts(pv, ml1, x, abi.encodeWithSelector(IUARegistry.UAKeyInUse.selector, x.h, ua));
        _set(pv, ml1, _rec(ua, address(0), 0, _pk(1), true));
    }

    /// Class-2 key bytes refused as a class-1 version of the same UA (`setPqzKey` reads the same marker).
    function test_class2Key_asClass1_refused() public {
        bytes32 ua = _singleClass1(pv, ml1, _pk(0));
        R memory x = _rec(ua, address(0), 0, _pk(1), true);
        _set(pv, ml1, x);
        bytes32 rd = UAKinds.pqzKeyVersionRecordDigest(ua, 1, x.h, bytes32(uint256(1)));
        IUARegistry.UASig memory s;
        s.signature = _sig(ml1, UAKinds.uaMessage(ML, UAKinds.PURPOSE_PQZ_KEY, rd));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyInUse.selector, x.h, ua));
        pv.setPqzKey(ua, 1, x.key, bytes32(uint256(1)), s);
    }

    /// The same key bytes for two tokens of one UA: refused; control: another key.
    function test_twoTokens_sameKey_refused() public {
        bytes32 ua = _single(pv, ml1);
        _set(pv, ml1, _rec(ua, address(tOn), 0, _pk(0), true));
        R memory x = _rec(ua, address(tOff), 0, _pk(0), false);
        _setReverts(pv, ml1, x, abi.encodeWithSelector(IUARegistry.UAKeyInUse.selector, x.h, ua));
        _set(pv, ml1, _rec(ua, address(tOff), 0, _pk(1), false));
    }

    /// Across UAs: a key proven as UA1's class-1 key cannot be proven as UA2's scoped key, nor a scoped one as another
    /// UA's scoped key. Control: UA2's own key proves.
    function test_crossUa_provenKey_refused() public {
        bytes32 u1 = _singleClass1(pv, ml1, _pk(0));
        bytes32 u2 = _single(pv, ml2);
        R memory x = _rec(u2, address(0), 0, _pk(0), true);
        x.proof = _sig(x.key, _proofMsg(x));
        _set(pv, ml2, x);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyInUse.selector, x.h, u1));
        pv.storePqzScopedPop(u2, address(0), 0, x.proof);

        R memory y = _rec(u2, address(tOn), 0, _pk(5), true);
        _set(pv, ml2, y);
        pv.storePqzScopedPop(u2, address(tOn), 0, y.proof); // control
        bytes32 u3 = _single(pv, ml3);
        R memory z = _rec(u3, address(tOn), 0, _pk(5), true);
        _set(pv, ml3, z);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyInUse.selector, z.h, u2));
        pv.storePqzScopedPop(u3, address(tOn), 0, z.proof);
    }

    // ----- versions per scope -----

    /// Each record space has its own sequence: class 1 at version 0, class 2 at 1, a class-3 token at 0, so a read of the
    /// wrong space cannot pass by accident.
    function test_versionsPerScope() public {
        bytes32 ua = _singleClass1(pv, ml1, _pk(0));
        R memory a0 = _rec(ua, address(0), 0, _pk(1), true);
        R memory a1 = _rec(ua, address(0), 1, _pk(2), true);
        R memory t0 = _rec(ua, address(tOn), 0, _pk(3), true);
        _set(pv, ml1, a0);
        _set(pv, ml1, a1);
        _set(pv, ml1, t0);
        pv.storePqzScopedPop(ua, address(0), 1, a1.proof);
        pv.storePqzScopedPop(ua, address(tOn), 0, t0.proof);
        (uint64 v1, address p1,,) = pv.pqzKeyOf(ua);
        (uint64 v2, address p2,,) = pv.pqzScopedKeyOf(ua, address(0));
        (uint64 v3, address p3,,) = pv.pqzScopedKeyOf(ua, address(tOn));
        assertEq(abi.encode(v1, v2, v3), abi.encode(uint64(0), uint64(1), uint64(0)));
        assertEq(SSTORE2.read(p1), _pk(0));
        assertEq(SSTORE2.read(p2), _pk(2));
        assertEq(SSTORE2.read(p3), _pk(3));
        assertEq(pv.pqzKeyLatest(ua), 0);
        assertEq(pv.pqzScopedKeyLatest(ua, address(0)), 1);
        assertEq(pv.pqzScopedKeyLatest(ua, address(tOn)), 0);
    }

    // ----- Codex U4h-1 (owner 2026-11-15, CTR-PQZ-30's Change): another set's scoped proof with the verifier enabled -----

    /// A registry whose 0x0142 verifier checks this set only (`SetVerifierStandIn`, the real verifier's length rule).
    function _setReg() internal returns (UARegistry r) {
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](2);
        c[0] = UARegistry.KindConfig(ML, address(mock), 400_000);
        c[1] = UARegistry.KindConfig(UAKinds.PQZ_MLWE, address(new SetVerifierStandIn()), 1_000_000);
        r = _deploy(address(0x5ca0000000000000000000000000000000000043), chainUidA, address(0), false, BUDGET, address(0), true, c);
    }

    /// The test's own message check (`_sig` is the base mock's `keccak256(abi.encode(key, message))`).
    function _verifierRule(R memory x) internal pure returns (bool) {
        return keccak256(x.proof) == keccak256(_sig(x.key, _proofMsg(x)));
    }

    /// U4h-1: with the verifier enabled, a class-3 key of another set registers and rotates: each proof stored UNPROVEN
    /// (`CHECKED_NONE`, `proven` false, no `keyOwner`), the version current (the token's set), listed once. Before the fix the
    /// verifier's refusal made `storePqzScopedPop` revert `UAPoP`.
    function test_u4h1_otherSet_withVerifier_storedUnproven() public {
        UARegistry r = _setReg();
        bytes32 ua = _single(r, ml1);
        for (uint64 v; v < 2; ++v) {
            R memory x = _rec(ua, address(tOn), v, _pkOther(v), true);
            assertTrue(_verifierRule(x), "a valid proof of its own set");
            _set(r, ml1, x);
            vm.expectEmit(address(r));
            emit IUARegistry.UAPqzScopedPopStored(ua, address(tOn), v, UAKinds.CHECKED_NONE, x.proof);
            r.storePqzScopedPop(ua, address(tOn), v, x.proof);
            (uint64 cur,,, bool pr) = r.pqzScopedKeyOf(ua, address(tOn));
            assertEq(cur, v, "current: the token's set");
            assertFalse(pr, "stored unproven: never taken as checked on chain");
            (,, bool prAt) = r.pqzScopedKeyAt(ua, address(tOn), v);
            assertFalse(prAt);
            assertEq(r.pqzScopedPopOf(ua, address(tOn), v), x.proof, "the bytes kept for the off-chain check");
            assertEq(r.keyOwner(x.h), bytes32(0), "no owner without an on-chain check");
        }
        assertEq(r.pqzScopedCount(address(tOn)), 1, "listed once");
    }

    /// U4h-1 control: the same set still verifies on chain with the verifier enabled (`CHECKED_CHAIN`, proven, `keyOwner`).
    function test_u4h1_sameSet_withVerifier_provenOnChain() public {
        UARegistry r = _setReg();
        bytes32 ua = _single(r, ml1);
        R memory x = _rec(ua, address(tOn), 0, _pk(0), true);
        _set(r, ml1, x);
        vm.expectEmit(address(r));
        emit IUARegistry.UAPqzScopedPopStored(ua, address(tOn), 0, UAKinds.CHECKED_CHAIN, x.proof);
        r.storePqzScopedPop(ua, address(tOn), 0, x.proof);
        (,,, bool pr) = r.pqzScopedKeyOf(ua, address(tOn));
        assertTrue(pr);
        assertEq(r.keyOwner(x.h), ua);
    }

    /// U4h-1 control: a wrong proof of the same set still refuses (`UAPoP`): the record's hash is of a proof over another message.
    function test_u4h1_sameSet_wrongProof_refused() public {
        UARegistry r = _setReg();
        bytes32 ua = _single(r, ml1);
        R memory x = _rec(ua, address(tOn), 0, _pk(0), true);
        x.proof = _sig(x.key, keccak256("another message"));
        x.ph = keccak256(x.proof);
        _set(r, ml1, x);
        vm.expectRevert(IUARegistry.UAPoP.selector);
        r.storePqzScopedPop(ua, address(tOn), 0, x.proof);
    }

    /// U4h-1: scope 0 (class 2) keeps the class-1 rule with the verifier enabled: another set's proof stored unproven, the key
    /// not listed (control of `_scopedCurrent`'s set-length rule).
    function test_u4h1_otherSet_scope0_storedUnproven_notListed() public {
        UARegistry r = _setReg();
        bytes32 ua = _single(r, ml1);
        R memory x = _rec(ua, address(0), 0, _pkOther(7), true);
        _set(r, ml1, x);
        vm.expectEmit(address(r));
        emit IUARegistry.UAPqzScopedPopStored(ua, address(0), 0, UAKinds.CHECKED_NONE, x.proof);
        r.storePqzScopedPop(ua, address(0), 0, x.proof);
        assertEq(r.pqzScopedCount(address(0)), 0);
    }

    // ----- Codex U4h-2 (owner 2026-11-15): a successor's scoped holder list shows the predecessor's holders -----

    /// A holder registered on gen 1 (`pv`, slot 0x0142 with the verifier) with a proven scope-0 key; gen 2 in front of it without
    /// 0x0142: its scoped key read forwards (as before), and so does its holder list now (count, entry, the index past the end).
    function test_u4h2_successorListsInheritedHolders() public {
        bytes32 ua = _single(pv, ml1);
        R memory x = _rec(ua, address(0), 0, _pk(0), true);
        _set(pv, ml1, x);
        pv.storePqzScopedPop(ua, address(0), 0, x.proof);
        UARegistry g2 = _deploy(address(0x5Ca0000000000000000000000000000000000044), chainUidA, address(pv), false, BUDGET,
            address(0), true, new UARegistry.KindConfig[](0));
        (uint64 v, address ptr,, bool pr) = g2.pqzScopedKeyOf(ua, address(0));
        assertEq(abi.encode(v, SSTORE2.read(ptr), pr), abi.encode(uint64(0), x.key, true), "the key read forwards (control)");
        assertEq(pv.pqzScopedCount(address(0)), 1);
        assertEq(g2.pqzScopedCount(address(0)), 1, "the inherited holder is listed");
        assertEq(g2.pqzScopedAt(address(0), 0), ua);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAIndex.selector, UAKinds.PQZ_MLWE, uint256(1)));
        g2.pqzScopedAt(address(0), 1);
        assertEq(g2.pqzScopedCount(address(tOn)), 0, "another scope: none");
    }
}
