// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UARegistryAuxLib} from "../../src/ua/UARegistryAuxLib.sol";
import {UARegistryCoreLib} from "../../src/ua/UARegistryCoreLib.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {PqzCore} from "../../src/pqz/PqzCore.sol";
import {UACall} from "./UACall.sol";
import {UARegistryBase} from "./UARegistryBase.sol";

/// The frame gas of one `requireAuthorized` from a contract, every account and slot cold (one transaction).
contract HotProbe {
    function cost(UARegistry r, bytes32 ua, bytes32 purpose, bytes32 digest, IUARegistry.UASig calldata s) external view returns (uint256 g) {
        g = gasleft();
        r.requireAuthorized(ua, purpose, digest, s);
        g -= gasleft();
    }
}

/// CTR-UA-44 (TODO 3ze, owner 2026-11-14: "Không, tắt member cũ, thành viên mới cho phép thêm vào. ua chỉ tính fix 1 lần khi
/// đăng ký."; "Và vì đi theo chain, thế nên version tiếp theo sẽ là version+1 => không cần nhảy."): `updateMsig` disables old
/// slots, appends new ones, changes weights and the threshold, one registry at a time; the id stays the first structure's. Each
/// refusal runs next to a passing twin that differs in that one thing. Members: EOAs (native, ECDSA), `mldsa65` keys and one
/// `p256` key under the stand-in verifier (`_sig`).
contract UARegistryMsigUpdateTest is UARegistryBase {
    uint16 internal constant ML = 0x0131;
    uint16 internal constant P256 = 0x0101;
    uint16 internal constant EOA = UAKinds.EVM_EOA;
    uint256 internal constant PA = 0xA11CE;
    uint256 internal constant PB = 0xB0B;
    uint256 internal constant PC = 0xC0C;
    uint256 internal constant PD = 0xD0D;
    uint256 internal constant PE = 0xE0E;
    address internal constant REG_M = 0x5cA0000000000000000000000000000000000002;
    address internal constant REG_G2 = 0x5CA0000000000000000000000000000000000004;
    address internal constant REG_X = 0x5cA0000000000000000000000000000000000005;
    bytes32 internal constant TX = keccak256("a metatx digest");
    bytes32 internal constant CHAT = keccak256("a pqchat record");

    UARegistry internal r;
    bytes32 internal a;
    bytes32 internal b;
    bytes32 internal c;
    bytes32 internal d;
    bytes32 internal e;
    bytes32[7] internal ml; // ml[1] … ml[6]: registered `mldsa65` ids
    bytes32 internal p1;

    mapping(bytes32 => uint256) internal pkOf;
    mapping(bytes32 => bytes) internal keyOfId;
    mapping(bytes32 => uint16) internal kindOfId;
    mapping(bytes32 => bytes32[]) internal innerSigners; // an `msig` member: which of its slots sign for it
    UARegistry internal dom; // ≠ 0: the registry whose `UAAuth` domain native leaves sign in (a gen-1 record read through gen 2)

    struct Up {
        bytes32 ua;
        uint64 version;
        IUARegistry.MsigStructure st;
        uint256 enabled;
        uint64 until;
    }

    function setUp() public override {
        super.setUp();
        r = _deploy(REG_M, chainUidA, address(0), false, BUDGET, address(0), true, _cfgsMl(400_000));
        (a, b, c, d, e) = (_eoaId(PA), _eoaId(PB), _eoaId(PC), _eoaId(PD), _eoaId(PE));
        for (uint256 i = 1; i <= 6; ++i) {
            bytes memory k = _mlKey(i);
            ml[i] = UAKinds.uaOf(ML, k);
            (kindOfId[ml[i]], keyOfId[ml[i]]) = (ML, k);
        }
        p1 = UAKinds.uaOf(P256, _key(P256));
        (kindOfId[p1], keyOfId[p1]) = (P256, _key(P256));
        _members(r);
    }

    // ----- fixtures -----

    function _eoaId(uint256 pk) internal returns (bytes32 id) {
        id = _pad(vm.addr(pk));
        (kindOfId[id], pkOf[id]) = (EOA, pk);
    }

    function _cfgsMl(uint64 mlCap) internal view returns (UARegistry.KindConfig[] memory cfg) {
        UARegistry.KindConfig[] memory base = _cfgs(address(mock));
        cfg = new UARegistry.KindConfig[](base.length + 1);
        for (uint256 i; i < base.length; ++i) cfg[i] = base[i];
        cfg[base.length] = UARegistry.KindConfig(ML, address(mock), mlCap);
    }

    function _mlKey(uint256 salt) internal pure returns (bytes memory pk) {
        pk = new bytes(1952);
        for (uint256 i; i < pk.length; i += 32) {
            bytes32 w = keccak256(abi.encode(salt, i));
            for (uint256 j; j < 32 && i + j < pk.length; ++j) pk[i + j] = w[j];
        }
    }

    function _members(UARegistry x) internal {
        for (uint256 i = 1; i <= 6; ++i) _register(x, ML, keyOfId[ml[i]]);
        _register(x, P256, _key(P256));
    }

    function _ids(bytes32 x) internal pure returns (bytes32[] memory l) {
        l = new bytes32[](1);
        l[0] = x;
    }

    function _ids(bytes32 x, bytes32 y) internal pure returns (bytes32[] memory l) {
        l = new bytes32[](2);
        (l[0], l[1]) = (x, y);
    }

    function _ids(bytes32 x, bytes32 y, bytes32 z) internal pure returns (bytes32[] memory l) {
        l = new bytes32[](3);
        (l[0], l[1], l[2]) = (x, y, z);
    }

    function _idx(IUARegistry.MsigStructure memory st, bytes32 id) internal pure returns (uint16) {
        for (uint256 i; i < st.members.length; ++i) if (st.members[i].id == id) return uint16(i);
        revert("no such slot");
    }

    /// One leaf's signature over `md` (derived: under `member`; native: `typed` itself on a portable record, its `UAAuth` over `md`
    /// on a transaction).
    function _leaf(UARegistry x, bytes32 id, bytes32 md, bytes32 typed, bool portable) internal view returns (bytes memory) {
        uint16 k = kindOfId[id];
        if (address(dom) != address(0)) x = dom;
        if (k == EOA) return portable ? _ecdsa(pkOf[id], typed) : _ecdsa(pkOf[id], x.uaAuthDigest(id, UAKinds.PURPOSE_MEMBER, md));
        return _sig(keyOfId[id], UAKinds.uaMessage(k, UAKinds.PURPOSE_MEMBER, md));
    }

    /// The `MemberSig[]` of `ids` in the structure `st` of `ua` over `(purpose, digest)`, in index order; an `msig` member signs by
    /// its `innerSigners` over its own current structure.
    function _sigs(UARegistry x, IUARegistry.MsigStructure memory st, bytes32 ua, bytes32[] memory ids, bytes32 purpose,
        bytes32 digest, bool portable) internal view returns (IUARegistry.MemberSig[] memory s)
    {
        bytes32 md = _memberDigest(ua, purpose, digest);
        s = new IUARegistry.MemberSig[](ids.length);
        for (uint256 i; i < ids.length; ++i) {
            bytes32 id = ids[i];
            if (kindOfId[id] == UAKinds.MSIG) {
                s[i] = IUARegistry.MemberSig(_idx(st, id), _inner(x, id, md, digest, portable), "");
            } else {
                s[i] = IUARegistry.MemberSig(_idx(st, id), new IUARegistry.InnerSig[](0), _leaf(x, id, md, digest, portable));
            }
        }
        for (uint256 i = 1; i < s.length; ++i) {
            for (uint256 j = i; j > 0 && s[j - 1].index > s[j].index; --j) (s[j - 1], s[j]) = (s[j], s[j - 1]);
        }
    }

    function _inner(UARegistry x, bytes32 iu, bytes32 md, bytes32 typed, bool portable)
        internal
        view
        returns (IUARegistry.InnerSig[] memory l)
    {
        bytes32 mdi = UAKinds.memberDigest(iu, UAKinds.uaMessage(UAKinds.MSIG, UAKinds.PURPOSE_MEMBER, md));
        IUARegistry.MsigStructure memory st = x.msigOf(iu);
        bytes32[] memory who = innerSigners[iu];
        l = new IUARegistry.InnerSig[](who.length);
        for (uint256 i; i < who.length; ++i) l[i] = IUARegistry.InnerSig(_idx(st, who[i]), _leaf(x, who[i], mdi, typed, portable));
        for (uint256 i = 1; i < l.length; ++i) {
            for (uint256 j = i; j > 0 && l[j - 1].index > l[j].index; --j) (l[j - 1], l[j]) = (l[j], l[j - 1]);
        }
    }

    function _auth(IUARegistry.MemberSig[] memory s) internal pure returns (IUARegistry.UASig memory u) {
        u.members = s;
    }

    /// Registers `threshold`-of-`ids` (weights `w`) on `x`, its `pop` by `popIds` (empty: none), then every other slot accepts.
    function _reg(UARegistry x, uint16 threshold, bytes32[] memory ids, uint16[] memory w, bytes32[] memory popIds)
        internal
        returns (bytes32 ua)
    {
        Member[] memory m = new Member[](ids.length);
        for (uint256 i; i < ids.length; ++i) m[i] = Member(kindOfId[ids[i]], ids[i], w[i]);
        bytes memory key = _msigKey(threshold, m);
        ua = UAKinds.uaOf(UAKinds.MSIG, key);
        IUARegistry.MsigStructure memory st = UACall.structure(key);
        bytes memory pop = popIds.length == 0
            ? bytes("")
            : abi.encode(_sigs(x, st, ua, popIds, UAKinds.PURPOSE_POP_V2, _regDigest(ua, UAKinds.MSIG), true));
        UACall.register(x, UAKinds.MSIG, key, _none(), pop, "");
        for (uint256 i; i < ids.length; ++i) if (!x.memberAccepted(ua, _idx(st, ids[i]))) _accept(x, ua, ids[i]);
        kindOfId[ua] = UAKinds.MSIG;
    }

    function _w(uint256 n) internal pure returns (uint16[] memory w) {
        w = new uint16[](n);
        for (uint256 i; i < n; ++i) w[i] = 1;
    }

    function _accept(UARegistry x, bytes32 ua, bytes32 id) internal {
        bytes32 typed = UAKinds.membershipDigest(ua, id);
        x.acceptMembership(ua, _sigs(x, x.msigOf(ua), ua, _ids(id), UAKinds.PURPOSE_MEMBERSHIP, typed, true)[0]);
    }

    /// 2-of-{a, b, c} EOAs, weight 1, every slot accepted.
    function _eoa3(UARegistry x) internal returns (bytes32) {
        return _reg(x, 2, _ids(a, b, c), _w(3), new bytes32[](0));
    }

    /// 2-of-{ml1, ml2, ml3}: PQ-eligible, `pop` by ml1 + ml2, ml3 accepted.
    function _pq3(UARegistry x) internal returns (bytes32) {
        return _reg(x, 2, _ids(ml[1], ml[2], ml[3]), _w(3), _ids(ml[1], ml[2]));
    }

    // ----- the update -----

    function _next(UARegistry x, bytes32 ua) internal view returns (Up memory u) {
        (uint64 v, uint256 en,) = x.msigStateOf(ua);
        u = Up(ua, v + 1, x.msigOf(ua), en, uint64(block.number + 100));
    }

    function _typed(Up memory u, bytes32 cu, address registry) internal pure returns (bytes32) {
        return UAKinds.msigUpdateDigest(u.ua, cu, registry, u.version, u.st, u.enabled, u.until);
    }

    /// `ids` of the **stored** structure on `x` sign `u` for `(cu, registry)`.
    function _upSigs(UARegistry x, Up memory u, bytes32[] memory ids, bytes32 cu, address registry)
        internal
        view
        returns (IUARegistry.MemberSig[] memory)
    {
        return _sigs(x, x.msigOf(u.ua), u.ua, ids, UAKinds.PURPOSE_MSIG_UPDATE, _typed(u, cu, registry), true);
    }

    function _apply(UARegistry x, Up memory u, bytes32[] memory ids) internal {
        IUARegistry.MemberSig[] memory s = _upSigs(x, u, ids, x.chainUid(), address(x));
        x.updateMsig(u.ua, u.version, u.st, u.enabled, u.until, s, x.chainUid());
    }

    function _refused(UARegistry x, Up memory u, bytes32[] memory ids, bytes memory err) internal {
        bytes32 cu = x.chainUid();
        IUARegistry.MemberSig[] memory s = _upSigs(x, u, ids, cu, address(x));
        vm.expectRevert(err); // `chainUid()` read before: the next call is the update
        x.updateMsig(u.ua, u.version, u.st, u.enabled, u.until, s, cu);
    }

    function _append(Up memory u, uint16 kind, bytes32 id, uint16 weight, bool on) internal pure {
        IUARegistry.MsigMember[] memory m = new IUARegistry.MsigMember[](u.st.members.length + 1);
        for (uint256 i; i < u.st.members.length; ++i) m[i] = u.st.members[i];
        m[m.length - 1] = IUARegistry.MsigMember(kind, id, weight);
        u.st.members = m;
        if (on) u.enabled |= 1 << (m.length - 1);
    }

    function _append(Up memory u, bytes32 id, bool on) internal view {
        _append(u, kindOfId[id], id, 1, on);
    }

    function _set(Up memory u, bytes32 id, bool on) internal pure {
        uint256 bit = 1 << _idx(u.st, id);
        u.enabled = on ? u.enabled | bit : u.enabled & ~bit;
    }

    function _err(bytes4 sel, bytes32 ua) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(sel, ua);
    }

    function _keyData0120() internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG);
    }

    function _slots(uint256 n) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IUARegistry.UAMsigSlots.selector, n);
    }

    function _authorizes(UARegistry x, bytes32 ua, bytes32[] memory ids) internal view {
        x.requireAuthorized(ua, UAKinds.PURPOSE_METATX, TX, _auth(_sigs(x, x.msigOf(ua), ua, ids, UAKinds.PURPOSE_METATX, TX, false)));
    }

    function _portable(UARegistry x, bytes32 ua, bytes32[] memory ids) internal view {
        x.requirePortable(ua, UAKinds.PURPOSE_PQCHAT, CHAT, _auth(_sigs(x, x.msigOf(ua), ua, ids, UAKinds.PURPOSE_PQCHAT, CHAT, true)));
    }

    function _authRefused(UARegistry x, bytes32 ua, bytes32[] memory ids) internal {
        IUARegistry.UASig memory s = _auth(_sigs(x, x.msigOf(ua), ua, ids, UAKinds.PURPOSE_METATX, TX, false));
        vm.expectRevert(_err(IUARegistry.UAUnauthorized.selector, ua));
        x.requireAuthorized(ua, UAKinds.PURPOSE_METATX, TX, s);
        s = _auth(_sigs(x, x.msigOf(ua), ua, ids, UAKinds.PURPOSE_PQCHAT, CHAT, true));
        vm.expectRevert(_err(IUARegistry.UAUnauthorized.selector, ua));
        x.requirePortable(ua, UAKinds.PURPOSE_PQCHAT, CHAT, s);
    }

    /// `setPqzKey(ua, version)` by `ids` (a fresh key per `salt`).
    function _pqzKeyCall(UARegistry x, bytes32 ua, uint64 version, bytes32[] memory ids, uint256 salt)
        internal
        view
        returns (bytes memory)
    {
        bytes memory key = new bytes(16_384);
        key[0] = bytes1(uint8(salt));
        key[1] = bytes1(uint8(salt >> 8));
        bytes32 hash = keccak256(abi.encode("proof", salt));
        bytes32 h = UAKinds.keyHashOf(UAKinds.PQZ_MLWE, key);
        bytes32 rd = version == 0
            ? UAKinds.pqzKeyRecordDigest(ua, h, hash)
            : UAKinds.pqzKeyVersionRecordDigest(ua, version, h, hash);
        IUARegistry.UASig memory s = _auth(_sigs(x, x.msigOf(ua), ua, ids, UAKinds.PURPOSE_PQZ_KEY, rd, true));
        return abi.encodeCall(IUARegistry.setPqzKey, (ua, version, key, hash, s));
    }

    function _call(address t, bytes memory data) internal returns (bool ok, bytes memory ret) {
        (ok, ret) = t.call(data);
    }

    function _callRefused(address t, bytes memory data, bytes memory err) internal {
        (bool ok, bytes memory ret) = t.call(data);
        assertFalse(ok, "refused");
        assertEq(ret, err);
    }

    // ----- digests (vectors: ../vectors/ua/portable.json) -----

    /// The typehashes, the purpose and the digest by hand: what `clientkeys` and `ua-rs` hash.
    function test_msigUpdateTypehashesPinned() public pure {
        assertEq(
            UAKinds.UA_MSIG_UPDATE_TYPEHASH,
            keccak256(
                "UAMsigUpdate(bytes32 ua,bytes32 chainUid,address registry,uint64 version,uint16 threshold,UAMsigMember[] members,uint256 enabled,uint64 validUntilBlock)UAMsigMember(uint16 kind,bytes32 id,uint16 weight)"
            )
        );
        assertEq(UAKinds.UA_MSIG_UPDATE_TYPEHASH, 0x4f444098cb5d1c5e604d10d13c9c803ac8429ef9938342ded6997343b9c48ac6);
        assertEq(UAKinds.UA_MSIG_MEMBER_TYPEHASH, 0x49ee2633d577df4283fdcf2546b6c8b72f1e3cddb2449cefdfc6eed31e26a05a);
        assertEq(UAKinds.PURPOSE_MSIG_UPDATE, keccak256("scaas.ua.purpose.msig-update.v1"));
        assertEq(UAKinds.PURPOSE_MSIG_UPDATE, 0x200cc8b48b9348af55b58ea4506db28f5a9b48de75c7d03cebd6e96c302145c6);
        assertEq(IUARegistry.updateMsig.selector, bytes4(0x533f2d73));
        assertEq(IUARegistry.msigStateOf.selector, bytes4(0xdaee052e));
        assertEq(IUARegistry.ChainUidMismatch.selector, bytes4(0x14767f45));

        IUARegistry.MsigStructure memory st;
        st.threshold = 2;
        st.members = new IUARegistry.MsigMember[](2);
        st.members[0] = IUARegistry.MsigMember(EOA, bytes32(uint256(0xa1)), 1);
        st.members[1] = IUARegistry.MsigMember(ML, keccak256("m"), 3);
        (bytes32 ua, bytes32 cu, address reg_) = (keccak256("an msig"), keccak256("a chain"), address(0x5ca));
        bytes32 h0 = keccak256(abi.encode(UAKinds.UA_MSIG_MEMBER_TYPEHASH, EOA, bytes32(uint256(0xa1)), uint16(1)));
        bytes32 h1 = keccak256(abi.encode(UAKinds.UA_MSIG_MEMBER_TYPEHASH, ML, keccak256("m"), uint16(3)));
        bytes32 sh = keccak256(abi.encode(UAKinds.UA_MSIG_UPDATE_TYPEHASH, ua, cu, reg_, uint64(7), uint16(2),
            keccak256(abi.encodePacked(h0, h1)), uint256(3), uint64(99)));
        assertEq(UAKinds.msigUpdateDigest(ua, cu, reg_, 7, st, 3, 99),
            keccak256(abi.encodePacked(hex"1901", UAKinds.PORTABLE_DOMAIN_SEPARATOR, sh)));
    }

    // ----- positive controls -----

    /// 2-of-3 → disable c, append d, threshold 2: the view of the current structure, the words, the event; the id, the
    /// registration, `pop`, `keyOf` keep the first structure; d accepts its new slot; the new quorum authorizes on both paths, the
    /// old one (with the disabled c) on none.
    function test_updateDisableAppend() public {
        bytes32 ua = _eoa3(r);
        (, bytes memory key0,, bytes memory pop0,) = r.registrationOf(ua);
        Up memory u = _next(r, ua);
        _set(u, c, false);
        _append(u, d, true);
        IUARegistry.MemberSig[] memory s = _upSigs(r, u, _ids(a, b), chainUidA, address(r));
        vm.expectEmit(address(r));
        emit IUARegistry.UAMsigUpdated(ua, 1, 2, 4, u.enabled);
        vm.prank(address(0xBEEF)); // anyone submits
        r.updateMsig(ua, 1, u.st, u.enabled, u.until, s, chainUidA);

        IUARegistry.MsigStructure memory now_ = r.msigOf(ua);
        assertEq(abi.encode(now_), abi.encode(u.st), "msigOf: the current structure, every slot");
        (uint64 v, uint256 en, uint256 acc) = r.msigStateOf(ua);
        assertEq(v, 1);
        assertEq(en, u.enabled);
        assertEq(acc, 7, "accepted bits never cleared: c's stays");
        uint16 ic = _idx(now_, c);
        assertFalse(r.memberAccepted(ua, ic), "a disabled slot does not count");
        assertFalse(r.memberAccepted(ua, 3), "an appended slot has not accepted");
        (, bytes memory key1,, bytes memory pop1,) = r.registrationOf(ua);
        assertEq(key1, key0, "registrationOf keeps the first structure");
        assertEq(pop1, pop0);
        assertEq(UAKinds.uaOf(UAKinds.MSIG, key1), ua, "MM-1: the id is the first structure's");
        assertEq(r.keyOf(ua).length, 0, "MM-10: no key");
        (IUARegistry.Record memory rec,) = r.recordOf(ua);
        assertTrue(rec.keyPtr != address(0), "MM-7: the blob pointer");
        for (uint256 i; i < 3; ++i) assertEq(abi.encode(now_.members[i]), abi.encode(UACall.structure(key0).members[i]), "prefix");

        _authRefused(r, ua, _ids(a, d)); // d has not accepted yet
        _accept(r, ua, d);
        assertTrue(r.memberAccepted(ua, 3));
        _authorizes(r, ua, _ids(a, d));
        _portable(r, ua, _ids(a, d));
        _authorizes(r, ua, _ids(a, b));
        _authRefused(r, ua, _ids(b, c)); // the old quorum with the disabled slot: refused on every path
    }

    /// A never-updated `msig`: version 0, every slot enabled, the registration's bytes; nothing else changes.
    function test_neverUpdated() public {
        bytes32 ua = _eoa3(r);
        (uint64 v, uint256 en, uint256 acc) = r.msigStateOf(ua);
        assertEq(v, 0);
        assertEq(en, 7);
        assertEq(acc, 7);
        (IUARegistry.Record memory rec,) = r.recordOf(ua);
        assertEq(rec.keyPtr, address(0));
        for (uint256 i; i < 3; ++i) assertTrue(r.memberAccepted(ua, i));
        assertFalse(r.memberAccepted(ua, 3));
        _authorizes(r, ua, _ids(a, b));
        (v, en, acc) = r.msigStateOf(a);
        assertEq(v + en + acc, 0, "not an msig");
    }

    /// Re-enable: a slot that accepted before counts at once.
    function test_reEnable() public {
        bytes32 ua = _eoa3(r);
        Up memory u = _next(r, ua);
        _set(u, c, false);
        _apply(r, u, _ids(a, b));
        _authRefused(r, ua, _ids(a, c));
        u = _next(r, ua);
        _set(u, c, true);
        _apply(r, u, _ids(a, b));
        _authorizes(r, ua, _ids(a, c));
        (uint64 v,,) = r.msigStateOf(ua);
        assertEq(v, 2);
    }

    /// Weights only, then the threshold only.
    function test_weightThenThreshold() public {
        bytes32 ua = _eoa3(r);
        Up memory u = _next(r, ua);
        // `lo` the lower slot of a and b: it signs first, so after it reaches the threshold the chain path refuses the next slot
        (bytes32 lo, bytes32 hi) = _idx(u.st, a) < _idx(u.st, b) ? (a, b) : (b, a);
        u.st.members[_idx(u.st, lo)].weight = 2;
        _apply(r, u, _ids(a, b));
        _authRefused(r, ua, _ids(lo, hi)); // lo alone reaches 2: a slot after the threshold, and not minimal on the portable path
        _authorizes(r, ua, _ids(lo));
        u = _next(r, ua);
        u.st.threshold = 3;
        _apply(r, u, _ids(lo));
        _authRefused(r, ua, _ids(lo));
        _authorizes(r, ua, _ids(lo, hi));
    }

    /// The last block of `validUntilBlock` passes; one later is `UAMsigExpired`.
    function test_validUntilBlock() public {
        bytes32 ua = _eoa3(r);
        Up memory u = _next(r, ua);
        u.until = uint64(block.number);
        _apply(r, u, _ids(a, b));
        u = _next(r, ua);
        u.until = uint64(block.number);
        IUARegistry.MemberSig[] memory s = _upSigs(r, u, _ids(a, b), chainUidA, address(r));
        vm.roll(block.number + 1);
        vm.expectRevert(_err(IUARegistry.UAMsigExpired.selector, ua));
        r.updateMsig(ua, u.version, u.st, u.enabled, u.until, s, chainUidA);
    }

    // ----- refusals: rows 1–4 -----

    function test_refusedChainUid() public {
        bytes32 ua = _eoa3(r);
        Up memory u = _next(r, ua);
        bytes32 other = keccak256("another chain");
        IUARegistry.MemberSig[] memory s = _upSigs(r, u, _ids(a, b), chainUidA, address(r));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.ChainUidMismatch.selector, chainUidA, other));
        r.updateMsig(ua, u.version, u.st, u.enabled, u.until, s, other);
        // signed for another chain word, submitted with this one
        s = _upSigs(r, u, _ids(a, b), other, address(r));
        vm.expectRevert(_err(IUARegistry.UAUnauthorized.selector, ua));
        r.updateMsig(ua, u.version, u.st, u.enabled, u.until, s, chainUidA);
        _apply(r, u, _ids(a, b));
    }

    /// Gen 1 and gen 2 of one chain word: an `msig` registered on both (gen 1 does not see gen 2); an update signed for gen 2's
    /// address is refused on gen 1, the one for gen 1 passes there. Gen 2 refuses an update of a record gen 1 holds (row 3).
    function test_refusedOtherRegistry() public {
        UARegistry g2 = _deploy(REG_G2, chainUidA, address(r), false, BUDGET, address(0), true, new UARegistry.KindConfig[](0));
        bytes32 ua = _eoa3(g2);
        _eoa3(r);
        Up memory u = _next(r, ua);
        _set(u, c, false);
        IUARegistry.MemberSig[] memory s = _upSigs(r, u, _ids(a, b), chainUidA, address(g2));
        vm.expectRevert(_err(IUARegistry.UAUnauthorized.selector, ua));
        r.updateMsig(ua, u.version, u.st, u.enabled, u.until, s, chainUidA);
        _apply(r, u, _ids(a, b));
        _apply(g2, u, _ids(a, b)); // its own update, signed for its own address

        bytes32 g1only = _reg(r, 2, _ids(a, b, d), _w(3), new bytes32[](0));
        Up memory w = _next(r, g1only);
        s = _upSigs(r, w, _ids(a, b), chainUidA, address(g2));
        vm.expectRevert(_err(IUARegistry.UAUnauthorized.selector, g1only));
        g2.updateMsig(g1only, w.version, w.st, w.enabled, w.until, s, chainUidA);
    }

    function test_refusedNotAnMsig() public {
        Up memory u = _next(r, _eoa3(r));
        u.ua = ml[1];
        _refusedUnsigned(r, u, _err(IUARegistry.UAUnauthorized.selector, ml[1]));
        u.ua = keccak256("unregistered");
        _refusedUnsigned(r, u, _err(IUARegistry.UAUnauthorized.selector, u.ua));
    }

    function _refusedUnsigned(UARegistry x, Up memory u, bytes memory err) internal {
        bytes32 cu = x.chainUid();
        vm.expectRevert(err);
        x.updateMsig(u.ua, u.version, u.st, u.enabled, u.until, new IUARegistry.MemberSig[](0), cu);
    }

    /// MM-13: exactly the stored version + 1: `+ 2`, the stored one, below it and a replay are `UAMsigVersion(ua, stored)`.
    function test_refusedVersion() public {
        bytes32 ua = _eoa3(r);
        Up memory u = _next(r, ua);
        u.version = 2;
        _refused(r, u, _ids(a, b), abi.encodeWithSelector(IUARegistry.UAMsigVersion.selector, ua, uint64(0)));
        u.version = 0;
        _refused(r, u, _ids(a, b), abi.encodeWithSelector(IUARegistry.UAMsigVersion.selector, ua, uint64(0)));
        u.version = 1;
        IUARegistry.MemberSig[] memory s = _upSigs(r, u, _ids(a, b), chainUidA, address(r));
        r.updateMsig(ua, 1, u.st, u.enabled, u.until, s, chainUidA);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAMsigVersion.selector, ua, uint64(1)));
        r.updateMsig(ua, 1, u.st, u.enabled, u.until, s, chainUidA); // a replay of the applied update
        u = _next(r, ua);
        u.version = 3;
        _refused(r, u, _ids(a, b), abi.encodeWithSelector(IUARegistry.UAMsigVersion.selector, ua, uint64(1)));
        u.version = 2;
        _apply(r, u, _ids(a, b));
    }

    // ----- rows 5–8 -----

    function test_refusedSlots() public {
        bytes32 ua = _eoa3(r);
        Up memory u = _next(r, ua);
        IUARegistry.MsigMember[] memory two = new IUARegistry.MsigMember[](2);
        (two[0], two[1]) = (u.st.members[0], u.st.members[1]);
        IUARegistry.MsigMember[] memory keep = u.st.members;
        u.st.members = two;
        u.enabled = 3;
        _refused(r, u, _ids(a, b), _slots(2)); // a slot removed
        u.st.members = keep;
        u.enabled = 15;
        _refused(r, u, _ids(a, b), _slots(3)); // an enabled bit past the slots
        u.enabled = 7;
        for (uint256 i; i < 254; ++i) _append(u, EOA, bytes32(uint256(0x10000 + i)), 1, false);
        _refused(r, u, _ids(a, b), _slots(257));
        u = _next(r, ua);
        for (uint256 i; i < 14; ++i) _append(u, EOA, bytes32(uint256(0x10000 + i)), 1, true);
        _refused(r, u, _ids(a, b), _slots(17)); // 17 enabled
        u.enabled &= ~uint256(1 << 16);
        _apply(r, u, _ids(a, b)); // 16 enabled
    }

    function test_refusedSlotChanged() public {
        bytes32 ua = _eoa3(r);
        Up memory u = _next(r, ua);
        uint16 i = _idx(u.st, b);
        u.st.members[i].kind = UAKinds.EVM_CONTRACT;
        _refused(r, u, _ids(a, b), abi.encodeWithSelector(IUARegistry.UAMsigSlotChanged.selector, i));
        u.st.members[i].kind = EOA;
        u.st.members[i].id = e;
        _refused(r, u, _ids(a, b), abi.encodeWithSelector(IUARegistry.UAMsigSlotChanged.selector, i));
        u.st.members[i].id = b;
        _apply(r, u, _ids(a, b));
    }

    /// Row 7: weight 0, a duplicate id (under its kind, and under a second native kind: one slot per id), a native kind with a derived id,
    /// a kind no member may have, a self-slot (appended enabled, and appended disabled then enabled).
    function test_refusedKeyData() public {
        bytes32 ua = _eoa3(r);
        Up memory u = _next(r, ua);
        u.st.members[0].weight = 0;
        _refused(r, u, _ids(a, b), _keyData0120());
        _appendRefused(ua, EOA, a, true);
        _appendRefused(ua, UAKinds.EVM_CONTRACT, a, true);
        _appendRefused(ua, UAKinds.EVM_CONTRACT, a, false);
        _appendRefused(ua, EOA, ml[1], true);
        _appendRefused(ua, UAKinds.ZETHER_BLS12381, ml[4], true);
        _appendRefused(ua, UAKinds.MSIG, ua, true);
        u = _next(r, ua);
        _append(u, UAKinds.MSIG, ua, 1, false); // a disabled self-slot is no member yet
        _apply(r, u, _ids(a, b));
        u = _next(r, ua);
        _set(u, ua, true);
        _refused(r, u, _ids(a, b), _keyData0120());
        u = _next(r, ua);
        _append(u, d, true);
        _apply(r, u, _ids(a, b));
    }

    function _appendRefused(bytes32 ua, uint16 kind, bytes32 id, bool on) internal {
        Up memory u = _next(r, ua);
        _append(u, kind, id, 1, on);
        _refused(r, u, _ids(a, b), _keyData0120());
    }

    /// Row 8 (Q1): the threshold counts enabled and accepted weight; an appended slot has not accepted.
    function test_refusedThreshold() public {
        bytes32 ua = _eoa3(r);
        Up memory u = _next(r, ua);
        u.st.threshold = 0;
        _refused(r, u, _ids(a, b), _err(IUARegistry.UAMsigThreshold.selector, ua));
        _set(u, c, false);
        _append(u, d, true);
        u.st.threshold = 3; // a + b accepted, d not yet: 2
        _refused(r, u, _ids(a, b), _err(IUARegistry.UAMsigThreshold.selector, ua));
        u.st.threshold = 2;
        _apply(r, u, _ids(a, b));
        _accept(r, ua, d);
        u = _next(r, ua);
        u.st.threshold = 3;
        _apply(r, u, _ids(a, b));
    }

    // ----- row 9: who signs -----

    function test_refusedSigners() public {
        bytes32 ua = _eoa3(r);
        Up memory u = _next(r, ua);
        _set(u, c, false);
        _append(u, d, true);
        _append(u, e, true);
        bytes32 typed = _typed(u, chainUidA, address(r));
        bytes memory unauthorized = _err(IUARegistry.UAUnauthorized.selector, ua);
        // the target's new members only: their slots are past the stored ones
        _sigsRefused(u, _sigs(r, u.st, ua, _ids(d, e), UAKinds.PURPOSE_MSIG_UPDATE, typed, true), unauthorized);
        _sigsRefused(u, _upSigs(r, u, _ids(a), chainUidA, address(r)), unauthorized); // short of the threshold
        _sigsRefused(u, _upSigs(r, u, _ids(a, b, c), chainUidA, address(r)), unauthorized); // not minimal
        _apply(r, u, _ids(a, b));

        // a disabled slot, and an enabled slot that never accepted
        u = _next(r, ua);
        _sigsRefused(u, _upSigs(r, u, _ids(a, c), chainUidA, address(r)), unauthorized);
        _sigsRefused(u, _upSigs(r, u, _ids(a, d), chainUidA, address(r)), unauthorized);
        _accept(r, ua, d);
        _apply(r, u, _ids(a, d));
    }

    function _sigsRefused(Up memory u, IUARegistry.MemberSig[] memory s, bytes memory err) internal {
        vm.expectRevert(err);
        r.updateMsig(u.ua, u.version, u.st, u.enabled, u.until, s, chainUidA);
    }

    // ----- row 10: appended or re-enabled members -----

    function test_refusedMemberUnknown() public {
        bytes32 ua = _eoa3(r);
        bytes32 stranger = UAKinds.uaOf(ML, _mlKey(99));
        kindOfId[stranger] = ML;
        Up memory u = _next(r, ua);
        _append(u, stranger, false);
        _refused(r, u, _ids(a, b), _err(IUARegistry.UAMemberUnknown.selector, stranger)); // unregistered (appended disabled too)
        u = _next(r, ua);
        _append(u, 0x0130, ml[1], 1, true); // registered as mldsa65, listed as mldsa44
        _refused(r, u, _ids(a, b), _err(IUARegistry.UAMemberUnknown.selector, ml[1]));
        u = _next(r, ua);
        _append(u, ml[1], true);
        _apply(r, u, _ids(a, b));
    }

    /// An `msig` member that holds an `msig` (a third level) is refused when appended; when it grew one after it was listed, the
    /// outer keeps it (it signs nothing at that level) and may disable it, but not enable it again.
    function test_nestedThirdLevel() public {
        bytes32 j = _reg(r, 1, _ids(ml[6]), _w(1), _ids(ml[6]));
        innerSigners[j] = _ids(ml[6]);
        bytes32 i = _pq3(r);
        innerSigners[i] = _ids(ml[1], ml[2]);
        bytes32 v = _reg(r, 2, _ids(i, ml[4], ml[5]), _w(3), _ids(ml[4], ml[5]));
        // I grows a third level: j appended (flat now)
        Up memory u = _next(r, i);
        _append(u, j, true);
        _apply(r, u, _ids(ml[1], ml[2]));
        _accept(r, i, j);
        // a new msig appending I: I holds an msig now
        bytes32 w = _eoa3(r);
        u = _next(r, w);
        _append(u, i, true);
        _refused(r, u, _ids(a, b), _err(IUARegistry.UAMemberUnknown.selector, i));

        // V keeps I: its key write and an unrelated update run; I signs nothing for V at a level that is not there
        (bool ok,) = _call(address(r), _pqzKeyCall(r, v, 0, _ids(ml[4], ml[5]), 1));
        assertTrue(ok, "V rotates its key with I grown");
        u = _next(r, v);
        u.st.members[_idx(u.st, ml[4])].weight = 1; // unchanged weights: a version step only
        _apply(r, u, _ids(ml[4], ml[5]));
        _authorizes(r, v, _ids(i, ml[4])); // I's own quorum ml1 + ml2 still signs for it
        u = _next(r, v);
        _set(u, i, false);
        _apply(r, u, _ids(ml[4], ml[5]));
        u = _next(r, v);
        _set(u, i, true);
        _refused(r, u, _ids(ml[4], ml[5]), _err(IUARegistry.UAMemberUnknown.selector, i));
    }

    /// MM-14: at a member's level its own `msig` slot is classical weight, never followed: an I whose new msig member weighs its
    /// threshold is no longer PQ for V, which then may not write its PQZ key (fail closed).
    function test_nestedThirdLevelIsClassical() public {
        bytes32 j = _reg(r, 1, _ids(ml[6]), _w(1), _ids(ml[6]));
        bytes32 i = _pq3(r);
        innerSigners[i] = _ids(ml[1], ml[2]);
        bytes32 v = _reg(r, 2, _ids(i, ml[4], ml[5]), _w(3), _ids(ml[4], ml[5]));
        Up memory u = _next(r, i);
        _append(u, UAKinds.MSIG, j, 2, true); // classical 2 at I's own level is j's weight there: I's threshold
        _apply(r, u, _ids(ml[1], ml[2]));
        u = _next(r, v);
        u.st.members[_idx(u.st, i)].weight = 2;
        // I weighs 2, classical for V (j not followed): V's classical 2 reaches its threshold 2, V stops being PQ-eligible (row 12)
        _refused(r, u, _ids(ml[4], ml[5]), _err(IUARegistry.UAPqzHolder.selector, v));
        u.st.threshold = 3; // classical 2 < 3: still PQ-eligible
        _apply(r, u, _ids(ml[4], ml[5]));
    }

    // ----- rows 11–13 -----

    /// Row 11: the target's enabled slots pass the registration bound (`verifyBudget`).
    function test_refusedBound() public {
        UARegistry x = _deploy(REG_X, keccak256("chain x"), address(0), false, 1_300_000, address(0), true, _cfgsMl(400_000));
        _members(x);
        bytes32 ua = _eoa3(x);
        Up memory u = _next(x, ua);
        for (uint256 k = 1; k <= 3; ++k) _append(u, ml[k], true);
        u.st.threshold = 3; // three of the lightest: 3 × (400 k + 45 k) + 2,500 > 1.3 M
        _refused(x, u, _ids(a, b), _keyData0120());
        u.st.threshold = 2; // 2 × 445 k + 2,500
        _apply(x, u, _ids(a, b));
        // the bound counts the enabled slots only: the three mldsa65 slots disabled, 3-of-{a, b, c} is 3 × 95 k + 2,500 (with them,
        // the three lightest would take the 400 k caps: 1,337,500 > 1.3 M)
        u = _next(x, ua);
        for (uint256 k = 1; k <= 3; ++k) _set(u, ml[k], false);
        u.st.threshold = 3;
        _apply(x, u, _ids(a, b));
    }

    /// Row 12 (Q4): a PQ-eligible `msig` stays PQ-eligible; a PQ-eligible target passes the debit bound.
    function test_refusedPqzHolder() public {
        bytes32 ua = _pq3(r);
        Up memory u = _next(r, ua);
        _append(u, a, true);
        u.st.members[3].weight = 2; // classical 2 ≥ threshold 2
        _refused(r, u, _ids(ml[1], ml[2]), _err(IUARegistry.UAPqzHolder.selector, ua));
        u.st.members[3].weight = 1;
        _apply(r, u, _ids(ml[1], ml[2]));
        // a classical-dominant msig that stays so is not judged by the debit bound
        bytes32 cl = _eoa3(r);
        Up memory w = _next(r, cl);
        for (uint256 k = 1; k <= 3; ++k) _append(w, ml[k], true);
        _set(w, c, false);
        _apply(r, w, _ids(a, b)); // classical a + b = 2, threshold 2: not eligible, allowed
    }

    /// Row 12's debit bound: caps chosen from this set's `PQZ_DEBIT_MIN_GAS` so that 2-of-3 passes and 3-of-3 does not.
    function test_refusedDebitBound() public {
        uint256 room = UARegistryCoreLib.TX_GAS_CAP - PqzSet.PQZ_DEBIT_MIN_GAS; // what the authorization may take
        uint64 cap = uint64(room * 63 / 64 / 3 + 50_000); // three such signers exceed it; two do not
        UARegistry x = _deploy(REG_X, keccak256("chain x"), address(0), false, 3 * cap + 300_000, address(0), true, _cfgsMl(cap));
        _members(x);
        bytes32 ua = _pq3(x);
        Up memory u = _next(x, ua);
        u.st.threshold = 3;
        _refused(x, u, _ids(ml[1], ml[2]), _err(IUARegistry.UAPqzHolder.selector, ua));
        u.st.threshold = 2;
        _apply(x, u, _ids(ml[1], ml[2]));
    }

    /// Row 13: a target whose next update would not fit one transaction: 3-of-4 `mldsa65` at 400 k; the largest count that fits
    /// is taken from the pinned constants, one more is refused.
    function test_refusedNextUpdate() public {
        bytes32 ua = _reg(r, 3, _ids(ml[1], ml[2], ml[3]), _w(3), _ids(ml[1], ml[2], ml[3]));
        uint256 worst = 3 * (UARegistryCoreLib.MSIG_MEMBER_GAS + 400_000) + UARegistryCoreLib.MSIG_ACCEPTED_GAS;
        uint256 fit = (UARegistryCoreLib.TX_GAS_CAP - UARegistryCoreLib.MSIG_UPDATE_GAS - worst) / UARegistryCoreLib.MSIG_UPDATE_SLOT_GAS;
        assertLt(fit, 256, "row 13 must be able to refuse here: heavier signers if the constants move");
        Up memory u = _next(r, ua);
        for (uint256 i = 3; i <= fit; ++i) _append(u, EOA, bytes32(uint256(0x10000 + i)), 1, false);
        _refused(r, u, _ids(ml[1], ml[2], ml[3]), _slots(fit + 1));
        IUARegistry.MsigMember[] memory m = new IUARegistry.MsigMember[](fit);
        for (uint256 i; i < fit; ++i) m[i] = u.st.members[i];
        u.st.members = m;
        _apply(r, u, _ids(ml[1], ml[2], ml[3]));
    }

    // ----- acceptance, generations, the library -----

    /// MM-11: an appended slot accepts by `acceptMembership`; past the slots is refused; a disabled slot may accept.
    function test_acceptAppendedSlot() public {
        bytes32 ua = _eoa3(r);
        Up memory u = _next(r, ua);
        _append(u, d, false);
        _apply(r, u, _ids(a, b));
        IUARegistry.MemberSig memory s = _sigs(r, u.st, ua, _ids(d), UAKinds.PURPOSE_MEMBERSHIP, UAKinds.membershipDigest(ua, d), true)[0];
        s.index = 4;
        vm.expectRevert(_err(IUARegistry.UAUnauthorized.selector, ua));
        r.acceptMembership(ua, s);
        _accept(r, ua, d);
        (,, uint256 acc) = r.msigStateOf(ua);
        assertEq(acc >> 3 & 1, 1, "a disabled slot accepted");
        assertFalse(r.memberAccepted(ua, 3), "and counts once enabled");
    }

    /// Gen 2 forwards the current structure of a gen-1 record (`msigOf`, `msigStateOf`, `memberAccepted`) and its authorization.
    function test_gen2ForwardsCurrent() public {
        bytes32 ua = _eoa3(r);
        Up memory u = _next(r, ua);
        _set(u, c, false);
        _append(u, d, true);
        _apply(r, u, _ids(a, b));
        _accept(r, ua, d);
        UARegistry g2 = _deploy(REG_G2, chainUidA, address(r), false, BUDGET, address(0), true, new UARegistry.KindConfig[](0));
        dom = r; // gen 1 verifies its native members in its own domain
        assertEq(abi.encode(g2.msigOf(ua)), abi.encode(r.msigOf(ua)));
        (uint64 v, uint256 en, uint256 acc) = g2.msigStateOf(ua);
        (uint64 v1, uint256 en1, uint256 acc1) = r.msigStateOf(ua);
        assertEq(v, v1);
        assertEq(en, en1);
        assertEq(acc, acc1);
        for (uint256 k; k < 5; ++k) assertEq(g2.memberAccepted(ua, k), r.memberAccepted(ua, k));
        _authorizes(g2, ua, _ids(a, d));
        _authRefused(g2, ua, _ids(b, c));
    }

    /// On a gen-2 PQZ host, `setPqzKey` of a gen-1 `msig` signs against gen 1's current structure: an appended signer counts, and a
    /// raised threshold is the raised one (never `registrationOf`'s first structure).
    function test_gen2HostCurrentStructure() public {
        bytes32 ua = _pq3(r);
        Up memory u = _next(r, ua);
        _append(u, ml[4], true);
        _apply(r, u, _ids(ml[1], ml[2]));
        _accept(r, ua, ml[4]);
        UARegistry.KindConfig[] memory cfg = new UARegistry.KindConfig[](1);
        cfg[0] = UARegistry.KindConfig(UAKinds.PQZ_MLWE, address(mock), 400_000);
        UARegistry g2 = _deploy(REG_G2, chainUidA, address(r), false, BUDGET, address(0), true, cfg);
        (bool ok,) = _call(address(g2), _pqzKeyCall(g2, ua, 0, _ids(ml[1], ml[4]), 1));
        assertTrue(ok, "an appended signer");

        u = _next(r, ua);
        u.st.threshold = 3;
        _apply(r, u, _ids(ml[1], ml[4]));
        _callRefused(address(g2), _pqzKeyCall(g2, ua, 1, _ids(ml[1], ml[2]), 2), _err(IUARegistry.UAUnauthorized.selector, ua));
        (ok,) = _call(address(g2), _pqzKeyCall(g2, ua, 1, _ids(ml[1], ml[2], ml[3]), 2));
        assertTrue(ok, "three of the raised threshold");
    }

    function _callOrRevert(address t, bytes memory data) internal {
        (bool ok, bytes memory ret) = t.call(data);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 32), mload(ret)) }
    }

    /// A PQ `msig` after an update: the new quorum writes its PQZ key, the old one with the disabled slot does not.
    function test_setPqzKeyAfterUpdate() public {
        bytes32 ua = _pq3(r);
        Up memory u = _next(r, ua);
        _set(u, ml[3], false);
        _append(u, ml[4], true);
        _apply(r, u, _ids(ml[1], ml[2]));
        _accept(r, ua, ml[4]);
        _callRefused(address(r), _pqzKeyCall(r, ua, 0, _ids(ml[2], ml[3]), 1), _err(IUARegistry.UAUnauthorized.selector, ua));
        _callOrRevert(address(r), _pqzKeyCall(r, ua, 0, _ids(ml[1], ml[4]), 1));
    }

    /// The nested positive control: an inner updated under an outer; the outer signs with the inner's new quorum on both paths.
    function test_nestedInnerUpdated() public {
        bytes32 i = _pq3(r);
        innerSigners[i] = _ids(ml[1], ml[2]);
        bytes32 v = _reg(r, 2, _ids(i, ml[4], ml[5]), _w(3), _ids(ml[4], ml[5]));
        Up memory u = _next(r, i);
        _set(u, ml[2], false);
        _append(u, ml[6], true);
        _apply(r, u, _ids(ml[1], ml[2]));
        _accept(r, i, ml[6]);
        _authRefused(r, v, _ids(i, ml[4])); // I's old quorum names the disabled ml2
        innerSigners[i] = _ids(ml[1], ml[6]);
        _authorizes(r, v, _ids(i, ml[4]));
        _portable(r, v, _ids(i, ml[4]));
    }

    /// `verifierShape` (frozen-shape rule, §5.3) differs after a disable-only update.
    function test_verifierShapeMoves() public {
        bytes32 ua = _eoa3(r);
        bytes32 before = PqzCore.verifierShape(address(r), ua, false);
        Up memory u = _next(r, ua);
        _set(u, c, false);
        _apply(r, u, _ids(a, b));
        assertTrue(PqzCore.verifierShape(address(r), ua, false) != before);
    }

    /// Called directly, the library's writer reverts (solc's call protection); the registry is the only way in.
    function test_libraryDirectCallReverts() public {
        bytes32 ua = _eoa3(r);
        Up memory u = _next(r, ua);
        IUARegistry.MemberSig[] memory s = _upSigs(r, u, _ids(a, b), chainUidA, address(r));
        (bool ok,) = address(UARegistryAuxLib).call(
            abi.encodeWithSelector(UARegistryAuxLib.updateMsig.selector, ua, u.version, u.st, u.enabled, u.until, s, chainUidA)
        );
        assertFalse(ok);
        r.updateMsig(ua, u.version, u.st, u.enabled, u.until, s, chainUidA);
    }

    // ----- 256 slots (P1-2: no reader masks by `(1 << count) - 1`) -----

    /// A PQ `msig` grown to 256 slots (16 enabled at most): `requireAuthorized`, `requirePortable`, `setPqzKey` and a further
    /// `updateMsig` all pass; the further update fits one transaction. Its own registry: `mldsa65` at a 100 k cap.
    function test_256Slots() public {
        UARegistry x = _deploy(REG_X, keccak256("chain x"), address(0), false, BUDGET, address(0), true, _cfgsMl(100_000));
        _members(x);
        bytes32 ua = _pq3(x);
        Up memory u = _next(x, ua);
        for (uint256 i; i < 253; ++i) _append(u, EOA, bytes32(uint256(0x10000 + i)), 1, false);
        _apply(x, u, _ids(ml[1], ml[2]));
        assertEq(x.msigOf(ua).members.length, 256);
        _authorizes(x, ua, _ids(ml[1], ml[3]));
        _portable(x, ua, _ids(ml[2], ml[3]));
        _callOrRevert(address(x), _pqzKeyCall(x, ua, 0, _ids(ml[1], ml[2]), 1));
        assertFalse(x.memberAccepted(ua, 255));
        u = _next(x, ua);
        u.enabled |= 1 << 255; // the last slot, a 256-safe shift
        bytes memory data = abi.encodeCall(IUARegistry.updateMsig,
            (ua, u.version, u.st, u.enabled, u.until, _upSigs(x, u, _ids(ml[1], ml[2]), x.chainUid(), address(x)), x.chainUid()));
        uint256 total = _gasTotal(address(x), data);
        emit log_named_uint("updateMsig, 256 slots, a further update (regular + state)", total);
        assertLe(total, UARegistryCoreLib.TX_GAS_CAP, "the next update fits one transaction");
        (, uint256 en,) = x.msigStateOf(ua);
        assertEq(en >> 255, 1);
    }

    // ----- gas -----

    function _gasTotal(address t, bytes memory data) internal returns (uint256) {
        _callOrRevert(t, data);
        Vm.Gas memory g = vm.lastCallGas();
        return g.gasTotalUsed + uint256(int256(g.gasStateUsed));
    }

    /// An `msig` of 3 accepted EOAs and `n - 3` disabled EOA slots; returns the calldata of its next update (version + 1, no
    /// change, signed by a + b): the form row 13 bounds.
    function _grown(uint256 n) internal returns (address, bytes memory) {
        UARegistry x = _deploy(address(uint160(0x5ca00 + n)), keccak256(abi.encode("chain", n)), address(0), false, BUDGET, address(0),
            true, _cfgsMl(400_000));
        bytes32 ua = _eoa3(x);
        if (n > 3) {
            Up memory g = _next(x, ua);
            for (uint256 i = 3; i < n; ++i) _append(g, EOA, bytes32(uint256(0x10000 + i)), 1, false);
            _apply(x, g, _ids(a, b));
        }
        Up memory u = _next(x, ua);
        return (address(x), abi.encodeCall(IUARegistry.updateMsig,
            (ua, u.version, u.st, u.enabled, u.until, _upSigs(x, u, _ids(a, b), x.chainUid(), address(x)), x.chainUid())));
    }

    /// Row 13's model: an update of `n` slots (regular + EIP-8037 state gas, intrinsic and calldata included, two EOA signers
    /// whose real cost is far under their 50 k caps) stays under `MSIG_UPDATE_GAS + n × MSIG_UPDATE_SLOT_GAS`. Logs the figures the
    /// constants were set from.
    function test_gas_updateRowModel() public {
        uint256[4] memory ns = [uint256(3), 16, 64, 256];
        uint256[4] memory g;
        for (uint256 k; k < 4; ++k) {
            (address x, bytes memory data) = _grown(ns[k]);
            g[k] = _gasTotal(x, data);
            emit log_named_uint(string.concat("updateMsig total gas, slots ", vm.toString(ns[k])), g[k]);
            assertLe(g[k], UARegistryCoreLib.MSIG_UPDATE_GAS + ns[k] * UARegistryCoreLib.MSIG_UPDATE_SLOT_GAS, "row 13 model");
        }
        emit log_named_uint("per slot (256 - 16) / 240", (g[3] - g[1]) / 240);
        emit log_named_uint("fixed (3 slots less 3 per-slot)", g[0] - 3 * ((g[3] - g[1]) / 240));
    }

    /// The hot path: `requireAuthorized` of a 2-of-3 EOA `msig`, never updated and updated (the blob read replaces the registration
    /// blob's, and the record's slot is read once either way).
    function test_gas_requireAuthorized() public {
        bytes32 ua = _eoa3(r);
        HotProbe p = new HotProbe();
        IUARegistry.UASig memory s = _auth(_sigs(r, r.msigOf(ua), ua, _ids(a, b), UAKinds.PURPOSE_METATX, TX, false));
        uint256 g0 = p.cost(r, ua, UAKinds.PURPOSE_METATX, TX, s);
        Up memory u = _next(r, ua);
        _apply(r, u, _ids(a, b));
        s = _auth(_sigs(r, r.msigOf(ua), ua, _ids(a, b), UAKinds.PURPOSE_METATX, TX, false));
        uint256 g1 = p.cost(r, ua, UAKinds.PURPOSE_METATX, TX, s);
        emit log_named_uint("requireAuthorized 2-of-3, never updated", g0);
        emit log_named_uint("requireAuthorized 2-of-3, updated", g1);
        assertLe(g1, g0, "an updated msig reads no more");
    }
}
