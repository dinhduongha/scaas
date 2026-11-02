// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UARegistryBase} from "./UARegistryBase.sol";
import {UACall} from "./UACall.sol";

/// Nested `msig` (spec `docs/superpowers/specs/2026-11-02-msig-nested.md`, owner 2026-11-02): an `msig` may hold `msig` members,
/// verification goes two levels only. The stand-in verifier signs (`_sig`), ECDSA is real. Each negative changes one thing from a
/// signature set that passes in the same test.
contract UARegistryNestedTest is UARegistryBase {
    uint16 internal constant P256 = 0x0101;
    uint16 internal constant ED = 0x0102;
    uint16 internal constant ML65 = 0x0131;
    uint256 internal constant PK_A = 0xA11CE;
    uint256 internal constant PK_B = 0xB0B;
    uint256 internal constant PK_C = 0xCA7;

    IUARegistry.InnerSig[] internal noneInner; // always empty

    bytes internal keyP;
    bytes internal keyE;
    bytes32 internal idP;
    bytes32 internal idE;

    function setUp() public override {
        super.setUp();
        (keyP, keyE) = (_key(P256), _key(ED));
        (idP, idE) = (_register(reg, P256, keyP), _register(reg, ED, keyE));
    }

    // ----- helpers -----

    function _eoa(uint256 pk) internal pure returns (bytes32) {
        return _pad(vm.addr(pk));
    }

    /// `t`-of-{EOA a, p256, ed25519}, weights 1, registered with an empty `pop` (classical-dominant), every slot accepted.
    function _inner(uint16 t, uint256 pk) internal returns (bytes memory d, bytes32 ua) {
        Member[] memory m = new Member[](3);
        m[0] = Member(UAKinds.EVM_EOA, _eoa(pk), 1);
        m[1] = Member(P256, idP, 1);
        m[2] = Member(ED, idE, 1);
        d = _msigKey(t, m);
        ua = UACall.register(reg, UAKinds.MSIG, d, _none(), "", "");
        _acceptInner(d, ua, pk);
    }

    function _acceptInner(bytes memory d, bytes32 ua, uint256 pk) internal {
        reg.acceptMembership(ua, _acceptEoaSig(d, pk));
        reg.acceptMembership(ua, _acceptKeySig(d, P256, keyP));
        reg.acceptMembership(ua, _acceptKeySig(d, ED, keyE));
    }

    /// {inner `iu`, EOA b}, threshold 2, registered.
    function _outer(bytes32 iu, uint256 pkB) internal returns (bytes memory d, bytes32 ua) {
        Member[] memory m = new Member[](2);
        m[0] = Member(UAKinds.MSIG, iu, 1);
        m[1] = Member(UAKinds.EVM_EOA, _eoa(pkB), 1);
        d = _msigKey(2, m);
        ua = UACall.register(reg, UAKinds.MSIG, d, _none(), "", "");
    }

    function _mdInner(bytes32 iu, bytes32 mdOuter) internal pure returns (bytes32) {
        return UAKinds.memberDigest(iu, UAKinds.uaMessage(UAKinds.MSIG, UAKinds.PURPOSE_MEMBER, mdOuter));
    }

    /// Slots `p` (p256) then `e` (ed25519), in index order of the inner structure `d`, over `md`.
    function _leaves(bytes memory d, bytes32 md) internal view returns (IUARegistry.InnerSig[] memory s) {
        s = new IUARegistry.InnerSig[](2);
        (uint16 ip, uint16 ie) = (_indexOf(d, idP), _indexOf(d, idE));
        (uint256 first, uint256 second) = ip < ie ? (0, 1) : (1, 0);
        s[first] = IUARegistry.InnerSig(ip, _sig(keyP, UAKinds.uaMessage(P256, UAKinds.PURPOSE_MEMBER, md)));
        s[second] = IUARegistry.InnerSig(ie, _sig(keyE, UAKinds.uaMessage(ED, UAKinds.PURPOSE_MEMBER, md)));
    }

    /// The outer signature of {inner, EOA b} over `(PURPOSE_METATX, digest)`, slots in index order.
    function _outerSigs(bytes memory du, bytes32 ua, bytes32 iu, bytes memory di, uint256 pkB, bytes32 digest)
        internal
        view
        returns (IUARegistry.MemberSig[] memory s)
    {
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX, digest);
        s = new IUARegistry.MemberSig[](2);
        uint16 iSlot = _indexOf(du, iu);
        uint16 bSlot = 1 - iSlot;
        s[iSlot] = IUARegistry.MemberSig(iSlot, _leaves(di, _mdInner(iu, md)), "");
        s[bSlot] = IUARegistry.MemberSig(bSlot, noneInner, _nativeSig(reg, pkB, UAKinds.PURPOSE_MEMBER, md));
    }

    function _pass(bytes32 ua, bytes memory d, IUARegistry.MemberSig[] memory s) internal view {
        _req(reg, ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(d, s));
    }

    function _refused(bytes32 ua, bytes memory d, IUARegistry.MemberSig[] memory s) internal {
        bytes memory auth = _msigAuth(d, s);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        _req(reg, ua, UAKinds.PURPOSE_METATX, DIGEST, auth);
    }

    /// An `msig` both levels accepted: inner 2-of-3, outer {inner, EOA b} 2-of-2.
    function _active() internal returns (bytes memory di, bytes32 iu, bytes memory du, bytes32 ua) {
        (di, iu) = _inner(2, PK_A);
        (du, ua) = _outer(iu, PK_B);
        uint16 iSlot = _indexOf(du, iu);
        reg.acceptMembership(ua, _acceptEoaSig(du, PK_B));
        bytes32 typed = UAKinds.membershipDigest(ua, iu);
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_MEMBERSHIP, typed);
        reg.acceptMembership(ua, IUARegistry.MemberSig(iSlot, _leaves(di, _mdInner(iu, md)), ""));
    }

    // ----- the generic `bytes auth` -----

    function authCall(bytes32 ua, bytes calldata auth) external pure returns (bytes memory) {
        return UAKinds.uaAuthCall(ua, UAKinds.PURPOSE_METATX, DIGEST, auth);
    }

    /// `UAKinds.uaAuthCall` splices a nested list into the call by hand: byte for byte the typed call, and the real registry answers it.
    function test_genericAuthIsTheTypedCall() public {
        (bytes memory di, bytes32 iu, bytes memory du, bytes32 ua) = _active();
        IUARegistry.MemberSig[] memory s = _outerSigs(du, ua, iu, di, PK_B, DIGEST);
        IUARegistry.UASig memory u;
        u.members = s;
        bytes memory auth = _msigAuth(du, s);
        bytes memory call = this.authCall(ua, auth);
        assertEq(call, abi.encodeCall(IUARegistry.requireAuthorized, (ua, UAKinds.PURPOSE_METATX, DIGEST, u)));
        (bool ok,) = address(reg).staticcall(call);
        assertTrue(ok);

        s[_indexOf(du, iu)].members[0].sig = _sig(keyP, keccak256("another message"));
        (bool bad, bytes memory ret) = address(reg).staticcall(this.authCall(ua, _msigAuth(du, s)));
        assertFalse(bad);
        assertEq(ret, abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));

        // not the id's own structure: `keyData` + `signature`, as the two words came
        IUARegistry.UASig memory flat;
        (flat.keyData, flat.signature) = (hex"aa", hex"bb");
        assertEq(this.authCall(ua, abi.encode(flat.keyData, flat.signature)),
            abi.encodeCall(IUARegistry.requireAuthorized, (ua, UAKinds.PURPOSE_METATX, DIGEST, flat)));
    }

    /// A `sig` that is not `abi.encode(MemberSig[])` at the one canonical offset is refused before the registry, with empty data, as the
    /// ABI decoder did. `good` is the positive control.
    function test_genericAuthMalformed() public {
        (bytes memory di, bytes32 iu, bytes memory du, bytes32 ua) = _active();
        bytes memory good = abi.encode(_outerSigs(du, ua, iu, di, PK_B, DIGEST));
        this.authCall(ua, abi.encode(du, good));
        vm.expectRevert(bytes(""));
        this.authCall(ua, abi.encode(du, bytes("")));
        vm.expectRevert(bytes(""));
        this.authCall(ua, abi.encode(du, abi.encode(uint256(0x20))));
        assembly ("memory-safe") {
            mstore(add(good, 32), 0x40)
        }
        vm.expectRevert(bytes(""));
        this.authCall(ua, abi.encode(du, good));
    }

    // ----- registration: two levels -----

    /// An `msig` holding an `msig` member cannot itself be a member: `UAMemberUnknown` names the id a level too deep.
    function test_twoLevelsOnly() public {
        (, bytes32 iu) = _inner(2, PK_A);
        (bytes memory du, bytes32 ua) = _outer(iu, PK_B);
        assertEq(reg.kindOf(ua), UAKinds.MSIG);
        assertEq(reg.msigOf(ua).members[_indexOf(du, iu)].kind, UAKinds.MSIG);
        Member[] memory m = new Member[](2);
        m[0] = Member(UAKinds.MSIG, ua, 1);
        m[1] = Member(UAKinds.EVM_EOA, _eoa(PK_C), 1);
        bytes memory d = _msigKey(2, m);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAMemberUnknown.selector, iu));
        UACall.register(reg, UAKinds.MSIG, d, _none(), "", "");
    }

    /// A member is registered first, under its stated kind: an id not registered, or a registered id of another kind, is refused;
    /// ids are hashes of the structure, so a member listed before it exists is the only way to a cycle and it fails here.
    function test_memberRegisteredFirst() public {
        Member[] memory m = new Member[](2);
        m[0] = Member(UAKinds.MSIG, keccak256("not registered"), 1);
        m[1] = Member(UAKinds.EVM_EOA, _eoa(PK_C), 1);
        bytes memory d = _msigKey(2, m);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAMemberUnknown.selector, m[_indexOf(d, keccak256("not registered"))].id));
        UACall.register(reg, UAKinds.MSIG, d, _none(), "", "");
        m[_indexOf(d, keccak256("not registered"))] = Member(UAKinds.MSIG, idP, 1);
        d = _msigKey(2, m);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAMemberUnknown.selector, idP));
        UACall.register(reg, UAKinds.MSIG, d, _none(), "", "");
    }

    // ----- requireAuthorized -----

    function test_nestedAuthorizes() public {
        (bytes memory di, bytes32 iu, bytes memory du, bytes32 ua) = _active();
        _pass(ua, du, _outerSigs(du, ua, iu, di, PK_B, DIGEST));
    }

    /// One change per case from the set that passes above.
    function test_nestedNegatives() public {
        (bytes memory di, bytes32 iu, bytes memory du, bytes32 ua) = _active();
        uint16 iSlot = _indexOf(du, iu);
        IUARegistry.MemberSig[] memory s = _outerSigs(du, ua, iu, di, PK_B, DIGEST);
        _pass(ua, du, s);

        bytes memory good = s[iSlot].members[0].sig;
        s[iSlot].members[0].sig = hex"00";
        _refused(ua, du, s); // a bad inner signature
        s[iSlot].members[0].sig = good;

        IUARegistry.InnerSig[] memory two = s[iSlot].members;
        s[iSlot].members = new IUARegistry.InnerSig[](1);
        s[iSlot].members[0] = two[0];
        _refused(ua, du, s); // the inner threshold unmet

        s[iSlot].members = noneInner;
        _refused(ua, du, s); // an `msig` slot without its list
        s[iSlot].sig = good;
        _refused(ua, du, s); // an `msig` slot with a `sig` of its own, no list
        s[iSlot].members = two;
        _refused(ua, du, s); // list and `sig`
        s[iSlot].sig = "";

        (two[0], two[1]) = (two[1], two[0]);
        _refused(ua, du, s); // inner indexes not increasing
        (two[0], two[1]) = (two[1], two[0]);

        uint16 bSlot = 1 - iSlot;
        s[bSlot].members = two;
        _refused(ua, du, s); // a list on a signing member
        s[bSlot].members = noneInner;
        _pass(ua, du, s);
    }

    /// Stop at the threshold at the inner level: a third inner signature fails, a 2-of-3 is not 3-of-3.
    function test_innerStopsAtThreshold() public {
        (bytes memory di, bytes32 iu, bytes memory du, bytes32 ua) = _active();
        IUARegistry.MemberSig[] memory s = _outerSigs(du, ua, iu, di, PK_B, DIGEST);
        uint16 iSlot = _indexOf(du, iu);
        bytes32 md = _mdInner(iu, _memberDigest(ua, UAKinds.PURPOSE_METATX, DIGEST));
        uint16 ia = _indexOf(di, _eoa(PK_A));
        IUARegistry.InnerSig[] memory three = new IUARegistry.InnerSig[](3);
        IUARegistry.InnerSig[] memory two = s[iSlot].members;
        (uint16 lo, uint16 hi) = (two[0].index, two[1].index);
        uint256 at = ia < lo ? 0 : (ia < hi ? 1 : 2);
        uint256 j;
        for (uint256 i; i < 3; ++i) {
            if (i == at) three[i] = IUARegistry.InnerSig(ia, _nativeSig(reg, PK_A, UAKinds.PURPOSE_MEMBER, md));
            else three[i] = two[j++];
        }
        s[iSlot].members = three;
        _refused(ua, du, s);
    }

    /// A good signature of a slot the inner `msig` has not accepted fails; so does a good signature of an outer slot not accepted.
    function test_unacceptedAtEitherLevel() public {
        Member[] memory m = new Member[](3);
        m[0] = Member(UAKinds.EVM_EOA, _eoa(PK_A), 1);
        m[1] = Member(P256, idP, 1);
        m[2] = Member(ED, idE, 1);
        bytes memory di = _msigKey(2, m);
        bytes32 iu = UACall.register(reg, UAKinds.MSIG, di, _none(), "", "");
        reg.acceptMembership(iu, _acceptKeySig(di, P256, keyP));
        reg.acceptMembership(iu, _acceptEoaSig(di, PK_A)); // ed25519 not accepted: active, 2 of 3
        (bytes memory du, bytes32 ua) = _outer(iu, PK_B);
        reg.acceptMembership(ua, _acceptEoaSig(du, PK_B));
        uint16 iSlot = _indexOf(du, iu);
        bytes32 typed = UAKinds.membershipDigest(ua, iu);
        bytes32 mdm = _mdInner(iu, _memberDigest(ua, UAKinds.PURPOSE_MEMBERSHIP, typed));

        // the outer slot refuses the list holding the unaccepted ed25519 slot, stays open
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        reg.acceptMembership(ua, IUARegistry.MemberSig(iSlot, _leaves(di, mdm), ""));
        assertFalse(reg.memberAccepted(ua, iSlot));
        IUARegistry.MemberSig[] memory s = _outerSigs(du, ua, iu, di, PK_B, DIGEST);
        _refused(ua, du, s); // the outer slot is unaccepted too
    }

    /// `digest` of the outer, the outer itself, the inner: each is in the chain, so a signature for one never serves another.
    function test_digestChainBindsOuterAndInner() public {
        (bytes memory di, bytes32 iu, bytes memory du, bytes32 ua) = _active();
        // a second outer with the same inner, both slots accepted
        (bytes memory du2, bytes32 ua2) = _outer(iu, PK_C);
        reg.acceptMembership(ua2, _acceptEoaSig(du2, PK_C));
        uint16 is2 = _indexOf(du2, iu);
        bytes32 typed2 = UAKinds.membershipDigest(ua2, iu);
        reg.acceptMembership(ua2, IUARegistry.MemberSig(is2, _leaves(di, _mdInner(iu, _memberDigest(ua2, UAKinds.PURPOSE_MEMBERSHIP, typed2))), ""));
        IUARegistry.MemberSig[] memory s2 = _outerSigs(du2, ua2, iu, di, PK_C, DIGEST);
        _pass(ua2, du2, s2);

        // the inner list made for `ua` in `ua2`
        IUARegistry.MemberSig[] memory s = _outerSigs(du, ua, iu, di, PK_B, DIGEST);
        s2[is2].members = s[_indexOf(du, iu)].members;
        _refused(ua2, du2, s2);

        // the same list under another digest of the same outer
        IUARegistry.MemberSig[] memory other = _outerSigs(du, ua, iu, di, PK_B, keccak256("other"));
        other[_indexOf(du, iu)].members = s[_indexOf(du, iu)].members;
        _refused(ua, du, other);

        // leaves that signed the outer's digest directly, one level short
        IUARegistry.MemberSig[] memory short_ = _outerSigs(du, ua, iu, di, PK_B, DIGEST);
        short_[_indexOf(du, iu)].members = _leaves(di, _memberDigest(ua, UAKinds.PURPOSE_METATX, DIGEST));
        _refused(ua, du, short_);
    }

    /// Below the threshold in accepted weight the outer authorizes nothing, whatever the inner signs; an inner below its own accepted
    /// threshold cannot accept. Accepting is one call, one slot; a second call is a no-op with any bytes.
    function test_acceptanceAtBothLevels() public {
        Member[] memory m = new Member[](3);
        m[0] = Member(UAKinds.EVM_EOA, _eoa(PK_A), 1);
        m[1] = Member(P256, idP, 1);
        m[2] = Member(ED, idE, 1);
        bytes memory di = _msigKey(2, m);
        bytes32 iu = UACall.register(reg, UAKinds.MSIG, di, _none(), "", "");
        (bytes memory du, bytes32 ua) = _outer(iu, PK_B);
        uint16 iSlot = _indexOf(du, iu);
        bytes32 typed = UAKinds.membershipDigest(ua, iu);
        bytes32 mdi = _mdInner(iu, _memberDigest(ua, UAKinds.PURPOSE_MEMBERSHIP, typed));
        IUARegistry.MemberSig memory slot = IUARegistry.MemberSig(iSlot, _leaves(di, mdi), "");

        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        reg.acceptMembership(ua, slot); // the inner has accepted nothing

        reg.acceptMembership(iu, _acceptKeySig(di, P256, keyP));
        reg.acceptMembership(iu, _acceptKeySig(di, ED, keyE));
        reg.acceptMembership(ua, slot);
        assertTrue(reg.memberAccepted(ua, iSlot));
        assertFalse(reg.memberAccepted(ua, 1 - iSlot));

        // the accepted weight 1 is below the threshold 2: nothing authorizes yet
        _refused(ua, du, _outerSigs(du, ua, iu, di, PK_B, DIGEST));
        reg.acceptMembership(ua, _acceptEoaSig(du, PK_B));
        _pass(ua, du, _outerSigs(du, ua, iu, di, PK_B, DIGEST));

        reg.acceptMembership(ua, IUARegistry.MemberSig(iSlot, noneInner, hex"dead")); // no-op
    }

    // ----- generations -----

    /// The outer on gen 2, the inner on gen 1: gen 2 hands the slot on under `member`, gen 1 checks its own structure, its accepted
    /// bits and its native members under its own domain.
    function test_innerHeldByGen1() public {
        (bytes memory di, bytes32 iu) = _inner(2, PK_A);
        UARegistry gen2 = _deploy(address(0x5ca2), chainUidA, address(reg), false, BUDGET, address(0), true, new UARegistry.KindConfig[](0));
        Member[] memory m = new Member[](2);
        m[0] = Member(UAKinds.MSIG, iu, 1);
        m[1] = Member(UAKinds.EVM_EOA, _eoa(PK_B), 1);
        bytes memory du = _msigKey(2, m);
        bytes32 ua = UACall.register(gen2, UAKinds.MSIG, du, _none(), "", "");
        uint16 iSlot = _indexOf(du, iu);
        gen2.acceptMembership(ua, _acceptEoaSig(du, PK_B));
        bytes32 typed = UAKinds.membershipDigest(ua, iu);
        gen2.acceptMembership(ua, IUARegistry.MemberSig(iSlot, _leaves(di, _mdInner(iu, _memberDigest(ua, UAKinds.PURPOSE_MEMBERSHIP, typed))), ""));

        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX, DIGEST);
        IUARegistry.MemberSig[] memory s = new IUARegistry.MemberSig[](2);
        s[iSlot] = IUARegistry.MemberSig(iSlot, _leaves(di, _mdInner(iu, md)), "");
        s[1 - iSlot] = IUARegistry.MemberSig(1 - iSlot, noneInner, _nativeSig(gen2, PK_B, UAKinds.PURPOSE_MEMBER, md));
        _req(gen2, ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(du, s));

        s[iSlot].members = _gen1NativeLeaves(reg, di, iu, md);
        _req(gen2, ua, UAKinds.PURPOSE_METATX, DIGEST, _msigAuth(du, s));
        s[iSlot].members = _gen1NativeLeaves(gen2, di, iu, md); // gen 2's domain, not the inner's
        bytes memory auth = _msigAuth(du, s);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        _req(gen2, ua, UAKinds.PURPOSE_METATX, DIGEST, auth);
    }

    /// The inner's EOA, under `domain`'s `UAAuth`, and its p256 member.
    function _gen1NativeLeaves(UARegistry domain, bytes memory di, bytes32 iu, bytes32 md)
        internal
        view
        returns (IUARegistry.InnerSig[] memory l)
    {
        bytes32 mdi = _mdInner(iu, md);
        (uint16 ia, uint16 ip) = (_indexOf(di, _eoa(PK_A)), _indexOf(di, idP));
        l = new IUARegistry.InnerSig[](2);
        (uint256 x, uint256 y) = ia < ip ? (0, 1) : (1, 0);
        l[x] = IUARegistry.InnerSig(ia, _nativeSig(domain, PK_A, UAKinds.PURPOSE_MEMBER, mdi));
        l[y] = IUARegistry.InnerSig(ip, _sig(keyP, UAKinds.uaMessage(P256, UAKinds.PURPOSE_MEMBER, mdi)));
    }

    // ----- the portable path: `pop`, KEM, the PQ eligibility -----

    function _pqRegistry() internal returns (UARegistry r, bytes[3] memory k, bytes32[3] memory id) {
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](2);
        c[0] = UARegistry.KindConfig(ML65, address(mock), 200_000);
        c[1] = UARegistry.KindConfig(P256, address(mock), 400_000);
        r = _deploy(address(0x5cb9), chainUidA, address(0), false, BUDGET, address(0), true, c);
        for (uint256 i; i < 3; ++i) {
            k[i] = new bytes(1952);
            k[i][0] = bytes1(uint8(i + 1));
            id[i] = UACall.register(r, ML65, k[i], _none(), _pop(r, ML65, k[i]), "");
        }
    }

    /// A PQ-eligible inner: {ml65 k0, ml65 k1, EOA a}, 2-of-3, its `pop` by the two ML-DSA slots, so the EOA's slot is not accepted.
    function _pqInner(UARegistry r, bytes[3] memory k, bytes32[3] memory id) internal returns (bytes memory d, bytes32 ua) {
        Member[] memory m = new Member[](3);
        m[0] = Member(ML65, id[0], 1);
        m[1] = Member(ML65, id[1], 1);
        m[2] = Member(UAKinds.EVM_EOA, _eoa(PK_A), 1);
        d = _msigKey(2, m);
        ua = UAKinds.uaOf(UAKinds.MSIG, d);
        bytes32 rd = _regDigest(ua, UAKinds.MSIG);
        IUARegistry.MemberSig[] memory s = _twoMl(d, id, k, _memberDigest(ua, UAKinds.PURPOSE_POP_V2, rd));
        assertEq(UACall.register(r, UAKinds.MSIG, d, _none(), abi.encode(s), ""), ua);
    }

    /// Slots of `k0` and `k1` in `d`, in index order, over `md`.
    function _twoMl(bytes memory d, bytes32[3] memory id, bytes[3] memory k, bytes32 md)
        internal
        view
        returns (IUARegistry.MemberSig[] memory s)
    {
        s = new IUARegistry.MemberSig[](2);
        (uint16 i0, uint16 i1) = (_indexOf(d, id[0]), _indexOf(d, id[1]));
        (uint256 x, uint256 y) = i0 < i1 ? (0, 1) : (1, 0);
        s[x] = IUARegistry.MemberSig(i0, noneInner, _sig(k[0], UAKinds.uaMessage(ML65, UAKinds.PURPOSE_MEMBER, md)));
        s[y] = IUARegistry.MemberSig(i1, noneInner, _sig(k[1], UAKinds.uaMessage(ML65, UAKinds.PURPOSE_MEMBER, md)));
    }

    struct Pq {
        UARegistry r;
        bytes[3] k;
        bytes32[3] id;
        bytes di;
        bytes32 iu;
        bytes du;
        bytes32 ua;
        uint16 iSlot;
        uint16 lSlot;
        bytes32 rd; // the registration digest
    }

    /// {`_pqInner`, ml65 k2}, 2-of-2, not registered.
    function _pqOuter() internal returns (Pq memory p) {
        (p.r, p.k, p.id) = _pqRegistry();
        (p.di, p.iu) = _pqInner(p.r, p.k, p.id);
        Member[] memory m = new Member[](2);
        m[0] = Member(UAKinds.MSIG, p.iu, 1);
        m[1] = Member(ML65, p.id[2], 1);
        p.du = _msigKey(2, m);
        p.ua = UAKinds.uaOf(UAKinds.MSIG, p.du);
        (p.iSlot, p.lSlot) = (_indexOf(p.du, p.iu), _indexOf(p.du, p.id[2]));
        p.rd = _regDigest(p.ua, UAKinds.MSIG);
    }

    /// `p`'s signature of a portable record: `rd` under `purpose`, the inner by `leaves`, the ML-DSA slot.
    function _pqSigs(Pq memory p, bytes32 purpose, bytes32 rd, IUARegistry.InnerSig[] memory leaves)
        internal
        view
        returns (IUARegistry.MemberSig[] memory s)
    {
        bytes32 md = _memberDigest(p.ua, purpose, rd);
        s = new IUARegistry.MemberSig[](2);
        s[p.iSlot] = IUARegistry.MemberSig(p.iSlot, leaves, "");
        s[p.lSlot] = IUARegistry.MemberSig(p.lSlot, noneInner, _sig(p.k[2], UAKinds.uaMessage(ML65, UAKinds.PURPOSE_MEMBER, md)));
    }

    function _pqMdi(Pq memory p, bytes32 purpose, bytes32 rd) internal pure returns (bytes32) {
        return _mdInner(p.iu, _memberDigest(p.ua, purpose, rd));
    }

    /// The outer's `pop` over its registration digest: the inner list signs under `member` over the chain; a native inner member signs
    /// the record's typed digest itself. Minimal at both levels; the `pop` exempts the outer's slots, not the inner's.
    function test_portablePopNested() public {
        Pq memory p = _pqOuter();
        p.r.acceptMembership(p.iu, _acceptEoaSig(p.di, PK_A));
        bytes32 mdi = _pqMdi(p, UAKinds.PURPOSE_POP_V2, p.rd);
        IUARegistry.MemberSig[] memory s =
            _pqSigs(p, UAKinds.PURPOSE_POP_V2, p.rd, _mixedLeaves(p.di, p.id, p.k, mdi, _ecdsa(PK_A, p.rd)));

        // the native inner member over the chain-bound `UAAuth`, not the typed digest: refused
        IUARegistry.MemberSig[] memory bad = _pqSigs(p, UAKinds.PURPOSE_POP_V2, p.rd,
            _mixedLeaves(p.di, p.id, p.k, mdi, _nativeSig(p.r, PK_A, UAKinds.PURPOSE_MEMBER, mdi)));
        vm.expectRevert(IUARegistry.UAPoP.selector);
        UACall.register(p.r, UAKinds.MSIG, p.du, _none(), abi.encode(bad), "");

        // a third inner signature: the inner level is minimal too
        bad = _pqSigs(p, UAKinds.PURPOSE_POP_V2, p.rd, _threeLeaves(p.di, p.id, p.k, mdi, _ecdsa(PK_A, p.rd)));
        vm.expectRevert(IUARegistry.UAPoP.selector);
        UACall.register(p.r, UAKinds.MSIG, p.du, _none(), abi.encode(bad), "");

        assertEq(UACall.register(p.r, UAKinds.MSIG, p.du, _none(), abi.encode(s), ""), p.ua);
        assertTrue(p.r.memberAccepted(p.ua, p.iSlot));
        assertTrue(p.r.memberAccepted(p.ua, p.lSlot));
        assertEq(p.r.popOf(p.ua), abi.encode(s), "the stored pop holds the inner list");
    }

    function test_popInnerSlotNeedsItsOwnAcceptance() public {
        Pq memory p = _pqOuter(); // the inner's EOA slot not accepted
        bytes32 mdi = _pqMdi(p, UAKinds.PURPOSE_POP_V2, p.rd);
        IUARegistry.MemberSig[] memory s =
            _pqSigs(p, UAKinds.PURPOSE_POP_V2, p.rd, _mixedLeaves(p.di, p.id, p.k, mdi, _ecdsa(PK_A, p.rd)));
        vm.expectRevert(IUARegistry.UAPoP.selector);
        UACall.register(p.r, UAKinds.MSIG, p.du, _none(), abi.encode(s), "");
        p.r.acceptMembership(p.iu, _acceptEoaSig(p.di, PK_A));
        assertEq(UACall.register(p.r, UAKinds.MSIG, p.du, _none(), abi.encode(s), ""), p.ua);
    }

    /// `ml65 k0` then the EOA, in index order of `d`.
    function _mixedLeaves(bytes memory d, bytes32[3] memory id, bytes[3] memory k, bytes32 mdi, bytes memory eoaSig)
        internal
        pure
        returns (IUARegistry.InnerSig[] memory s)
    {
        (uint16 i0, uint16 ie) = (_indexOf(d, id[0]), _indexOf(d, _eoa(PK_A)));
        (uint256 x, uint256 y) = i0 < ie ? (0, 1) : (1, 0);
        s = new IUARegistry.InnerSig[](2);
        s[x] = IUARegistry.InnerSig(i0, _sig(k[0], UAKinds.uaMessage(ML65, UAKinds.PURPOSE_MEMBER, mdi)));
        s[y] = IUARegistry.InnerSig(ie, eoaSig);
    }

    /// All three slots of `_pqInner`'s structure, in index order.
    function _threeLeaves(bytes memory d, bytes32[3] memory id, bytes[3] memory k, bytes32 mdi, bytes memory eoaSig)
        internal
        pure
        returns (IUARegistry.InnerSig[] memory s)
    {
        s = new IUARegistry.InnerSig[](3);
        for (uint16 i; i < 3; ++i) {
            if (i == _indexOf(d, id[0])) s[i] = IUARegistry.InnerSig(i, _sig(k[0], UAKinds.uaMessage(ML65, UAKinds.PURPOSE_MEMBER, mdi)));
            else if (i == _indexOf(d, id[1])) s[i] = IUARegistry.InnerSig(i, _sig(k[1], UAKinds.uaMessage(ML65, UAKinds.PURPOSE_MEMBER, mdi)));
            else s[i] = IUARegistry.InnerSig(i, eoaSig);
        }
    }

    /// CTR-PQZ-12: an `msig` member counts as PQ weight iff it is PQ-eligible itself, else as classical weight.
    function test_pqEligibleCountsInnerByItsOwnRule() public {
        (UARegistry r, bytes[3] memory k, bytes32[3] memory id) = _pqRegistry();
        (, bytes32 pqInner) = _pqInner(r, k, id);
        // a classical inner: two EOAs
        Member[] memory c = new Member[](2);
        c[0] = Member(UAKinds.EVM_EOA, _eoa(PK_A), 1);
        c[1] = Member(UAKinds.EVM_EOA, _eoa(PK_B), 1);
        bytes memory dc = _msigKey(2, c);
        bytes32 classicalInner = UACall.register(r, UAKinds.MSIG, dc, _none(), "", "");
        IUARegistry.UAAttrs memory kem = UACall.attrs("", 0, _kemPk());

        // the classical inner weighs 2 of threshold 2 beside ml65 w1: classical-dominant, no KEM record
        Member[] memory m = new Member[](2);
        m[0] = Member(UAKinds.MSIG, classicalInner, 2);
        m[1] = Member(ML65, id[2], 1);
        bytes memory d = _msigKey(2, m);
        bytes32 ua = UAKinds.uaOf(UAKinds.MSIG, d);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKemHolder.selector, ua));
        UACall.register(r, UAKinds.MSIG, d, kem, "", "");
        assertEq(UACall.register(r, UAKinds.MSIG, d, _none(), "", ""), ua, "classical-dominant: an empty pop");

        // the same shape with the PQ-eligible inner: PQ-eligible, so an empty pop is refused
        m[0] = Member(UAKinds.MSIG, pqInner, 2);
        m[1] = Member(ML65, id[2], 1);
        d = _msigKey(2, m);
        vm.expectRevert(IUARegistry.UAPoP.selector);
        UACall.register(r, UAKinds.MSIG, d, _none(), "", "");
    }

    function _kemPk() internal pure returns (bytes memory pk) {
        pk = new bytes(1601);
        pk[0] = 0x01;
    }

    /// `setKemKey` on a nested `msig`: portable, minimal, stored with the inner list.
    function test_setKemKeyNested() public {
        Pq memory p = _pqOuter();
        p.r.acceptMembership(p.iu, _acceptEoaSig(p.di, PK_A));
        IUARegistry.MemberSig[] memory s = _pqSigs(p, UAKinds.PURPOSE_POP_V2, p.rd,
            _mixedLeaves(p.di, p.id, p.k, _pqMdi(p, UAKinds.PURPOSE_POP_V2, p.rd), _ecdsa(PK_A, p.rd)));
        UACall.register(p.r, UAKinds.MSIG, p.du, _none(), abi.encode(s), "");

        bytes memory pk = _kemPk();
        bytes32 rd = UAKinds.kemRecordDigest(p.ua, 1, pk);
        IUARegistry.UASig memory a;
        a.members = _pqSigs(p, UAKinds.PURPOSE_KEM, rd,
            _mixedLeaves(p.di, p.id, p.k, _pqMdi(p, UAKinds.PURPOSE_KEM, rd), _ecdsa(PK_A, rd)));
        p.r.setKemKey(p.ua, 1, UACall.kem(pk), a);
        (, bytes memory stored) = p.r.kemKeyAt(p.ua, 1);
        bytes memory want = abi.encode(a.members);
        assertEq(stored, want);
    }

    // ----- the encoding -----

    struct OldMemberSig {
        uint16 index;
        bytes keyData;
        bytes sig;
    }

    /// N2: `members` sits where `keyData` sat, and an empty array encodes as empty bytes do, so a flat signature's bytes do not change:
    /// every stored `pop` and every vector stays. Non-empty old `keyData` was refused anyway.
    function test_flatEncodingUnchanged() public pure {
        IUARegistry.MemberSig[] memory n = new IUARegistry.MemberSig[](2);
        OldMemberSig[] memory o = new OldMemberSig[](2);
        n[0].index = 1;
        n[0].sig = hex"aabb";
        n[1].index = 7;
        n[1].sig = new bytes(3309);
        (o[0].index, o[0].sig, o[1].index, o[1].sig) = (1, hex"aabb", 7, new bytes(3309));
        assertEq(abi.encode(n), abi.encode(o));
    }
}
