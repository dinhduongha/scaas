// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {VmSafe} from "forge-std/Vm.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UACall} from "./UACall.sol";
import {MockWallet, UARegistryBase} from "./UARegistryBase.sol";

/// The gas of one `memberAccepted` from a contract, the shape of `UARegistryLib._accepted` on a gen-2 host.
contract AcceptedProbe {
    function cost(UARegistry r, bytes32 ua, uint256 i) external view returns (uint256 cold, uint256 warm) {
        uint256 g = gasleft();
        r.memberAccepted(ua, i);
        cold = g - gasleft();
        g = gasleft();
        r.memberAccepted(ua, i);
        warm = g - gasleft();
    }
}

/// CTR-UA-37 (owner 2026-11-02): listing in `msigOf` is no consent, `memberAccepted` is; only accepted slots count at verify.
contract UARegistryMembershipTest is UARegistryBase {
    uint16 internal constant ML = 0x0131; // PQ, stored: an `msig` of these is PQ-eligible
    uint16 internal constant P256 = 0x0101; // classical, not stored
    uint256 internal constant ALICE = 0xA11CE;
    uint256 internal constant BOB = 0xB0B;
    address internal constant REG_M = 0x5cA0000000000000000000000000000000000002;
    address internal constant REG_N = 0x5Ca0000000000000000000000000000000000003;
    address internal constant REG_G2 = 0x5CA0000000000000000000000000000000000004;
    bytes32 internal constant TX_DIGEST = keccak256("a metatx digest");

    UARegistry internal r;
    bytes internal ml1;
    bytes internal ml2;
    bytes internal ml3;
    bytes internal p1;
    bytes internal p2;

    function setUp() public override {
        super.setUp();
        r = _deploy(REG_M, chainUidA, address(0), false, BUDGET, address(0), true, _pqCfgs());
        (ml1, ml2, ml3) = (_ml(1), _ml(2), _ml(3));
        (p1, p2) = (_key(P256), _key(0x0100));
        _members(r);
    }

    function _pqCfgs() internal view returns (UARegistry.KindConfig[] memory c) {
        UARegistry.KindConfig[] memory base = _cfgs(address(mock));
        c = new UARegistry.KindConfig[](base.length + 1);
        for (uint256 i; i < base.length; ++i) c[i] = base[i];
        c[base.length] = UARegistry.KindConfig(ML, address(mock), 400_000);
    }

    function _ml(uint256 salt) internal pure returns (bytes memory pk) {
        pk = new bytes(1952);
        for (uint256 i; i < pk.length; i += 32) {
            bytes32 w = keccak256(abi.encode(salt, i));
            for (uint256 j; j < 32 && i + j < pk.length; ++j) pk[i + j] = w[j];
        }
    }

    /// A scheme-1 KEM key of 1,601 B.
    function _kemPk(uint256 seed) internal pure returns (bytes memory pk) {
        pk = new bytes(UAKinds.KEM_PK_LENGTH);
        for (uint256 i; i < pk.length; ++i) pk[i] = bytes1(uint8(uint256(keccak256(abi.encode(seed, i)))));
        pk[0] = bytes1(UAKinds.KEM_SCHEME_MLKEM1024_X25519);
    }

    function _members(UARegistry x) internal {
        (_register(x, ML, ml1), _register(x, ML, ml2), _register(x, ML, ml3));
        (_register(x, P256, p1), _register(x, 0x0100, p2));
    }

    // ----- structures -----

    /// 2-of-(ml1, ml2, ml3): PQ-eligible.
    function _pqMsig() internal view returns (bytes memory d, bytes32 ua) {
        Member[] memory m = new Member[](3);
        m[0] = Member(ML, UAKinds.uaOf(ML, ml1), 1);
        m[1] = Member(ML, UAKinds.uaOf(ML, ml2), 1);
        m[2] = Member(ML, UAKinds.uaOf(ML, ml3), 1);
        d = _msigKey(2, m);
        ua = UAKinds.uaOf(UAKinds.MSIG, d);
    }

    /// 2-of-(EOA alice, p1, EOA bob): classical-dominant, empty `pop`.
    function _classical() internal view returns (bytes memory d, bytes32 ua) {
        Member[] memory m = new Member[](3);
        m[0] = Member(UAKinds.EVM_EOA, _pad(vm.addr(ALICE)), 1);
        m[1] = Member(P256, UAKinds.uaOf(P256, p1), 1);
        m[2] = Member(UAKinds.EVM_EOA, _pad(vm.addr(BOB)), 1);
        d = _msigKey(2, m);
        ua = UAKinds.uaOf(UAKinds.MSIG, d);
    }

    function _regMsig(UARegistry x, bytes memory d, bytes memory pop) internal returns (bytes32) {
        return UACall.register(x, UAKinds.MSIG, d, _none(), pop, "");
    }

    /// `MemberSig` of ML key `key` in `d` over `(purpose, digest)`, a transaction or a portable record alike.
    function _mlSig(bytes memory d, bytes memory key, bytes32 purpose, bytes32 digest)
        internal
        pure
        returns (IUARegistry.MemberSig memory)
    {
        bytes32 ua = UAKinds.uaOf(UAKinds.MSIG, d);
        bytes32 md = _memberDigest(ua, purpose, digest);
        return IUARegistry.MemberSig(_indexOf(d, UAKinds.uaOf(ML, key)), new IUARegistry.InnerSig[](0), _sig(key, UAKinds.uaMessage(ML, UAKinds.PURPOSE_MEMBER, md)));
    }

    /// `a`, `b` in index order, as a `UASig`.
    function _two(IUARegistry.MemberSig memory a, IUARegistry.MemberSig memory b)
        internal
        pure
        returns (IUARegistry.UASig memory s)
    {
        s.members = new IUARegistry.MemberSig[](2);
        (s.members[0], s.members[1]) = a.index < b.index ? (a, b) : (b, a);
    }

    function _pqPop(bytes memory d, bytes memory a, bytes memory b) internal pure returns (bytes memory) {
        bytes32 ua = UAKinds.uaOf(UAKinds.MSIG, d);
        bytes32 rd = _regDigest(ua, UAKinds.MSIG);
        return abi.encode(_two(_mlSig(d, a, UAKinds.PURPOSE_POP_V2, rd), _mlSig(d, b, UAKinds.PURPOSE_POP_V2, rd)).members);
    }

    /// The registered `pqMsig` by the `pop` of ml1 + ml2.
    function _pqRegistered(UARegistry x) internal returns (bytes memory d, bytes32 ua) {
        (d, ua) = _pqMsig();
        _regMsig(x, d, _pqPop(d, ml1, ml2));
    }

    function _txSig(bytes memory d, bytes memory a, bytes memory b) internal pure returns (IUARegistry.UASig memory) {
        return _two(_mlSig(d, a, UAKinds.PURPOSE_METATX, TX_DIGEST), _mlSig(d, b, UAKinds.PURPOSE_METATX, TX_DIGEST));
    }

    function _unauthorized(bytes32 ua) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua);
    }

    function _bits(UARegistry x, bytes32 ua) internal view returns (uint256) {
        return uint256(vm.load(address(x), keccak256(abi.encode(ua, uint256(15)))));
    }

    /// What the wallet shows and a client hashes (`clientkeys`), by hand.
    function test_membershipDigestByHand() public pure {
        (bytes32 ua, bytes32 member) = (keccak256("an msig"), keccak256("a member"));
        bytes32 th = keccak256("UAMembership(bytes32 ua,bytes32 member)");
        assertEq(UAKinds.UA_MEMBERSHIP_TYPEHASH, th);
        assertEq(th, 0x2ffb61cab130ef54f9af88d7255ca81c570651b2562c2c368286a1f43bfe5cb4);
        bytes32 ds = 0x9a2c390d4dc940ccdb5fa6b21e673e87159bdd99aeef22ea791bcea9efc64ca1;
        assertEq(UAKinds.membershipDigest(ua, member), keccak256(abi.encodePacked(hex"1901", ds, keccak256(abi.encode(th, ua, member)))));
        assertEq(UAKinds.PURPOSE_MEMBERSHIP, keccak256("scaas.ua.purpose.membership.v1"));
    }

    // ----- who accepts -----

    /// An EOA over the typed digest, submitted by a stranger; only its slot changes; the event names slot and member.
    function test_membershipNativeAccepts() public {
        (bytes memory d, bytes32 ua) = _classical();
        _regMsig(r, d, "");
        IUARegistry.MemberSig memory s = _acceptEoaSig(d, ALICE);
        assertFalse(r.memberAccepted(ua, s.index));
        vm.expectEmit(address(r));
        emit IUARegistry.UAMembershipAccepted(ua, s.index, _pad(vm.addr(ALICE)));
        vm.prank(address(0xDEAD));
        r.acceptMembership(ua, s);
        assertTrue(r.memberAccepted(ua, s.index));
        for (uint256 i; i < 3; ++i) assertEq(r.memberAccepted(ua, i), i == s.index);
    }

    /// A registered member under `member`, over `memberDigest`.
    function test_membershipRegisteredAccepts() public {
        (bytes memory d, bytes32 ua) = _classical();
        _regMsig(r, d, "");
        IUARegistry.MemberSig memory s = _acceptKeySig(d, P256, p1);
        vm.expectEmit(address(r));
        emit IUARegistry.UAMembershipAccepted(ua, s.index, UAKinds.uaOf(P256, p1));
        r.acceptMembership(ua, s);
        assertTrue(r.memberAccepted(ua, s.index));
    }

    /// A contract member answers ERC-1271 over the typed digest: the wallet sees that digest; a wallet that refuses, or answers
    /// for another signer, leaves the slot open.
    function test_membershipContractAccepts() public {
        address w = address(new MockWallet(vm.addr(ALICE), 0, 0, address(0)));
        Member[] memory m = new Member[](2);
        m[0] = Member(UAKinds.EVM_EOA, _pad(w), 1);
        m[1] = Member(P256, UAKinds.uaOf(P256, p1), 1);
        bytes memory d = _msigKey(2, m);
        bytes32 ua = _regMsig(r, d, "");
        uint16 i = _indexOf(d, _pad(w));
        bytes32 typed = UAKinds.membershipDigest(ua, _pad(w));
        bytes memory good = _ecdsa(ALICE, typed);
        vm.expectRevert(_unauthorized(ua));
        r.acceptMembership(ua, IUARegistry.MemberSig(i, new IUARegistry.InnerSig[](0), _ecdsa(BOB, typed)));
        assertFalse(r.memberAccepted(ua, i));
        vm.expectCall(w, abi.encodeWithSelector(IERC1271.isValidSignature.selector, typed, good));
        vm.expectEmit(address(r));
        emit IUARegistry.UAMembershipAccepted(ua, i, _pad(w));
        r.acceptMembership(ua, IUARegistry.MemberSig(i, new IUARegistry.InnerSig[](0), good));
        assertEq(_bits(r, ua), 1 << i);
    }

    // ----- the bitmap at registration -----

    /// A slot that signed the stored `pop` reads accepted with no call and no event; the other reads false. The same `pop`
    /// does it on every registry.
    function test_membershipPopSignersAccepted() public {
        (bytes memory d, bytes32 ua) = _pqRegistered(r);
        (uint16 a, uint16 b, uint16 c) = (_indexOf(d, UAKinds.uaOf(ML, ml1)), _indexOf(d, UAKinds.uaOf(ML, ml2)), _indexOf(d, UAKinds.uaOf(ML, ml3)));
        assertTrue(r.memberAccepted(ua, a));
        assertTrue(r.memberAccepted(ua, b));
        assertFalse(r.memberAccepted(ua, c));
        assertEq(_bits(r, ua), 1 << a | 1 << b, "the stored bits, slot 15");

        UARegistry x = _deploy(REG_N, keccak256("another chain"), address(0), false, BUDGET, address(0), true, _pqCfgs());
        _members(x);
        _regMsig(x, d, _pqPop(d, ml1, ml2));
        assertEq(_bits(x, ua), 1 << a | 1 << b);
    }

    /// A classical-dominant `msig` has no `pop`: registration writes nothing.
    function test_membershipEmptyPopWritesNothing() public {
        (bytes memory d, bytes32 ua) = _classical();
        _regMsig(r, d, "");
        assertEq(_bits(r, ua), 0);
        for (uint256 i; i < 3; ++i) assertFalse(r.memberAccepted(ua, i));
    }

    /// The registration's own `pop` is what accepts its signers: it verifies with no slot accepted, on a registry where
    /// nobody accepted anything.
    function test_membershipPopExempt() public {
        (bytes memory d, bytes32 ua) = _pqMsig();
        assertEq(_bits(r, ua), 0);
        assertEq(_regMsig(r, d, _pqPop(d, ml1, ml2)), ua);
    }

    // ----- only accepted members count -----

    /// Good signatures of the classical-dominant `msig`: refused until enough weight accepted, then the same call passes;
    /// an accepted slot next to an unaccepted one fails too.
    function test_membershipRefusedUntilEnoughWeight() public {
        (bytes memory d, bytes32 ua) = _classical();
        _regMsig(r, d, "");
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX, TX_DIGEST);
        IUARegistry.MemberSig memory a = IUARegistry.MemberSig(
            _indexOf(d, _pad(vm.addr(ALICE))), new IUARegistry.InnerSig[](0), _nativeSig(r, ALICE, UAKinds.PURPOSE_MEMBER, md));
        IUARegistry.MemberSig memory p = IUARegistry.MemberSig(
            _indexOf(d, UAKinds.uaOf(P256, p1)), new IUARegistry.InnerSig[](0), _sig(p1, UAKinds.uaMessage(P256, UAKinds.PURPOSE_MEMBER, md)));
        IUARegistry.UASig memory s = _two(a, p);
        vm.expectRevert(_unauthorized(ua));
        r.requireAuthorized(ua, UAKinds.PURPOSE_METATX, TX_DIGEST, s);
        r.acceptMembership(ua, _acceptEoaSig(d, ALICE));
        vm.expectRevert(_unauthorized(ua));
        r.requireAuthorized(ua, UAKinds.PURPOSE_METATX, TX_DIGEST, s);
        r.acceptMembership(ua, _acceptKeySig(d, P256, p1));
        r.requireAuthorized(ua, UAKinds.PURPOSE_METATX, TX_DIGEST, s);
    }

    /// `requireAuthorized` on the PQ-eligible `msig`: the `pop` signers pass; a good signature of the third slot does not,
    /// the same call passes after it accepts.
    function test_membershipUnacceptedRefusedRequireAuthorized() public {
        (bytes memory d, bytes32 ua) = _pqRegistered(r);
        r.requireAuthorized(ua, UAKinds.PURPOSE_METATX, TX_DIGEST, _txSig(d, ml1, ml2));
        IUARegistry.UASig memory s = _txSig(d, ml1, ml3);
        vm.expectRevert(_unauthorized(ua));
        r.requireAuthorized(ua, UAKinds.PURPOSE_METATX, TX_DIGEST, s);
        r.acceptMembership(ua, _acceptKeySig(d, ML, ml3));
        r.requireAuthorized(ua, UAKinds.PURPOSE_METATX, TX_DIGEST, s);
    }

    /// An unaccepted contract member: its wallet's good ERC-1271 answer does not count until it accepted.
    function test_membershipUnacceptedRefusedErc1271() public {
        address w = address(new MockWallet(vm.addr(ALICE), 0, 0, address(0)));
        Member[] memory m = new Member[](1);
        m[0] = Member(UAKinds.EVM_EOA, _pad(w), 1);
        bytes memory d = _msigKey(1, m);
        bytes32 ua = _regMsig(r, d, "");
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX, TX_DIGEST);
        IUARegistry.UASig memory s;
        s.members = new IUARegistry.MemberSig[](1);
        s.members[0] = IUARegistry.MemberSig(0, new IUARegistry.InnerSig[](0), _ecdsa(ALICE, r.uaAuthDigest(_pad(w), UAKinds.PURPOSE_MEMBER, md)));
        vm.expectRevert(_unauthorized(ua));
        r.requireAuthorized(ua, UAKinds.PURPOSE_METATX, TX_DIGEST, s);
        r.acceptMembership(ua, IUARegistry.MemberSig(0, new IUARegistry.InnerSig[](0), _ecdsa(ALICE, UAKinds.membershipDigest(ua, _pad(w)))));
        r.requireAuthorized(ua, UAKinds.PURPOSE_METATX, TX_DIGEST, s);
    }

    /// `setKemKey`: the same record signed with the unaccepted slot is refused, and lands after it accepts.
    function test_membershipUnacceptedRefusedSetKemKey() public {
        (bytes memory d, bytes32 ua) = _pqRegistered(r);
        bytes memory pk = _kemPk(1);
        bytes32 rd = UAKinds.kemRecordDigest(ua, 1, pk);
        IUARegistry.UASig memory s = _two(_mlSig(d, ml1, UAKinds.PURPOSE_KEM, rd), _mlSig(d, ml3, UAKinds.PURPOSE_KEM, rd));
        vm.expectRevert(_unauthorized(ua));
        r.setKemKey(ua, 1, UACall.kem(pk), s);
        r.acceptMembership(ua, _acceptKeySig(d, ML, ml3));
        r.setKemKey(ua, 1, UACall.kem(pk), s);
        (uint64 v,,) = r.kemKeyOf(ua);
        assertEq(v, 1);
    }

    /// `setPqzKey`: the same.
    function test_membershipUnacceptedRefusedSetPqzKey() public {
        (bytes memory d, bytes32 ua) = _pqRegistered(r);
        bytes memory key = new bytes(16_384);
        bytes32 hash = keccak256("proof");
        bytes32 rd = UAKinds.pqzKeyRecordDigest(ua, UAKinds.keyHashOf(UAKinds.PQZ_MLWE, key), hash);
        IUARegistry.UASig memory s = _two(_mlSig(d, ml1, UAKinds.PURPOSE_PQZ_KEY, rd), _mlSig(d, ml3, UAKinds.PURPOSE_PQZ_KEY, rd));
        vm.expectRevert(_unauthorized(ua));
        r.setPqzKey(ua, 0, key, hash, s);
        r.acceptMembership(ua, _acceptKeySig(d, ML, ml3));
        r.setPqzKey(ua, 0, key, hash, s);
        (, address ptr,,) = r.pqzKeyOf(ua);
        assertTrue(ptr != address(0));
    }

    // ----- refusals, each with its positive control -----

    /// Another member's signature for this slot.
    function test_membershipWrongMemberRefused() public {
        (bytes memory d, bytes32 ua) = _classical();
        _regMsig(r, d, "");
        IUARegistry.MemberSig memory s = _acceptEoaSig(d, ALICE);
        s.index = _indexOf(d, _pad(vm.addr(BOB)));
        vm.expectRevert(_unauthorized(ua));
        r.acceptMembership(ua, s);
        // bob's key over the digest of alice's slot: right signer, wrong `member`
        uint16 ia = _indexOf(d, _pad(vm.addr(ALICE)));
        vm.expectRevert(_unauthorized(ua));
        r.acceptMembership(ua, IUARegistry.MemberSig(ia, new IUARegistry.InnerSig[](0), _ecdsa(BOB, UAKinds.membershipDigest(ua, _pad(vm.addr(ALICE))))));
        // a derived member's digest names the member too
        uint16 ip = _indexOf(d, UAKinds.uaOf(P256, p1));
        vm.expectRevert(_unauthorized(ua));
        r.acceptMembership(ua, IUARegistry.MemberSig(ip, new IUARegistry.InnerSig[](0), _sig(p1, UAKinds.uaMessage(P256, UAKinds.PURPOSE_MEMBER, _membershipMd(ua, _pad(vm.addr(ALICE)))))));
        r.acceptMembership(ua, _acceptEoaSig(d, BOB));
        assertTrue(r.memberAccepted(ua, _indexOf(d, _pad(vm.addr(BOB)))));
    }

    /// An acceptance of the same member in another `msig`.
    function test_membershipWrongUaRefused() public {
        (bytes memory d, bytes32 ua) = _classical();
        _regMsig(r, d, "");
        Member[] memory m = new Member[](2);
        m[0] = Member(UAKinds.EVM_EOA, _pad(vm.addr(ALICE)), 1);
        m[1] = Member(P256, UAKinds.uaOf(P256, p1), 1);
        bytes memory d2 = _msigKey(2, m);
        bytes32 ua2 = _regMsig(r, d2, "");
        IUARegistry.MemberSig memory other = _acceptEoaSig(d2, ALICE);
        other.index = _indexOf(d, _pad(vm.addr(ALICE)));
        vm.expectRevert(_unauthorized(ua));
        r.acceptMembership(ua, other);
        IUARegistry.MemberSig memory otherKey = _acceptKeySig(d2, P256, p1);
        otherKey.index = _indexOf(d, UAKinds.uaOf(P256, p1));
        vm.expectRevert(_unauthorized(ua));
        r.acceptMembership(ua, otherKey);
        r.acceptMembership(ua2, _acceptEoaSig(d2, ALICE));
        r.acceptMembership(ua, _acceptEoaSig(d, ALICE));
    }

    /// An index past the members, the first such and the largest; the same signature at its own slot passes.
    function test_membershipIndexOutOfRangeRefused() public {
        (bytes memory d, bytes32 ua) = _classical();
        _regMsig(r, d, "");
        IUARegistry.MemberSig memory s = _acceptEoaSig(d, ALICE);
        uint16 own = s.index;
        for (uint256 i; i < 2; ++i) {
            s.index = i == 0 ? 3 : type(uint16).max;
            vm.expectRevert(_unauthorized(ua));
            r.acceptMembership(ua, s);
            assertEq(_bits(r, ua), 0);
        }
        // the bound alone refuses: past the members the member check reads junk, so here it would pass if it were reached
        vm.mockCall(address(r), abi.encodeWithSelector(IUARegistry.requireAuthorized.selector), "");
        s.index = 3;
        vm.expectRevert(_unauthorized(ua));
        r.acceptMembership(ua, s);
        vm.clearMockedCalls();
        assertEq(_bits(r, ua), 0);
        s.index = own;
        r.acceptMembership(ua, s);
    }

    /// A `pop`, `kem` or `pqz-key` member signature is no acceptance.
    function test_membershipRecordSigIsNoAcceptance() public {
        (bytes memory d, bytes32 ua) = _pqRegistered(r);
        bytes32 typed = UAKinds.membershipDigest(ua, UAKinds.uaOf(ML, ml3));
        bytes32[3] memory purposes = [UAKinds.PURPOSE_POP_V2, UAKinds.PURPOSE_KEM, UAKinds.PURPOSE_PQZ_KEY];
        for (uint256 i; i < 3; ++i) {
            for (uint256 j; j < 2; ++j) { // over the membership's own digest, and the record's
                IUARegistry.MemberSig memory s = _mlSig(d, ml3, purposes[i], j == 0 ? typed : _regDigest(ua, UAKinds.MSIG));
                vm.expectRevert(_unauthorized(ua));
                r.acceptMembership(ua, s);
            }
        }
        // the bare `member` purpose of a transaction, too
        vm.expectRevert(_unauthorized(ua));
        r.acceptMembership(ua, _mlSig(d, ml3, UAKinds.PURPOSE_METATX, typed));
        r.acceptMembership(ua, _acceptKeySig(d, ML, ml3));
    }

    /// A native member's typed `pop` signature is no acceptance.
    function test_membershipNativePopIsNoAcceptance() public {
        (bytes memory d, bytes32 ua) = _classical();
        _regMsig(r, d, "");
        uint16 i = _indexOf(d, _pad(vm.addr(ALICE)));
        vm.expectRevert(_unauthorized(ua));
        r.acceptMembership(ua, IUARegistry.MemberSig(i, new IUARegistry.InnerSig[](0), _ecdsa(ALICE, _regDigest(ua, UAKinds.MSIG))));
        r.acceptMembership(ua, _acceptEoaSig(d, ALICE));
    }

    /// An acceptance is no `pop`, no KEM record signature, no PQZ key record signature: the same two signatures that pass as
    /// acceptances are refused at each, and the record's own signatures pass there.
    function test_membershipAcceptanceIsNoRecordSig() public {
        (bytes memory d, bytes32 ua) = _pqMsig();
        IUARegistry.UASig memory s = _two(_acceptKeySig(d, ML, ml1), _acceptKeySig(d, ML, ml2));
        vm.expectRevert(IUARegistry.UAPoP.selector);
        r.registerMsig(UACall.structure(d), _none(), s.members, "");
        // the `pop` signed slots 1 and 3; the other acceptance must verify as one, so the two are real signatures
        _regMsig(r, d, _pqPop(d, ml1, ml3));
        uint16 i2 = _indexOf(d, UAKinds.uaOf(ML, ml2));
        assertFalse(r.memberAccepted(ua, i2));
        vm.expectEmit(address(r));
        emit IUARegistry.UAMembershipAccepted(ua, i2, UAKinds.uaOf(ML, ml2));
        r.acceptMembership(ua, _acceptKeySig(d, ML, ml2));
        assertTrue(r.memberAccepted(ua, i2));
        bytes memory pk = _kemPk(2);
        vm.expectRevert(_unauthorized(ua));
        r.setKemKey(ua, 1, UACall.kem(pk), s);
        bytes memory key = new bytes(16_384);
        vm.expectRevert(_unauthorized(ua));
        r.setPqzKey(ua, 0, key, keccak256("proof"), s);
        bytes32 rd = UAKinds.kemRecordDigest(ua, 1, pk);
        r.setKemKey(ua, 1, UACall.kem(pk), _two(_mlSig(d, ml1, UAKinds.PURPOSE_KEM, rd), _mlSig(d, ml2, UAKinds.PURPOSE_KEM, rd)));
        (uint64 v,,) = r.kemKeyOf(ua);
        assertEq(v, 1);
    }

    /// Non-empty `keyData`, native and derived (CTR-UA-33).
    function test_membershipKeyDataRefused() public {
        (bytes memory d, bytes32 ua) = _classical();
        _regMsig(r, d, "");
        IUARegistry.MemberSig memory n = _acceptEoaSig(d, ALICE);
        IUARegistry.MemberSig memory p = _acceptKeySig(d, P256, p1);
        n.members = UACall.aList();
        vm.expectRevert(_unauthorized(ua));
        r.acceptMembership(ua, n);
        p.members = UACall.aList();
        vm.expectRevert(_unauthorized(ua));
        r.acceptMembership(ua, p);
        (n.members, p.members) = (new IUARegistry.InnerSig[](0), new IUARegistry.InnerSig[](0));
        r.acceptMembership(ua, n);
        r.acceptMembership(ua, p);
    }

    /// A single-key record, an unregistered id, a native id: no `msig` here.
    function test_membershipNotAnMsigRefused() public {
        IUARegistry.MemberSig memory s;
        bytes32[3] memory ids = [UAKinds.uaOf(ML, ml1), keccak256("nobody"), _pad(vm.addr(ALICE))];
        for (uint256 i; i < 3; ++i) {
            vm.expectRevert(_unauthorized(ids[i]));
            r.acceptMembership(ids[i], s);
            assertFalse(r.memberAccepted(ids[i], 0));
        }
    }

    /// The record's kind decides, not the bytes: an `msig` structure under a record of another kind is refused with a good
    /// signature, and accepts once the record says `msig` again.
    function test_membershipKindReadFromTheRecord() public {
        (bytes memory d, bytes32 ua) = _classical();
        _regMsig(r, d, "");
        IUARegistry.MemberSig memory s = _acceptEoaSig(d, ALICE);
        bytes32 slot = keccak256(abi.encode(ua, uint256(0))); // `records`: kind in the low 16 bits
        bytes32 w = vm.load(address(r), slot);
        assertEq(uint16(uint256(w)), UAKinds.MSIG);
        vm.store(address(r), slot, bytes32(uint256(w) & ~uint256(0xffff) | P256));
        vm.expectRevert(_unauthorized(ua));
        r.acceptMembership(ua, s);
        vm.store(address(r), slot, w);
        r.acceptMembership(ua, s);
        assertTrue(r.memberAccepted(ua, s.index));
    }

    /// Accepting twice is a no-op: no event, no write; a `pop` signer's acceptance too.
    function test_membershipIdempotent() public {
        (bytes memory d, bytes32 ua) = _pqRegistered(r);
        IUARegistry.MemberSig memory s = _acceptKeySig(d, ML, ml3);
        r.acceptMembership(ua, s);
        uint256 bits = _bits(r, ua);
        vm.recordLogs();
        r.acceptMembership(ua, s);
        r.acceptMembership(ua, _acceptKeySig(d, ML, ml1));
        assertEq(vm.getRecordedLogs().length, 0, "no second event");
        assertEq(_bits(r, ua), bits);
    }

    /// The 16th slot, the top index of an `msig`, in the bitmap and at verify.
    function test_membershipTopSlot() public {
        Member[] memory m = new Member[](16);
        bytes[] memory keys_ = new bytes[](16);
        for (uint256 i; i < 16; ++i) {
            keys_[i] = _ml(100 + i);
            m[i] = Member(ML, _register(r, ML, keys_[i]), 1);
        }
        bytes memory d = _msigKey(2, m);
        bytes32 ua = _regMsig(r, d, _pqPop(d, keys_[0], keys_[1]));
        uint256 top;
        for (uint256 i; i < 16; ++i) if (_indexOf(d, UAKinds.uaOf(ML, keys_[i])) == 15) top = i;
        assertGt(top, 1, "the id at slot 15 is not one of the two `pop` signers");
        IUARegistry.UASig memory s = _txSig(d, keys_[0], keys_[top]);
        vm.expectRevert(_unauthorized(ua));
        r.requireAuthorized(ua, UAKinds.PURPOSE_METATX, TX_DIGEST, s);
        assertFalse(r.memberAccepted(ua, 15));
        r.acceptMembership(ua, _acceptKeySig(d, ML, keys_[top]));
        assertTrue(r.memberAccepted(ua, 15));
        assertEq(_bits(r, ua) >> 15, 1, "bit 15 and nothing above");
        assertFalse(r.memberAccepted(ua, 16));
        assertFalse(r.memberAccepted(ua, 255));
        assertFalse(r.memberAccepted(ua, 256), "past the word, no wrap");
        assertFalse(r.memberAccepted(ua, type(uint256).max));
        r.requireAuthorized(ua, UAKinds.PURPOSE_METATX, TX_DIGEST, s);
    }

    /// One acceptance, every registry: nothing of a chain or a registry in what is signed, and each registry checks it for itself:
    /// the bytes accepted on `r` accept on `x`, on another chain, and one flipped byte does not; `x` keeps its own bits.
    function test_membershipPortable() public {
        (bytes memory d, bytes32 ua) = _classical();
        UARegistry x = _deploy(REG_N, keccak256("another chain"), address(0), false, BUDGET, address(0), true, _pqCfgs());
        _members(x);
        _regMsig(r, d, "");
        _regMsig(x, d, "");
        IUARegistry.MemberSig memory n = _acceptEoaSig(d, ALICE);
        IUARegistry.MemberSig memory p = _acceptKeySig(d, P256, p1);
        r.acceptMembership(ua, n);
        r.acceptMembership(ua, p);
        assertEq(_bits(x, ua), 0, "a registry of its own");
        vm.chainId(7);
        assertEq(UAKinds.membershipDigest(ua, _pad(vm.addr(ALICE))), _acceptDigestOn31337(ua), "no chain in the digest");
        for (uint256 i; i < 2; ++i) {
            IUARegistry.MemberSig memory s = i == 0 ? n : p;
            bytes memory bad = abi.encodePacked(s.sig);
            bad[0] ^= 0x01;
            vm.expectRevert(_unauthorized(ua));
            x.acceptMembership(ua, IUARegistry.MemberSig(s.index, new IUARegistry.InnerSig[](0), bad));
            x.acceptMembership(ua, s);
        }
        assertEq(_bits(x, ua), _bits(r, ua));
        assertEq(_bits(x, ua), 1 << n.index | 1 << p.index);
    }

    /// The digest by hand, with the domain's constant: the same words whatever `block.chainid` is.
    function _acceptDigestOn31337(bytes32 ua) internal view returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", UAKinds.PORTABLE_DOMAIN_SEPARATOR,
            keccak256(abi.encode(UAKinds.UA_MEMBERSHIP_TYPEHASH, ua, _pad(vm.addr(ALICE))))));
    }

    // ----- a gen-2 registry in front of a gen-1 record (as `setKemKey`, UA8-D11) -----

    function _gen2(bool pqz) internal returns (UARegistry) {
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](pqz ? 1 : 0);
        if (pqz) c[0] = UARegistry.KindConfig(UAKinds.PQZ_MLWE, address(mock), 400_000);
        return _deploy(REG_G2, chainUidA, address(r), false, BUDGET, address(0), true, c);
    }

    /// The acceptance goes to the generation that holds the record; gen 2 reads it there, and its forwarded verify counts it.
    function test_membershipGen2HoldsNoGen1Acceptance() public {
        (bytes memory d, bytes32 ua) = _pqRegistered(r);
        UARegistry g = _gen2(false);
        IUARegistry.MemberSig memory s = _acceptKeySig(d, ML, ml3);
        vm.expectRevert(_unauthorized(ua));
        g.acceptMembership(ua, s);
        assertFalse(g.memberAccepted(ua, s.index));
        vm.expectRevert(_unauthorized(ua));
        g.requireAuthorized(ua, UAKinds.PURPOSE_METATX, TX_DIGEST, _txSig(d, ml1, ml3));
        r.acceptMembership(ua, s);
        assertTrue(g.memberAccepted(ua, s.index));
        g.requireAuthorized(ua, UAKinds.PURPOSE_METATX, TX_DIGEST, _txSig(d, ml1, ml3));
    }

    /// `setPqzKey` on a gen 2 that hosts a gen-1 record checks gen 1's bitmap: the record's acceptances live with the record.
    function test_membershipGen2HostReadsGen1Bits() public {
        (bytes memory d, bytes32 ua) = _pqRegistered(r);
        UARegistry g = _gen2(true);
        bytes memory key = new bytes(16_384);
        bytes32 hash = keccak256("proof");
        bytes32 rd = UAKinds.pqzKeyRecordDigest(ua, UAKinds.keyHashOf(UAKinds.PQZ_MLWE, key), hash);
        IUARegistry.UASig memory s = _two(_mlSig(d, ml1, UAKinds.PURPOSE_PQZ_KEY, rd), _mlSig(d, ml3, UAKinds.PURPOSE_PQZ_KEY, rd));
        vm.expectRevert(_unauthorized(ua));
        g.setPqzKey(ua, 0, key, hash, s);
        r.acceptMembership(ua, _acceptKeySig(d, ML, ml3));
        g.setPqzKey(ua, 0, key, hash, s);
    }

    // ----- starvation (T-AUTH-4: a starved caller sees `UAVerifyGas`, never a verdict) -----

    /// Gen 1's bits out of reach on a gen-2 host: `UAVerifyGas`, not a refusal and not an empty revert.
    function test_membershipGen2HostStarvedIsVerifyGas() public {
        (bytes memory d, bytes32 ua) = _pqRegistered(r);
        UARegistry g = _gen2(true);
        bytes memory key = new bytes(16_384);
        bytes32 hash = keccak256("proof");
        bytes32 rd = UAKinds.pqzKeyRecordDigest(ua, UAKinds.keyHashOf(UAKinds.PQZ_MLWE, key), hash);
        IUARegistry.UASig memory s = _two(_mlSig(d, ml1, UAKinds.PURPOSE_PQZ_KEY, rd), _mlSig(d, ml2, UAKinds.PURPOSE_PQZ_KEY, rd));
        vm.mockCallRevert(address(r), abi.encodeWithSelector(IUARegistry.memberAccepted.selector), "");
        vm.expectRevert(UAKinds.UAVerifyGas.selector);
        g.setPqzKey(ua, 0, key, hash, s);
        vm.clearMockedCalls();
        g.setPqzKey(ua, 0, key, hash, s);
    }

    /// A member starved in its own check at `acceptMembership`: `UAVerifyGas`, the slot stays open, with gas it accepts.
    function test_membershipStarvedMemberIsVerifyGas() public {
        address w = address(new MockWallet(vm.addr(ALICE), 0, 0, address(0)));
        Member[] memory m = new Member[](1);
        m[0] = Member(UAKinds.EVM_EOA, _pad(w), 1);
        bytes memory d = _msigKey(1, m);
        bytes32 ua = _regMsig(r, d, "");
        IUARegistry.MemberSig memory s = IUARegistry.MemberSig(0, new IUARegistry.InnerSig[](0), _ecdsa(ALICE, UAKinds.membershipDigest(ua, _pad(w))));
        bytes memory call_ = abi.encodeCall(r.acceptMembership, (ua, s));
        (bool ok, bytes memory ret) = address(r).call{gas: 60_000}(call_);
        assertFalse(ok);
        assertEq(bytes4(ret), UAKinds.UAVerifyGas.selector);
        assertFalse(r.memberAccepted(ua, 0));
        (ok,) = address(r).call{gas: 2_000_000}(call_); // 2 M: the kept signature is a contract, state gas (owner 2026-11-03)
        assertTrue(ok);
        assertTrue(r.memberAccepted(ua, 0));
    }

    // ----- the cost -----

    function _reads(VmSafe.AccountAccess[] memory a, bytes32 slot) internal pure returns (uint256 n) {
        for (uint256 i; i < a.length; ++i) {
            VmSafe.StorageAccess[] memory sa = a[i].storageAccesses;
            for (uint256 j; j < sa.length; ++j) if (sa[j].slot == slot && !sa[j].isWrite) ++n;
        }
    }

    /// A gen 2 hosting a gen-1 record asks gen 1 per slot: this path's real cost, a write paying its own gas outside `verifyBudget`.
    function test_membershipGen2HostCallCost() public {
        (bytes memory d, bytes32 ua) = _pqRegistered(r);
        UARegistry g = _gen2(true);
        uint16 i = _indexOf(d, UAKinds.uaOf(ML, ml1));
        vm.cool(address(r));
        (uint256 cold, uint256 warm) = new AcceptedProbe().cost(r, ua, i);
        emit log_named_uint("gen 1 memberAccepted, first slot (cold)", cold);
        emit log_named_uint("gen 1 memberAccepted, next slot (warm)", warm);
        assertLt(cold, 6_500, "measured 6,055");
        assertLt(warm, 1_500, "measured 1,146");
        assertTrue(g.memberAccepted(ua, i));
    }

    /// Authorizing, and a stored record's signature, read the one bitmap slot once, however many members sign.
    function test_membershipVerifyReadsOneSlot() public {
        (bytes memory d, bytes32 ua) = _pqRegistered(r);
        bytes32 slot = keccak256(abi.encode(ua, uint256(15)));
        vm.startStateDiffRecording();
        r.requireAuthorized(ua, UAKinds.PURPOSE_METATX, TX_DIGEST, _txSig(d, ml1, ml2));
        assertEq(_reads(vm.stopAndReturnStateDiff(), slot), 1, "requireAuthorized");
        bytes memory pk = _kemPk(3);
        bytes32 rd = UAKinds.kemRecordDigest(ua, 1, pk);
        IUARegistry.UASig memory s = _two(_mlSig(d, ml1, UAKinds.PURPOSE_KEM, rd), _mlSig(d, ml2, UAKinds.PURPOSE_KEM, rd));
        vm.startStateDiffRecording();
        r.setKemKey(ua, 1, UACall.kem(pk), s);
        assertEq(_reads(vm.stopAndReturnStateDiff(), slot), 1, "setKemKey");
    }
}
