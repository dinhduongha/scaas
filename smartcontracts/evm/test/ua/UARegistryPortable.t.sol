// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UACall} from "./UACall.sol";
import {UARegistryBase} from "./UARegistryBase.sol";

/// UA-7 O1 (owner 2026-11-04; plan T66a): `requirePortable(ua, purposeTag, typedDigest, UASig)`, the registry's portable check view
/// a `PqChat` record takes. Stand-in verifiers (`MockVerifier`: the signature over (keyData, message) is their keccak), real ECDSA for
/// the native members. Every refusal next to its positive control, one change at a time.
contract UARegistryPortableTest is UARegistryBase {
    bytes32 internal constant TYPED = keccak256("scaas.ua.test.portable.typed"); // a record's typed digest (no chain context)
    uint256 internal constant SK = 0xA11CE;
    address internal constant REG_P = 0x5CA0000000000000000000000000000000000007;
    address internal constant REG_G2 = 0x5cA0000000000000000000000000000000000008;

    uint16[5] internal PQ = [UAKinds.MLDSA44, UAKinds.MLDSA65, UAKinds.FNDSA512, UAKinds.MLDSA87, UAKinds.FNDSA1024];
    UARegistry internal p; // the classical kinds of the base, the five PQ holder kinds, `msig`
    bytes internal d3; // `_msig3`'s structure, its id and its `mldsa65` key, for the tests that need more locals
    bytes32 internal u3;
    bytes internal ml3;

    function setUp() public override {
        super.setUp();
        UARegistry.KindConfig[] memory base = _cfgs(address(mock));
        UARegistry.KindConfig[] memory c = new UARegistry.KindConfig[](base.length + PQ.length);
        for (uint256 i; i < base.length; ++i) c[i] = base[i];
        for (uint256 i; i < PQ.length; ++i) c[base.length + i] = UARegistry.KindConfig(PQ[i], address(mock), 50_000);
        p = _deploy(REG_P, chainUidA, address(0), false, BUDGET, address(0), true, c);
    }

    // ----- fixtures -----

    /// A key of a PQ holder kind of its exact length (FN-DSA: its header byte, every coefficient 0 < q; ML-DSA: any bytes).
    function _pqKey(uint16 kind, uint8 seed) internal pure returns (bytes memory d) {
        uint256 n = kind == UAKinds.MLDSA44 ? 1312 : kind == UAKinds.MLDSA65 ? 1952 : kind == UAKinds.FNDSA512 ? 897
            : kind == UAKinds.MLDSA87 ? 2592 : 1793;
        d = new bytes(n);
        if (kind == UAKinds.FNDSA512 || kind == UAKinds.FNDSA1024) {
            d[0] = kind == UAKinds.FNDSA512 ? bytes1(0x09) : bytes1(0x0a);
            d[n - 1] = bytes1(seed); // the last coefficient's low bits: < q
        } else {
            for (uint256 i; i < n; ++i) d[i] = bytes1(uint8(i) ^ seed);
        }
    }

    function _portable(UARegistry r, bytes32 ua, bytes32 purpose, IUARegistry.UASig memory s) internal view {
        r.requirePortable(ua, purpose, TYPED, s);
    }

    function _refused(UARegistry r, bytes32 ua, bytes32 purpose, IUARegistry.UASig memory s) internal {
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        r.requirePortable(ua, purpose, TYPED, s);
    }

    /// A single key's `UASig` over `uaMessage(kind, purpose, TYPED)`.
    function _single(uint16 kind, bytes memory key, bytes32 purpose) internal pure returns (IUARegistry.UASig memory s) {
        s.signature = _sig(key, UAKinds.uaMessage(kind, purpose, TYPED));
    }

    /// A 2-of-3 over an EOA, `p256` and `mldsa65` (all weight 1): classical-dominant, so registered with an empty `pop`; every slot
    /// accepts by `acceptMembership` except `skip` (3 = none skipped).
    function _msig3(UARegistry r, uint256 skip) internal returns (bytes memory d, bytes32 ua, bytes memory ml) {
        ml = _pqKey(UAKinds.MLDSA65, 7);
        _register(r, UAKinds.MLDSA65, ml);
        _register(r, 0x0101, _key(0x0101));
        Member[] memory m = new Member[](3);
        m[0] = Member(UAKinds.EVM_EOA, _pad(vm.addr(SK)), 1);
        m[1] = Member(0x0101, UAKinds.uaOf(0x0101, _key(0x0101)), 1);
        m[2] = Member(UAKinds.MLDSA65, UAKinds.uaOf(UAKinds.MLDSA65, ml), 1);
        d = _msigKey(2, m);
        ua = UACall.register(r, UAKinds.MSIG, d, _none(), "", "");
        if (skip != 0) r.acceptMembership(ua, _acceptEoaSig(d, SK));
        if (skip != 1) r.acceptMembership(ua, _acceptKeySig(d, 0x0101, _key(0x0101)));
        if (skip != 2) r.acceptMembership(ua, _acceptKeySig(d, UAKinds.MLDSA65, ml));
    }

    /// The slot signature of `id` in `d` (an EOA, `p256` or the `mldsa65` key `ml`) over `purpose`: a derived member under `member`
    /// over the member digest, the EOA over `typed` itself (TS-D4) or, `uaAuth`, over its chain-bound `UAAuth` instead.
    function _slot(UARegistry r, bytes memory d, bytes32 ua, bytes32 id, bytes memory ml, bytes32 purpose, bool uaAuth)
        internal
        view
        returns (IUARegistry.MemberSig memory s)
    {
        bytes32 md = _memberDigest(ua, purpose, TYPED);
        s.index = _indexOf(d, id);
        if (id == _pad(vm.addr(SK))) {
            s.sig = uaAuth ? _nativeSig(r, SK, UAKinds.PURPOSE_MEMBER, md) : _ecdsa(SK, TYPED);
        } else if (id == UAKinds.uaOf(0x0101, _key(0x0101))) {
            s.sig = _sig(_key(0x0101), UAKinds.uaMessage(0x0101, UAKinds.PURPOSE_MEMBER, md));
        } else {
            s.sig = _sig(ml, UAKinds.uaMessage(UAKinds.MLDSA65, UAKinds.PURPOSE_MEMBER, md));
        }
    }

    /// The `members` of the slots of `ids`, sorted by index.
    function _members(UARegistry r, bytes memory d, bytes32 ua, bytes32[] memory ids, bytes memory ml, bytes32 purpose, bool uaAuth)
        internal
        view
        returns (IUARegistry.UASig memory s)
    {
        s.members = new IUARegistry.MemberSig[](ids.length);
        for (uint256 i; i < ids.length; ++i) s.members[i] = _slot(r, d, ua, ids[i], ml, purpose, uaAuth);
        for (uint256 i = 1; i < ids.length; ++i) {
            for (uint256 j = i; j > 0 && s.members[j - 1].index > s.members[j].index; --j) {
                (s.members[j - 1], s.members[j]) = (s.members[j], s.members[j - 1]);
            }
        }
    }

    function _ids(bytes32 a, bytes32 b) internal pure returns (bytes32[] memory l) {
        l = new bytes32[](2);
        (l[0], l[1]) = (a, b);
    }

    // ----- single keys -----

    /// Every PQ holder kind and a classical kind sign under `PURPOSE_PQCHAT`; the same signature under another purpose, and the
    /// kind's `kem` signature under `PURPOSE_PQCHAT` (purpose separation), are refused; `keyData` or `members` beside it too.
    function test_requirePortable_singleKeyEveryHolderKind() public {
        uint16[6] memory kinds = [PQ[0], PQ[1], PQ[2], PQ[3], PQ[4], uint16(0x0101)];
        for (uint256 i; i < kinds.length; ++i) {
            uint16 k = kinds[i];
            bytes memory key = k == 0x0101 ? _key(0x0101) : _pqKey(k, uint8(i + 1));
            bytes32 ua = _register(p, k, key);
            IUARegistry.UASig memory chat = _single(k, key, UAKinds.PURPOSE_PQCHAT);
            _portable(p, ua, UAKinds.PURPOSE_PQCHAT, chat);
            IUARegistry.UASig memory kem = _single(k, key, UAKinds.PURPOSE_KEM);
            _portable(p, ua, UAKinds.PURPOSE_KEM, kem); // its own purpose: the control
            _refused(p, ua, UAKinds.PURPOSE_PQCHAT, kem);
            _refused(p, ua, UAKinds.PURPOSE_KEM, chat);
            IUARegistry.UASig memory s = chat;
            s.keyData = key;
            _refused(p, ua, UAKinds.PURPOSE_PQCHAT, s);
            s = _single(k, key, UAKinds.PURPOSE_PQCHAT);
            s.members = new IUARegistry.MemberSig[](1);
            _refused(p, ua, UAKinds.PURPOSE_PQCHAT, s);
        }
    }

    /// `PURPOSE_POP_V2` (the registration's own check) and a chain-bound purpose are refused, though the signature verifies over
    /// them: `requireAuthorized` takes the `metatx` one, `register` took the `pop`.
    function test_requirePortable_purposes() public {
        bytes memory key = _pqKey(UAKinds.FNDSA512, 9);
        bytes32 ua = _register(p, UAKinds.FNDSA512, key);
        IUARegistry.UASig memory m = _single(UAKinds.FNDSA512, key, UAKinds.PURPOSE_METATX);
        p.requireAuthorized(ua, UAKinds.PURPOSE_METATX, TYPED, m);
        _refused(p, ua, UAKinds.PURPOSE_METATX, m);
        IUARegistry.UASig memory pop = _single(UAKinds.FNDSA512, key, UAKinds.PURPOSE_POP_V2);
        _refused(p, ua, UAKinds.PURPOSE_POP_V2, pop);
        IUARegistry.UASig memory pq = _single(UAKinds.FNDSA512, key, UAKinds.PURPOSE_PQZ_KEY);
        _portable(p, ua, UAKinds.PURPOSE_PQZ_KEY, pq);
        assertEq(UAKinds.PURPOSE_PQCHAT, keccak256("scaas.ua.purpose.pqchat.v1"));
    }

    /// An unregistered id and a native id are refused: a native id signs chain-bound only, so neither its `UAAuth` signature (which
    /// `requireAuthorized` takes) nor an ECDSA over the typed digest passes.
    function test_requirePortable_unregisteredAndNative() public {
        bytes memory key = _pqKey(UAKinds.MLDSA44, 3);
        bytes32 none = UAKinds.uaOf(UAKinds.MLDSA44, key);
        _refused(p, none, UAKinds.PURPOSE_PQCHAT, _single(UAKinds.MLDSA44, key, UAKinds.PURPOSE_PQCHAT));
        bytes32 eoa = _pad(vm.addr(SK));
        IUARegistry.UASig memory s;
        s.signature = _nativeSig(p, SK, UAKinds.PURPOSE_PQCHAT, TYPED);
        p.requireAuthorized(eoa, UAKinds.PURPOSE_PQCHAT, TYPED, s);
        _refused(p, eoa, UAKinds.PURPOSE_PQCHAT, s);
        s.signature = _ecdsa(SK, TYPED);
        _refused(p, eoa, UAKinds.PURPOSE_PQCHAT, s);
    }

    // ----- msig -----

    /// A classical-dominant `msig` (registered with an empty `pop`) signs by its accepted members: every 2-slot subset passes, the EOA
    /// over the typed digest. Refused: the EOA's chain-bound `UAAuth` instead (which `requireAuthorized` takes), one slot, an empty
    /// list, three slots (past the threshold), the slots out of order, `signature` beside the list.
    function test_requirePortable_msig() public {
        (d3, u3, ml3) = _msig3(p, 3);
        (bytes32 e, bytes32 k1, bytes32 k2) =
            (_pad(vm.addr(SK)), UAKinds.uaOf(0x0101, _key(0x0101)), UAKinds.uaOf(UAKinds.MLDSA65, ml3));
        bytes32 chat = UAKinds.PURPOSE_PQCHAT;
        _portable(p, u3, chat, _m3(_ids(e, k1), chat, false));
        _portable(p, u3, chat, _m3(_ids(e, k2), chat, false));
        _portable(p, u3, chat, _m3(_ids(k1, k2), chat, false));
        IUARegistry.UASig memory bound = _m3(_ids(e, k1), chat, true);
        p.requireAuthorized(u3, chat, TYPED, bound);
        _refused(p, u3, chat, bound);
        IUARegistry.UASig memory two = _m3(_ids(e, k1), chat, false);
        IUARegistry.UASig memory s;
        s.members = new IUARegistry.MemberSig[](1);
        s.members[0] = two.members[0];
        _refused(p, u3, chat, s);
        _refused(p, u3, chat, IUARegistry.UASig("", "", new IUARegistry.MemberSig[](0)));
        bytes32[] memory all = new bytes32[](3);
        (all[0], all[1], all[2]) = (e, k1, k2);
        _refused(p, u3, chat, _m3(all, chat, false));
        s.members = new IUARegistry.MemberSig[](2);
        (s.members[0], s.members[1]) = (two.members[1], two.members[0]);
        _refused(p, u3, chat, s);
        two.signature = hex"01";
        _refused(p, u3, chat, two);
        // purpose separation at the member level: the slots signed for `kem`
        _refused(p, u3, chat, _m3(_ids(e, k1), UAKinds.PURPOSE_KEM, false));
    }

    /// `_members` of the structure `_msig3` left in storage.
    function _m3(bytes32[] memory ids, bytes32 purpose, bool uaAuth) internal view returns (IUARegistry.UASig memory) {
        return _members(p, d3, u3, ids, ml3, purpose, uaAuth);
    }

    /// CTR-UA-37: a good signature of a slot that is listed but not accepted is refused, and passes once the slot accepts.
    function test_requirePortable_msigUnacceptedSlot() public {
        (bytes memory d, bytes32 ua, bytes memory ml) = _msig3(p, 1);
        IUARegistry.UASig memory s =
            _members(p, d, ua, _ids(_pad(vm.addr(SK)), UAKinds.uaOf(0x0101, _key(0x0101))), ml, UAKinds.PURPOSE_PQCHAT, false);
        _refused(p, ua, UAKinds.PURPOSE_PQCHAT, s);
        p.acceptMembership(ua, _acceptKeySig(d, 0x0101, _key(0x0101)));
        _portable(p, ua, UAKinds.PURPOSE_PQCHAT, s);
    }

    /// The minimal form (owner 2026-10-31, U8S-D1): a 2-of-(1, 2) whose weight-1 slot comes first, both slots signing, is refused
    /// though its threshold is met (the old rule: 1, then 3 >= 2); the weight-2 slot alone passes.
    function test_requirePortable_msigNotMinimal() public {
        _register(p, 0x0101, _key(0x0101));
        _register(p, 0x0102, _key(0x0102));
        (bytes32 a, bytes32 b) = (UAKinds.uaOf(0x0101, _key(0x0101)), UAKinds.uaOf(0x0102, _key(0x0102)));
        (uint16 lo, uint16 hi) = a < b ? (uint16(0x0101), uint16(0x0102)) : (uint16(0x0102), uint16(0x0101));
        Member[] memory m = new Member[](2);
        m[0] = Member(lo, UAKinds.uaOf(lo, _key(lo)), 1); // the lower id: index 0, weight 1
        m[1] = Member(hi, UAKinds.uaOf(hi, _key(hi)), 2);
        bytes memory d = _msigKey(2, m);
        bytes32 ua = UACall.register(p, UAKinds.MSIG, d, _none(), "", ""); // classical: an empty pop
        p.acceptMembership(ua, _acceptKeySig(d, lo, _key(lo)));
        p.acceptMembership(ua, _acceptKeySig(d, hi, _key(hi)));
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_PQCHAT, TYPED);
        IUARegistry.UASig memory s;
        s.members = new IUARegistry.MemberSig[](2);
        s.members[0] = IUARegistry.MemberSig(0, new IUARegistry.InnerSig[](0), _sig(_key(lo), UAKinds.uaMessage(lo, UAKinds.PURPOSE_MEMBER, md)));
        s.members[1] = IUARegistry.MemberSig(1, new IUARegistry.InnerSig[](0), _sig(_key(hi), UAKinds.uaMessage(hi, UAKinds.PURPOSE_MEMBER, md)));
        p.requireAuthorized(ua, UAKinds.PURPOSE_PQCHAT, TYPED, s); // a transaction authorisation keeps the old rule
        _refused(p, ua, UAKinds.PURPOSE_PQCHAT, s);
        IUARegistry.UASig memory heavy;
        heavy.members = new IUARegistry.MemberSig[](1);
        heavy.members[0] = s.members[1];
        _portable(p, ua, UAKinds.PURPOSE_PQCHAT, heavy);
    }

    // ----- generations -----

    /// UA8-D11: a gen 2 forwards a record gen 1 holds and returns gen 1's verdict, a refusal as gen 1's `UAUnauthorized(ua)`; an `msig`
    /// gen 2 holds, over gen-1 members, is checked by gen 2 (its derived members handed to gen 1).
    function test_requirePortable_gen2() public {
        (bytes memory d, bytes32 ua, bytes memory ml) = _msig3(p, 3);
        UARegistry g2 = _deploy(REG_G2, chainUidA, address(p), false, BUDGET, address(0), true, new UARegistry.KindConfig[](0));
        bytes32 chat = UAKinds.PURPOSE_PQCHAT;
        bytes32[] memory two = _ids(_pad(vm.addr(SK)), UAKinds.uaOf(0x0101, _key(0x0101)));
        _portable(g2, ua, chat, _members(p, d, ua, two, ml, chat, false));
        _refused(g2, ua, chat, _members(p, d, ua, two, ml, chat, true));
        bytes32 single = UAKinds.uaOf(UAKinds.MLDSA65, ml);
        _portable(g2, single, chat, _single(UAKinds.MLDSA65, ml, chat));
        _refused(g2, single, chat, _single(UAKinds.MLDSA65, ml, UAKinds.PURPOSE_KEM));
        _refused(g2, keccak256("unregistered"), chat, _single(UAKinds.MLDSA65, ml, chat));
        _gen2Msig(g2, ml);
    }

    /// An `msig` gen 2 holds, over the gen-1 `mldsa65` member and the EOA, threshold 1: gen 2 checks it, its derived member handed to gen 1.
    function _gen2Msig(UARegistry g2, bytes memory ml) internal {
        bytes32 single = UAKinds.uaOf(UAKinds.MLDSA65, ml);
        Member[] memory m = new Member[](2);
        m[0] = Member(UAKinds.EVM_EOA, _pad(vm.addr(SK)), 1);
        m[1] = Member(UAKinds.MLDSA65, single, 1);
        bytes memory d2 = _msigKey(1, m);
        bytes32 u2 = UACall.register(g2, UAKinds.MSIG, d2, _none(), "", "");
        g2.acceptMembership(u2, _acceptKeySig(d2, UAKinds.MLDSA65, ml));
        bytes32[] memory one = new bytes32[](1);
        one[0] = single;
        _portable(g2, u2, UAKinds.PURPOSE_PQCHAT, _members(g2, d2, u2, one, ml, UAKinds.PURPOSE_PQCHAT, false));
        _refused(g2, u2, UAKinds.PURPOSE_PQCHAT, _members(g2, d2, u2, one, ml, UAKinds.PURPOSE_KEM, false));
    }
}
