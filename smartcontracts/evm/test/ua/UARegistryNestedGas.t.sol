// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UARegistryLib} from "../../src/ua/UARegistryLib.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {UARegistryBase} from "./UARegistryBase.sol";
import {UACall} from "./UACall.sol";
import {BurnAll} from "./UAGas.t.sol";

/// Calls `target` giving its frame exactly `gas`; returns the outcome and the revert data.
contract FrameProbe {
    function probe(address target, bytes calldata data, uint256 gas) external returns (bool ok, bytes memory ret) {
        (ok, ret) = target.call{gas: gas}(data);
    }
}

/// Nested `msig` gas (spec `2026-11-02-msig-nested.md`): `requireAuthorized`'s least frame gas at the worst case of each PQ kind, one
/// level and two, every capped call burning its whole cap, every signature of the kind's real length, every member's record its own
/// cold account and slots, under `--isolate` (each probe a transaction of its own). Each case is registered exactly at its bound:
/// `bound - 1` refused, `bound` accepted, `bound` gas authorizes, one gas under the least frame gas is a starvation, never a verdict.
/// ML-DSA rows take the path of a key read from the record (the precompile path); the cached path reads 2 slots instead of 1,952 B.
contract UARegistryNestedGasTest is UARegistryBase {
    uint256 internal constant MEMBER = UARegistryLib.MSIG_MEMBER_GAS;
    uint256 internal constant ACCEPTED = UARegistryLib.MSIG_ACCEPTED_GAS;
    uint256 internal constant SMART = 400_000;

    struct Case {
        string name;
        uint16 kind;
        uint64 cap;
        uint256 sigLen;
        uint256 plain; // signing slots of the outer
        uint256[] groups; // the inner `msig`s, each its threshold, its signing slots
        uint256 spare; // slots each inner lists beyond its threshold (its key data's length, no signature)
    }

    FrameProbe internal fp;
    IUARegistry.InnerSig[] internal noneInner;
    uint256 internal salt;
    uint256 internal nextAt = 0x5d0000;

    function setUp() public override {
        super.setUp();
        fp = new FrameProbe();
    }

    // ----- keys -----

    /// A distinct valid key of `kind`: a point's x for `bip340`; length alone for ML-DSA and SLH-DSA; FN-DSA `0x09 ‖` bytes 0 / 1 keep every 14-bit `h_i` < 12289.
    function _pk(uint16 kind) internal returns (bytes memory k) {
        uint256 n = ++salt;
        if (kind == 0x0103) return abi.encodePacked(bytes32(vm.createWallet(n).publicKeyX));
        if (kind == 0x0133) return abi.encodePacked(keccak256(abi.encode("key", n)));
        k = new bytes(kind == 0x0130 ? 1312 : (kind == 0x0131 ? 1952 : 897));
        if (kind == 0x0132) k[0] = 0x09;
        for (uint256 i; i < 32; ++i) k[i + 1] = bytes1(uint8(n >> i & 1));
    }

    // ----- the structures -----

    function _uints(uint256 a) internal pure returns (uint256[] memory r) {
        r = new uint256[](1);
        r[0] = a;
    }

    function _uints(uint256 a, uint256 n) internal pure returns (uint256[] memory r) {
        r = new uint256[](n);
        for (uint256 i; i < n; ++i) r[i] = a;
    }

    function _none256() internal pure returns (uint256[] memory r) {}

    function _config(Case memory c) internal returns (UARegistry.KindConfig[] memory k, address burn) {
        burn = address(new BurnAll());
        k = new UARegistry.KindConfig[](1);
        k[0] = UARegistry.KindConfig(c.kind, burn, c.cap);
    }

    /// The registered inner `msig` of `n` fresh signing slots, n-of-n, its `pop` of all of them (BurnAll accepts anything).
    function _inner(UARegistry r, Case memory c, uint256 n) internal returns (bytes memory d, bytes32 ua) {
        Member[] memory m = new Member[](n + c.spare);
        for (uint256 i; i < m.length; ++i) {
            m[i] = Member(c.kind, UACall.register(r, c.kind, _pk(c.kind), _none(), hex"01", ""), 1);
        }
        d = _msigKey(uint16(n), m);
        bool pq = c.kind >= 0x0130;
        IUARegistry.MemberSig[] memory s = _flat(n, c.sigLen);
        ua = UACall.register(r, UAKinds.MSIG, d, _none(), pq ? abi.encode(s) : bytes(""), "");
        if (!pq) {
            for (uint256 i; i < n; ++i) r.acceptMembership(ua, s[i]);
        }
    }

    function _flat(uint256 n, uint256 sigLen) internal view returns (IUARegistry.MemberSig[] memory s) {
        s = new IUARegistry.MemberSig[](n);
        bytes memory sig = new bytes(sigLen);
        for (uint16 i; i < n; ++i) s[i] = IUARegistry.MemberSig(i, noneInner, sig);
    }

    /// The outer's members for `c` on `r`, every inner registered; the inner lists by outer id afterwards in `_sigs`.
    function _outerKey(UARegistry r, Case memory c) internal returns (bytes memory d) {
        uint256 g = c.groups.length;
        Member[] memory m = new Member[](c.plain + g);
        for (uint256 i; i < c.plain; ++i) {
            m[i] = Member(c.kind, UACall.register(r, c.kind, _pk(c.kind), _none(), hex"01", ""), 1);
        }
        for (uint256 i; i < g; ++i) {
            (, bytes32 iu) = _inner(r, c, c.groups[i]);
            m[c.plain + i] = Member(UAKinds.MSIG, iu, 1);
        }
        d = _msigKey(uint16(m.length), m);
    }

    /// Every slot signs: an `msig` slot its whole inner list.
    function _sigs(UARegistry r, Case memory c, bytes memory d) internal view returns (IUARegistry.MemberSig[] memory s) {
        IUARegistry.MsigStructure memory st = r.msigOf(UAKinds.uaOf(UAKinds.MSIG, d));
        s = new IUARegistry.MemberSig[](st.members.length);
        bytes memory sig = new bytes(c.sigLen);
        for (uint16 i; i < s.length; ++i) {
            if (st.members[i].kind != UAKinds.MSIG) {
                s[i] = IUARegistry.MemberSig(i, noneInner, sig);
                continue;
            }
            uint256 n = r.msigOf(st.members[i].id).threshold;
            IUARegistry.InnerSig[] memory l = new IUARegistry.InnerSig[](n);
            for (uint16 j; j < n; ++j) l[j] = IUARegistry.InnerSig(j, sig);
            s[i] = IUARegistry.MemberSig(i, l, "");
        }
    }

    /// `pop` of the outer before it exists: its slots from the key data alone.
    function _popSigs(UARegistry r, Case memory c, bytes memory d) internal view returns (IUARegistry.MemberSig[] memory s) {
        IUARegistry.MsigStructure memory st = UACall.structure(d);
        s = new IUARegistry.MemberSig[](st.members.length);
        bytes memory sig = new bytes(c.sigLen);
        for (uint16 i; i < s.length; ++i) {
            if (st.members[i].kind != UAKinds.MSIG) {
                s[i] = IUARegistry.MemberSig(i, noneInner, sig);
                continue;
            }
            uint256 n = r.msigOf(st.members[i].id).threshold;
            IUARegistry.InnerSig[] memory l = new IUARegistry.InnerSig[](n);
            for (uint16 j; j < n; ++j) l[j] = IUARegistry.InnerSig(j, sig);
            s[i] = IUARegistry.MemberSig(i, l, "");
        }
    }

    function _leaves(Case memory c) internal pure returns (uint256 n) {
        n = c.plain;
        for (uint256 i; i < c.groups.length; ++i) n += c.groups[i];
    }

    /// `_membersWorst` of `c`, gen 1: Σ (cap + MEMBER) per signature, MEMBER + ACCEPTED per inner `msig`, ACCEPTED, the hold above 400 k.
    function _bound(Case memory c) internal pure returns (uint256 b) {
        b = _leaves(c) * (c.cap + MEMBER) + c.groups.length * (MEMBER + ACCEPTED) + ACCEPTED;
        if (c.cap > SMART) b += (c.cap - SMART) / 63;
    }

    // ----- one case -----

    function _at() internal returns (address a) {
        a = address(uint160(nextAt));
        nextAt += 2;
    }

    /// Registers `c` at `bound - 1` (refused) and `bound`, authorizes, reports. Returns the least frame gas.
    function _run(Case memory c) internal returns (uint256 least) {
        uint256 bound = _bound(c);
        (UARegistry tight, UARegistry r) = _pair(c, bound);
        uint256 s0 = salt;
        bytes memory d = _outerKey(tight, c);
        salt = s0; // the same keys, the same ids
        assertEq(_outerKey(r, c), d);
        IUARegistry.MemberSig[] memory pop = _popSigs(r, c, d);
        least = _measure(c, r, d, _registerAt(tight, r, c, d, pop), bound);
    }

    function _pair(Case memory c, uint256 bound) internal returns (UARegistry tight, UARegistry r) {
        (UARegistry.KindConfig[] memory k,) = _config(c);
        tight = _deploy(_at(), chainUidA, address(0), false, uint64(bound - 1), address(0), true, k);
        r = _deploy(_at(), chainUidA, address(0), false, uint64(bound), address(0), true, k);
    }

    function _measure(Case memory c, UARegistry r, bytes memory d, bytes32 ua, uint256 bound) internal returns (uint256 least) {
        IUARegistry.UASig memory a;
        a.members = _sigs(r, c, d);
        bytes memory call = abi.encodeCall(IUARegistry.requireAuthorized, (ua, UAKinds.PURPOSE_METATX, DIGEST, a));
        least = _least(address(r), call, bound);
        emit log_string(string.concat(
            c.name, " | sigs ", vm.toString(_leaves(c)), " | inner ", vm.toString(c.groups.length), " | bound ", vm.toString(bound),
            " | least ", vm.toString(least), " | margin ", vm.toString(bound - least), " | calldata ", vm.toString(call.length)
        ));
    }

    /// The outer: refused at `tight`, registered at `r`, every slot accepted (a PQ-eligible outer by its `pop`, a classical one with an
    /// empty `pop`, slot by slot).
    function _registerAt(UARegistry tight, UARegistry r, Case memory c, bytes memory d, IUARegistry.MemberSig[] memory pop)
        internal
        returns (bytes32 ua)
    {
        bytes memory p = c.kind >= 0x0130 ? abi.encode(pop) : bytes("");
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        UACall.register(tight, UAKinds.MSIG, d, _none(), p, "");
        ua = UACall.register(r, UAKinds.MSIG, d, _none(), p, "");
        if (c.kind < 0x0130) {
            for (uint256 i; i < pop.length; ++i) r.acceptMembership(ua, pop[i]);
        }
    }

    function _least(address r, bytes memory call, uint256 bound) internal returns (uint256 hi) {
        (bool ok,) = fp.probe(r, call, bound);
        assertTrue(ok, "authorizes with the bound");
        uint256 lo;
        for (hi = bound; hi - lo > 1;) {
            uint256 mid = (lo + hi) / 2;
            (ok,) = fp.probe(r, call, mid);
            if (ok) hi = mid;
            else lo = mid;
        }
        // one gas under the least: never a verdict (T-AUTH-4)
        bytes memory ret;
        (ok, ret) = fp.probe(r, call, hi - 1);
        assertFalse(ok);
        assertTrue(ret.length == 0 || bytes4(ret) == UAKinds.UAVerifyGas.selector, "a verdict from a starved frame");
    }

    function _case(string memory n, uint16 kind, uint64 cap, uint256 sigLen, uint256 plain, uint256[] memory g)
        internal
        pure
        returns (Case memory)
    {
        return Case(n, kind, cap, sigLen, plain, g, 0);
    }

    // ----- the table: 12 M -----

    function test_nested_mldsa65() public {
        _run(_case("mldsa65 1L", 0x0131, 5_950_000, 3309, 1, _none256()));
        _run(_case("mldsa65 2L", 0x0131, 5_950_000, 3309, 0, _uints(1)));
    }

    function test_nested_mldsa44() public {
        _run(_case("mldsa44 1L", 0x0130, 4_250_000, 2420, 2, _none256()));
        _run(_case("mldsa44 2L [2]", 0x0130, 4_250_000, 2420, 0, _uints(2)));
        _run(_case("mldsa44 2L [1,1]", 0x0130, 4_250_000, 2420, 0, _uints(1, 2)));
    }

    function test_nested_fndsa512() public {
        _run(_case("fndsa512 1L", 0x0132, 2_500_000, 666, 4, _none256()));
        _run(_case("fndsa512 2L [4]", 0x0132, 2_500_000, 666, 0, _uints(4)));
        _run(_case("fndsa512 2L [2,2]", 0x0132, 2_500_000, 666, 0, _uints(2, 2)));
        _run(_case("fndsa512 2L [1x4]", 0x0132, 2_500_000, 666, 0, _uints(1, 4)));
    }

    function test_nested_slhdsa128s() public {
        _run(_case("slhdsa128s 1L", 0x0133, 1_400_000, 7856, 8, _none256()));
        _run(_case("slhdsa128s 2L [8]", 0x0133, 1_400_000, 7856, 0, _uints(8)));
        _run(_case("slhdsa128s 2L [4,4]", 0x0133, 1_400_000, 7856, 0, _uints(4, 2)));
        _run(_case("slhdsa128s 2L [1x8]", 0x0133, 1_400_000, 7856, 0, _uints(1, 8)));
        _run(_case("slhdsa128s mixed 4 + [2,2]", 0x0133, 1_400_000, 7856, 4, _uints(2, 2)));
        _run(_case("slhdsa128s Hedera 2L [1x7]", 0x0133, 1_400_000, 7856, 0, _uints(1, 7)));
        Case memory wide = _case("slhdsa128s 2L [1x8], each inner listing 16", 0x0133, 1_400_000, 7856, 0, _uints(1, 8));
        wide.spare = 15;
        _run(wide);
    }

    function test_nested_mldsa65Precompile() public {
        _run(_case("mldsa65 200k 1L", 0x0131, 200_000, 3309, 16, _none256()));
        _run(_case("mldsa65 200k 2L [16x3]", 0x0131, 200_000, 3309, 0, _uints(16, 3)));
        uint256[] memory g = _uints(10, 5);
        (g[3], g[4]) = (9, 9);
        _run(_case("mldsa65 200k 2L [10,10,10,9,9]", 0x0131, 200_000, 3309, 0, g));
    }

    /// A kind of cap 50 k (`bip340`, the group kinds, an ERC-1271 member without a clone implementation): the most signatures any
    /// shape reaches at 12 M, the leaf path of a classical key read from its registration blob.
    function test_nested_mostSignatures() public {
        uint256[] memory g = _uints(16, 8);
        g[7] = 10;
        _run(_case("bip340 cap 50k 2L [16x7,10]", 0x0103, 50_000, 64, 0, g));
        _run(_case("bip340 cap 50k 1L", 0x0103, 50_000, 64, 16, _none256()));
    }

    // ----- the edges: one more is refused at the real budget -----

    function _refused(Case memory c, uint64 budget) internal {
        (UARegistry.KindConfig[] memory k,) = _config(c);
        UARegistry r = _deploy(_at(), chainUidA, address(0), false, budget, address(0), true, k);
        // inner `msig`s that fit on their own, the outer that does not
        bytes memory d = _outerKey(r, c);
        bytes memory pop = abi.encode(_popSigs(r, c, d));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        UACall.register(r, UAKinds.MSIG, d, _none(), pop, "");
    }

    function test_edges_oneMoreIsRefused() public {
        _refused(_case("mldsa65", 0x0131, 5_950_000, 3309, 0, _uints(1, 2)), 12_000_000);
        _refused(_case("mldsa44", 0x0130, 4_250_000, 2420, 0, _uints(1, 3)), 12_000_000);
        _refused(_case("fndsa512", 0x0132, 2_500_000, 666, 0, _uints(1, 5)), 12_000_000);
        _refused(_case("slhdsa128s", 0x0133, 1_400_000, 7856, 0, _uints(1, 9)), 12_000_000);
        _refused(_case("slhdsa128s Hedera", 0x0133, 1_400_000, 7856, 0, _uints(1, 8)), 10_500_000);
        uint256[] memory g = _uints(10, 5);
        g[4] = 9; // 49 signatures: the table's 48 at 5 inner `msig`s is the exact budget
        _refused(_case("mldsa65 200k", 0x0131, 200_000, 3309, 0, g), 12_000_000);
    }

    /// The structures the table reports as fitting fit the real budget, not just their own bound.
    function test_edges_fitTheBudget() public pure {
        Case[4] memory c = [
            _case("slh [1x8]", 0x0133, 1_400_000, 7856, 0, _uints(1, 8)),
            _case("fn [1x4]", 0x0132, 2_500_000, 666, 0, _uints(1, 4)),
            _case("ml65 200k", 0x0131, 200_000, 3309, 0, _uints(16, 3)),
            _case("cap 50k", 0x0103, 50_000, 64, 0, _uints(16, 7))
        ];
        for (uint256 i; i < 4; ++i) assertLe(_bound(c[i]), 12_000_000, c[i].name);
        assertLe(_bound(_case("slh Hedera", 0x0133, 1_400_000, 7856, 0, _uints(1, 7))), 10_500_000);
    }

    // ----- generations -----

    /// gen 2's bound of the outer `c` whose inner `msig`s and signing kind are gen 1's: a handed leaf counts `cap + cap / 63 + margin`,
    /// a handed inner `msig` the same again over its whole worst case.
    function _boundGen2(Case memory c) internal pure returns (uint256 b) {
        uint256 leaf = c.cap + c.cap / 63 + 5_000;
        b = ACCEPTED + c.plain * (leaf + MEMBER);
        for (uint256 i; i < c.groups.length; ++i) {
            uint256 w = c.groups[i] * (leaf + MEMBER) + ACCEPTED;
            b += w + w / 63 + 5_000 + MEMBER;
        }
        if (leaf > SMART) b += (leaf - SMART) / 63;
    }

    /// The outer on gen 2, everything else on gen 1, at `_boundGen2`.
    function test_nested_gen2() public {
        _runGen2(_case("gen 2 slhdsa128s [1x6]", 0x0133, 1_400_000, 7856, 0, _uints(1, 6)));
        _runGen2(_case("gen 2 slhdsa128s [3,3]", 0x0133, 1_400_000, 7856, 0, _uints(3, 2)));
        _runGen2(_case("gen 2 fndsa512 [2,2]", 0x0132, 2_500_000, 666, 0, _uints(2, 2)));
    }

    function _runGen2(Case memory c) internal {
        uint256 bound = _boundGen2(c);
        (UARegistry.KindConfig[] memory k,) = _config(c);
        UARegistry g1 = _deploy(_at(), chainUidA, address(0), false, 12_000_000, address(0), true, k);
        UARegistry.KindConfig[] memory none = new UARegistry.KindConfig[](0);
        UARegistry tight = _deploy(_at(), chainUidA, address(g1), false, uint64(bound - 1), address(0), true, none);
        UARegistry r = _deploy(_at(), chainUidA, address(g1), false, uint64(bound), address(0), true, none);
        bytes memory d = _outerKey(g1, c); // inner `msig`s and leaves on gen 1
        IUARegistry.MemberSig[] memory pop = _popSigs(g1, c, d);
        _measure(c, r, d, _registerAt(tight, r, c, d, pop), bound);
    }

    // ----- CTR-PQZ-12: the holder fits 2^24 with its authorization's calldata (review I1) -----

    /// `{fndsa512, inner of 16 ml65, inner of n ml65}`, n-of-n at both levels, ready for a PQZ key on a registry of caps 200 k and 2.5 M.
    function _bigHolder(uint256 n) internal returns (UARegistry r, bytes memory d, IUARegistry.MemberSig[] memory pop, IUARegistry.UAAttrs memory a) {
        Case memory c = _case("ml65", 0x0131, 200_000, 3309, 0, _none256());
        address burn = address(new BurnAll());
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](2);
        k[0] = UARegistry.KindConfig(0x0131, burn, 200_000);
        k[1] = UARegistry.KindConfig(0x0132, burn, 2_500_000);
        r = _deploy(_at(), chainUidA, address(0), false, 12_000_000, address(0), true, k);
        Member[] memory m = new Member[](3);
        m[0] = Member(0x0132, UACall.register(r, 0x0132, _pk(0x0132), _none(), hex"01", ""), 1);
        (, bytes32 i1) = _inner(r, c, 16);
        (, bytes32 i2) = _inner(r, c, n);
        m[1] = Member(UAKinds.MSIG, i1, 1);
        m[2] = Member(UAKinds.MSIG, i2, 1);
        d = _msigKey(3, m);
        pop = _popSigs(r, c, d);
        IUARegistry.MsigStructure memory st = UACall.structure(d);
        for (uint256 i; i < 3; ++i) if (st.members[i].kind == 0x0132) pop[i].sig = new bytes(666);
        bytes memory key = new bytes(PqzSet.PK);
        key[0] = 0x01;
        a = UACall.attrs(key, keccak256("proof"), "");
    }

    /// The registry's bound for that shape: its worst, the hold, the debit, 16 per byte.
    function _holderBound(uint256 n) internal pure returns (uint256 w, uint256 total) {
        w = (16 + n) * (200_000 + MEMBER) + (2_500_000 + MEMBER) + 2 * (MEMBER + ACCEPTED) + ACCEPTED + (2_500_000 - SMART) / 63;
        uint256 auth = (192 + 672) + 2 * 192 + (16 + n) * (128 + 3_328);
        total = w + w / 63 + 5_000 + PqzSet.PQZ_DEBIT_MIN_GAS + 16 * auth;
    }

    /// The review's `{fndsa512, [16, 12]}` was admitted, 17.44 M against 2^24. The largest shape of this family that registers now fits: the least
    /// frame + the debit + 16 per byte of the authorization, every byte counted non-zero; one signature more is refused.
    function test_pqzHolderFits2p24WithItsCalldata() public {
        uint256 n = 15;
        for (;; --n) {
            (, uint256 total) = _holderBound(n);
            if (total <= 1 << 24) break;
        }
        assertLt(n, 12, "the review's shape is refused");
        (UARegistry r, bytes memory d, IUARegistry.MemberSig[] memory pop, IUARegistry.UAAttrs memory a) = _bigHolder(n + 1);
        bytes memory p = abi.encode(pop);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzHolder.selector, UAKinds.uaOf(UAKinds.MSIG, d)));
        UACall.register(r, UAKinds.MSIG, d, a, p, "");

        (r, d, pop, a) = _bigHolder(n);
        bytes32 ua = UACall.register(r, UAKinds.MSIG, d, a, abi.encode(pop), "");
        IUARegistry.UASig memory s;
        s.members = pop;
        (uint256 w,) = _holderBound(n);
        uint256 least = _least(address(r), abi.encodeCall(IUARegistry.requireAuthorized, (ua, UAKinds.PURPOSE_METATX, DIGEST, s)), w);
        uint256 spend = least + PqzSet.PQZ_DEBIT_MIN_GAS + 16 * abi.encode(s).length;
        emit log_named_uint("signatures", 17 + n);
        emit log_named_uint("least + debit + 16 per auth byte", spend);
        assertLe(spend, 1 << 24);
    }

    /// The EIP-7976 floor, 64 per byte: a cheap-cap kind with long signatures meets it before the regular gas does.
    function test_pqzHolderCalldataFloor() public {
        address burn = address(new BurnAll());
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](1);
        k[0] = UARegistry.KindConfig(0x0133, burn, 20_000);
        UARegistry r = _deploy(_at(), chainUidA, address(0), false, 12_000_000, address(0), true, k);
        Case memory c = _case("slh", 0x0133, 20_000, 7856, 0, _none256());
        Member[] memory m = new Member[](2);
        (, bytes32 i1) = _inner(r, c, 16);
        (, bytes32 i2) = _inner(r, c, 16);
        m[0] = Member(UAKinds.MSIG, i1, 1);
        m[1] = Member(UAKinds.MSIG, i2, 1);
        bytes memory d = _msigKey(2, m);
        uint256 auth = 2 * 192 + 32 * (128 + 7_872);
        uint256 w = 32 * (20_000 + MEMBER) + 2 * (MEMBER + ACCEPTED) + ACCEPTED;
        assertLe(w + w / 63 + 5_000 + PqzSet.PQZ_DEBIT_MIN_GAS + 16 * auth, 1 << 24, "the regular term alone admits it");
        assertGt(PqzSet.PQZ_DEBIT_MIN_GAS + 64 * auth, 1 << 24);
        bytes memory key = new bytes(PqzSet.PK);
        key[0] = 0x01;
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAPqzHolder.selector, UAKinds.uaOf(UAKinds.MSIG, d)));
        UACall.register(r, UAKinds.MSIG, d, UACall.attrs(key, keccak256("proof"), ""), hex"01", "");
    }
}
