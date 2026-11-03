// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm, VmSafe} from "forge-std/Vm.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UARegistryLib} from "../../src/ua/UARegistryLib.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UARegistryBase, MockVerifier, MockWallet} from "./UARegistryBase.sol";
import {UACall} from "./UACall.sol";
import {GasMeter} from "./GroupFixtures.sol";

/// A stand-in with the ML-DSA cache interface: `PRECOMPILE` as given, the parts derived from the key.
contract CacheVerifier is MockVerifier {
    address public immutable PRECOMPILE;

    constructor(address precompile) MockVerifier(0, 0) {
        PRECOMPILE = precompile;
    }

    function expandedKeyPart(bytes calldata pk, uint256 part) external pure returns (bytes memory) {
        return abi.encode(keccak256(pk), part);
    }

    function verifyCached(bytes calldata chunks, bytes32 message, bytes calldata sig) external pure returns (bool) {
        return sig.length == 32 && bytes32(sig) == keccak256(abi.encode(chunks, message));
    }
}

/// What `legacy/msig-nested/test/ua/UARegistrySplit.t.sol` held that still applies once `MemberSig` has no `keyData`: its differentials
/// compared the pre-split source, which no longer compiles (spec 2026-11-02-msig-nested §10). `UARegistryLib._msig`'s own guards, which
/// the `requireAuthorized` tests reach only on the registry's copy; the nested-offset note; the hot path, against the figures of the
/// last commit where the differential ran.
contract UARegistryLibMsigTest is UARegistryBase {
    address internal constant R1 = 0x5cA00000000000000000000000000000000000a1;
    address internal constant R2 = 0x5ca00000000000000000000000000000000000A2;
    address internal constant R8 = 0x5ca00000000000000000000000000000000000a8;
    uint64 internal constant PQ = 1_000_000;
    uint256 internal constant ALICE = 0xA11CE;
    uint16 internal constant ML44 = 0x0130;
    uint16 internal constant ML65 = 0x0131;
    uint16 internal constant FN = 0x0132;
    uint16 internal constant SLH = 0x0133;

    GasMeter internal gm;

    function setUp() public override {
        super.setUp();
        gm = new GasMeter();
    }

    function _pk(uint16 kind, uint256 salt) internal pure returns (bytes memory pk) {
        uint256 len = kind == ML44 ? 1312 : kind == ML65 ? 1952 : kind == FN ? 897 : kind == SLH ? 32 : 18_432;
        pk = new bytes(len);
        for (uint256 i; i < len; i += 32) {
            bytes32 w = keccak256(abi.encode(kind, salt, i));
            for (uint256 j; j < 32 && i + j < len; ++j) pk[i + j] = w[j];
        }
        if (kind == FN) {
            pk[0] = 0x09;
            for (uint256 i = 1; i < len; ++i) pk[i] = 0;
            pk[1] = bytes1(uint8(salt)); // FN-DSA h: only its length is checked here, the salt keeps ids apart
        }
    }

    /// One key data per kind of kinds.json `valid`, `msig` left out.
    function _rows() internal view returns (uint16[] memory k, bytes[] memory d) {
        string memory j = _kindsJson();
        uint256[] memory all = abi.decode(vm.parseJson(j, ".valid[*].kind"), (uint256[]));
        k = new uint16[](all.length);
        d = new bytes[](all.length);
        uint256 n;
        for (uint256 i; i < all.length; ++i) {
            bool seen = all[i] == UAKinds.MSIG;
            for (uint256 m; m < n; ++m) seen = seen || k[m] == all[i];
            if (seen) continue;
            k[n] = uint16(all[i]);
            d[n++] = vm.parseJsonBytes(j, string.concat(".valid[", vm.toString(i), "].keyData"));
        }
        assembly ("memory-safe") {
            mstore(k, n)
            mstore(d, n)
        }
    }

    function _keyOf(uint16 want) internal view returns (bytes memory) {
        (uint16[] memory k, bytes[] memory d) = _rows();
        for (uint256 i; i < k.length; ++i) if (k[i] == want) return d[i];
        revert("no row");
    }

    /// Every kind of `_rows`, each with its own verifier.
    function _all() internal returns (UARegistry.KindConfig[] memory c) {
        (uint16[] memory k,) = _rows();
        c = new UARegistry.KindConfig[](k.length);
        for (uint256 i; i < k.length; ++i) {
            address v = k[i] == ML44 || k[i] == ML65 ? address(new CacheVerifier(address(0))) : address(new MockVerifier(0, 0));
            c[i] = UARegistry.KindConfig(k[i], v, k[i] >= 0x0110 ? PQ : _cap(k[i]));
        }
    }

    function _one(uint16 kind, address v, uint64 cap) internal pure returns (UARegistry.KindConfig[] memory c) {
        c = new UARegistry.KindConfig[](1);
        c[0] = UARegistry.KindConfig(kind, v, cap);
    }

    function _plain(uint16 kind, bytes memory d) internal pure returns (bytes memory) {
        return UACall.registerCall(kind, d, _none(), _pop(UARegistry(address(0)), kind, d), "");
    }

    function _msigCall(bytes memory d, bytes memory pop) internal pure returns (bytes memory) {
        return UACall.registerCall(UAKinds.MSIG, d, _none(), pop, "");
    }

    function _word(bytes memory d, uint256 o) internal pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(d, 32), o))
        }
    }

    // ----- `UARegistryLib._msig`, on a registration's `pop` -----

    /// EOA, `ML44`, `FN`, weights 1: two PQ members of a threshold of 2, so PQ-eligible, so its `pop` is `_msig`'s.
    function _pqMsig(address at) internal returns (bytes memory d, bytes32 ua, bytes memory ml, bytes memory fn) {
        _deploy(at, chainUidA, address(0), false, BUDGET, address(0), true, _all());
        (ml, fn) = (_pk(ML44, 11), _keyOf(FN));
        Member[] memory m = new Member[](3);
        m[0] = Member(UAKinds.EVM_EOA, _pad(vm.addr(ALICE)), 1);
        m[1] = Member(ML44, UAKinds.uaOf(ML44, ml), 1);
        m[2] = Member(FN, UAKinds.uaOf(FN, fn), 1);
        d = _msigKey(2, m);
        ua = UAKinds.uaOf(UAKinds.MSIG, d);
        (bool ok,) = at.call(_plain(ML44, ml));
        assertTrue(ok, "ML44");
        (ok,) = at.call(_plain(FN, fn));
        assertTrue(ok, "FN");
    }

    function _member(bytes memory d, bytes32 id, bytes memory sig) internal pure returns (IUARegistry.MemberSig memory) {
        return IUARegistry.MemberSig(_indexOf(d, id), new IUARegistry.InnerSig[](0), sig);
    }

    function _sorted(IUARegistry.MemberSig[] memory s) internal pure returns (IUARegistry.MemberSig[] memory) {
        for (uint256 i = 1; i < s.length; ++i) {
            for (uint256 j = i; j > 0 && s[j - 1].index > s[j].index; --j) (s[j - 1], s[j]) = (s[j], s[j - 1]);
        }
        return s;
    }

    /// Every member's slot over `rd`, in index order.
    function _slots(bytes memory d, bytes32 ua, bytes32 rd, bytes memory ml, bytes memory fn)
        internal
        pure
        returns (IUARegistry.MemberSig[] memory s)
    {
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_POP_V2, rd);
        s = new IUARegistry.MemberSig[](3);
        s[0] = _member(d, _pad(vm.addr(ALICE)), _ecdsa(ALICE, rd));
        s[1] = _member(d, UAKinds.uaOf(FN, fn), _sig(fn, UAKinds.uaMessage(FN, UAKinds.PURPOSE_MEMBER, md)));
        s[2] = _member(d, UAKinds.uaOf(ML44, ml), _sig(ml, UAKinds.uaMessage(ML44, UAKinds.PURPOSE_MEMBER, md)));
        _sorted(s);
    }

    function _two(IUARegistry.MemberSig memory a, IUARegistry.MemberSig memory b)
        internal
        pure
        returns (IUARegistry.MemberSig[] memory s)
    {
        s = new IUARegistry.MemberSig[](2);
        (s[0], s[1]) = (a, b);
    }

    /// The first two slots by index that can sign: what `registerMsig` accepts.
    function _good(IUARegistry.MemberSig[] memory all) internal pure returns (IUARegistry.MemberSig[] memory) {
        return _two(all[0], all[1]);
    }

    /// The call, and every call it made out of the registry and its library (kind, callee, calldata), in order: a verification that
    /// should not have happened is seen here even when the verdict stays `UAPoP`.
    function _run(address at, bytes memory data) internal returns (bool ok, bytes memory ret, bytes32 calls, uint256 n) {
        vm.startStateDiffRecording();
        vm.stopAndReturnStateDiff(); // a recording's first use also holds what came before it
        vm.startStateDiffRecording();
        (ok, ret) = at.call(data);
        VmSafe.AccountAccess[] memory d = vm.stopAndReturnStateDiff();
        for (uint256 i; i < d.length; ++i) {
            bool isCall = d[i].kind == VmSafe.AccountAccessKind.Call || d[i].kind == VmSafe.AccountAccessKind.StaticCall;
            if (!isCall || d[i].account == at || d[i].account == address(UARegistryLib)) continue;
            calls = keccak256(abi.encode(calls, d[i].kind, d[i].account, d[i].data));
            ++n;
        }
    }

    /// `data` is refused with `UAPoP` having asked exactly what `control` asked: nothing past the slot that failed.
    function _refusedAs(address at, bytes memory data, bytes memory control, string memory label) internal {
        uint256 snap = vm.snapshotState();
        (,, bytes32 want, uint256 n) = _run(at, control);
        vm.revertToState(snap);
        (bool ok, bytes memory ret, bytes32 calls, uint256 m) = _run(at, data);
        assertFalse(ok, label);
        assertEq(ret, abi.encodeWithSelector(IUARegistry.UAPoP.selector), label);
        assertGt(n, 0, label);
        assertEq(m, n, string.concat(label, ": calls out"));
        assertEq(calls, want, string.concat(label, ": the same calls"));
    }

    function _refusedPop(bytes memory d, bytes memory pop, string memory label) internal {
        (bool ok, bytes memory ret) = R1.call(_msigCall(d, pop));
        assertFalse(ok, label);
        assertEq(ret, abi.encodeWithSelector(IUARegistry.UAPoP.selector), label);
    }

    /// One change each from the `pop` that passes in the last line.
    function test_libMsig_popRows() public {
        (bytes memory d, bytes32 ua, bytes memory ml, bytes memory fn) = _pqMsig(R1);
        bytes memory good = abi.encode(_good(_slots(d, ua, _regDigest(ua, UAKinds.MSIG), ml, fn)));
        _refusedPop(d, "", "no pop");
        _refusedPop(d, abi.encode(_good(_slots(d, ua, keccak256("other"), ml, fn))), "another digest");
        IUARegistry.MemberSig[] memory s = UACall.memberSigs(good);
        (s[0], s[1]) = (s[1], s[0]);
        _refusedPop(d, abi.encode(s), "out of order");
        s = UACall.memberSigs(good);
        s[0].members = UACall.aList();
        _refusedPop(d, abi.encode(s), "a list on a signing member");
        s = new IUARegistry.MemberSig[](1);
        s[0] = UACall.memberSigs(good)[0];
        _refusedPop(d, abi.encode(s), "below the threshold");
        (bool ok,) = R1.call(_msigCall(d, good));
        assertTrue(ok, "the pop that passes");
        assertEq(UARegistry(R1).kindOf(ua), UAKinds.MSIG);
    }

    /// A valid `MemberSig` after the threshold: the stop keeps the registration bound sound, so the third slot is never verified.
    function test_libMsig_stopsAtTheThreshold() public {
        (bytes memory d, bytes32 ua, bytes memory ml, bytes memory fn) = _pqMsig(R1);
        IUARegistry.MemberSig[] memory all = _slots(d, ua, _regDigest(ua, UAKinds.MSIG), ml, fn);
        _refusedAs(R1, _msigCall(d, abi.encode(all)), _msigCall(d, abi.encode(_good(all))), "after the threshold");
    }

    /// The same member twice: refused at the second slot, which is never verified.
    function test_libMsig_sameMemberTwice() public {
        (bytes memory d, bytes32 ua, bytes memory ml, bytes memory fn) = _pqMsig(R1);
        IUARegistry.MemberSig[] memory all = _slots(d, ua, _regDigest(ua, UAKinds.MSIG), ml, fn);
        IUARegistry.MemberSig[] memory one = new IUARegistry.MemberSig[](1);
        one[0] = all[0];
        _refusedAs(R1, _msigCall(d, abi.encode(_two(all[0], all[0]))), _msigCall(d, abi.encode(one)), "the same member twice");
    }

    /// An index past the members: refused before anything reads past the structure. A check that let it through would still end in
    /// `UAPoP`; only the calls show it.
    function test_libMsig_indexPastTheMembers() public {
        (bytes memory d, bytes32 ua, bytes memory ml, bytes memory fn) = _pqMsig(R1);
        bytes32 rd = _regDigest(ua, UAKinds.MSIG);
        IUARegistry.MemberSig[] memory all = _slots(d, ua, rd, ml, fn);
        IUARegistry.MemberSig[] memory one = new IUARegistry.MemberSig[](1);
        one[0] = all[0];
        IUARegistry.MemberSig memory past = IUARegistry.MemberSig(3, new IUARegistry.InnerSig[](0), _ecdsa(ALICE, rd));
        _refusedAs(R1, _msigCall(d, abi.encode(_two(all[0], past))), _msigCall(d, abi.encode(one)), "an index past the members");
    }

    // ----- malformed calldata -----

    /// `good` with the `pqzKey` offset of the `UAAttrs` at `attrs` aimed at the calldata byte `aim`.
    function _aimed(bytes memory good, uint256 attrs, uint256 aim) internal pure returns (bytes memory bad) {
        bad = bytes.concat(good);
        bytes32 rel = bytes32(aim - attrs);
        assembly ("memory-safe") {
            mstore(add(add(bad, 32), attrs), rel)
        }
    }

    /// An offset inside a struct is checked where it is read, and in the library the calldata is 96 B longer than the entry's. A `pqzKey`
    /// offset aimed at the appended clone word (0 here) reads as the empty key, which is what the well-formed call has: the same record,
    /// nothing the caller could not send. Aimed past those 96 B it is past the calldata, and refused.
    function test_nestedOffsetReadsAWordAsItsOwnArgument() public {
        bytes memory good = _plain(SLH, _pk(SLH, 1));
        uint256 attrs = 4 + uint256(_word(good, 4 + 2 * 32));
        _deploy(R1, chainUidA, address(0), false, BUDGET, address(0), true, _one(SLH, address(mock), PQ));
        _deploy(R2, chainUidA, address(0), false, BUDGET, address(0), true, _one(SLH, address(mock), PQ));

        (bool ok, bytes memory ret) = R2.call(_aimed(good, attrs, good.length + 96));
        assertFalse(ok, "past the calldata");
        assertEq(ret.length, 0);
        (ok,) = R2.call(_aimed(good, attrs, good.length + 64));
        assertTrue(ok, "the word, 0, as the length");
        (ok,) = R1.call(good);
        assertTrue(ok, "the well-formed call");
        bytes32 ua = UAKinds.uaOf(SLH, _pk(SLH, 1));
        (, bytes memory a) = R1.staticcall(abi.encodeCall(IUARegistry.registrationOf, (ua)));
        (, bytes memory b) = R2.staticcall(abi.encodeCall(IUARegistry.registrationOf, (ua)));
        assertEq(a, b, "the record of the well-formed call");
        assertEq(UARegistry(R2).verifyCap(SLH), PQ, "the immutables did not move");
    }

    // ----- the hot path -----

    /// `requireAuthorized` at `159d267e`, the last commit where the differential against the pre-split registry compiled (its `after`
    /// column; `register` state gas in `_stateBefore`). `0`: not a row.
    function _before(uint256 kind) internal pure returns (uint256) {
        if (kind == 256) return 16926;
        if (kind == 257) return 16953;
        if (kind == 258) return 16972;
        if (kind == 259) return 17029;
        if (kind == 260) return 17120;
        if (kind == 261) return 17274;
        if (kind == 262) return 17503;
        if (kind == 263) return 17389;
        if (kind == 264) return 17357;
        if (kind == 272) return 19531;
        if (kind == 273) return 19588;
        if (kind == 274) return 19666;
        if (kind == 275) return 19711;
        if (kind == 304) return 23257;
        if (kind == 305) return 23915;
        if (kind == 306) return 20870;
        if (kind == 307) return 20159;
        if (kind == 321) return 19543;
        return 0;
    }

    function _stateBefore(uint256 kind) internal pure returns (uint256) {
        if (kind == 256) return 1164330;
        if (kind == 257 || kind == 260 || kind == 264) return 1115370;
        if (kind == 258 || kind == 259) return 1066410;
        if (kind == 261 || kind == 263) return 1213290;
        if (kind == 262) return 1409130;
        if (kind == 272) return 1448910;
        if (kind == 273) return 1889550;
        if (kind == 274) return 1643220;
        if (kind == 275) return 2377620;
        if (kind == 304) return 3209940;
        if (kind == 305) return 4189140;
        if (kind == 306) return 2574990;
        if (kind == 307) return 1251540;
        if (kind == 321) return 1398420;
        return 0;
    }

    function _meter(address at, bytes32 ua, IUARegistry.UASig memory s, string memory label, uint256 before, uint256 slack) internal {
        (bool ok,, uint256 used) = gm.measure(at, abi.encodeCall(IUARegistry.requireAuthorized, (ua, UAKinds.PURPOSE_METATX, DIGEST, s)));
        assertTrue(ok, label);
        emit log_string(string.concat("GAS|", label, "|", vm.toString(before), "|", vm.toString(used)));
        assertLe(used, before + slack, label);
    }

    function _kindRow(address at, uint16 k, bytes memory d) internal {
        string memory n = vm.toString(uint256(k));
        (bool ok, bytes memory ret) = at.call(_plain(k, d));
        Vm.Gas memory lg = vm.lastCallGas();
        assertTrue(ok, n);
        assertEq(uint256(int256(lg.gasStateUsed)), _stateBefore(k), string.concat("register state ", n));
        bytes32 ua = abi.decode(ret, (bytes32));
        IUARegistry.UASig memory s;
        bytes memory key = UARegistry(at).keyOf(ua);
        if (key.length == 0) (s.keyData, key) = (d, d);
        s.signature = _sig(key, UAKinds.uaMessage(k, UAKinds.PURPOSE_METATX, DIGEST));
        assertGt(_before(k), 0, n);
        _meter(at, ua, s, string.concat("requireAuthorized ", n), _before(k), SLACK);
    }

    function _msigRow(address at) internal {
        bytes32 alice = _pad(vm.addr(ALICE));
        bytes32 p = UAKinds.uaOf(0x0101, _key(0x0101));
        Member[] memory m = new Member[](2);
        m[0] = Member(UAKinds.EVM_EOA, alice, 1);
        m[1] = Member(0x0101, p, 1);
        bytes memory ds = _msigKey(2, m);
        bytes32 mu = UARegistry(at).registerMsig(UACall.structure(ds), _none(), new IUARegistry.MemberSig[](0), "");
        uint256 used = vm.lastCallGas().gasTotalUsed;
        emit log_string(string.concat("GAS|registerMsig regular|143320|", vm.toString(used)));
        assertLe(used, 143320 + SLACK, "registerMsig");
        UARegistry(at).acceptMembership(mu, _acceptEoaSig(ds, ALICE));
        UARegistry(at).acceptMembership(mu, _acceptKeySig(ds, 0x0101, _key(0x0101)));
        bytes32 md = _memberDigest(mu, UAKinds.PURPOSE_METATX, DIGEST);
        IUARegistry.UASig memory sm;
        sm.members = new IUARegistry.MemberSig[](2);
        sm.members[_indexOf(ds, alice)] = _member(ds, alice, _ecdsa(ALICE, UARegistry(at).uaAuthDigest(alice, UAKinds.PURPOSE_MEMBER, md)));
        sm.members[_indexOf(ds, p)] = _member(ds, p, _sig(_key(0x0101), UAKinds.uaMessage(0x0101, UAKinds.PURPOSE_MEMBER, md)));
        _meter(at, mu, sm, "requireAuthorized msig 2-of-2", 51870, SLACK + 2 * MEMBER_LIST_GAS);
    }

    /// `requireAuthorized`, every kind and native, stays within +64 of the recorded figures (a code layout's change of JUMPDEST order); an
    /// `msig` adds the empty list per member (`MEMBER_LIST_GAS`); `register` state gas does not move; `registerMsig` of a flat `msig` stays
    /// within it too: one read of `hederaNative`, no copy of the structure to memory. Rows `GAS|label|before|now`.
    function test_gasHotPath() public {
        address at = R8;
        _deploy(at, chainUidA, address(0), false, BUDGET, address(0), true, _all());
        (uint16[] memory k, bytes[] memory d) = _rows();
        for (uint256 i; i < k.length; ++i) _kindRow(at, k[i], d[i]);
        IUARegistry.UASig memory e;
        bytes32 alice = _pad(vm.addr(ALICE));
        e.signature = _ecdsa(ALICE, UARegistry(at).uaAuthDigest(alice, UAKinds.PURPOSE_METATX, DIGEST));
        _meter(at, alice, e, "requireAuthorized native eoa", 12426, SLACK);
        MockWallet w = new MockWallet(vm.addr(ALICE), 0, 0, at);
        e.signature = _ecdsa(ALICE, UARegistry(at).uaAuthDigest(_pad(address(w)), UAKinds.PURPOSE_METATX, DIGEST));
        _meter(at, _pad(address(w)), e, "requireAuthorized native 1271", 14239, SLACK);
        _msigRow(at);
    }

    uint256 internal constant SLACK = 64;
    /// An empty `InnerSig[]` per flat member: 115 gas measured (spec §9).
    uint256 internal constant MEMBER_LIST_GAS = 115;
}
