// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UARegistryBase} from "./UARegistryBase.sol";
import {VerifyOnlyStandIn} from "./UARegistryLine.t.sol";
import {UACall} from "./UACall.sol";
import {PqzSet} from "../../src/pqz/PqzSet.sol";
import {MockScopeToken} from "./PqzScopedKeys.t.sol";

/// W1 / N2 / M1 (spec 2026-11-19-registry-verify-only-kinds §3, §7 (e), (f); plan Task 4): every signature-authenticated write is
/// checked by the generation that holds the signer's record. Gen 2 carries `p256` 0x0101 and `fndsa512` 0x0132 verify-only with an
/// **accept-all** stand-in; gen 1 holds the members. Each row: the positive control with good signatures, then a bad one stays
/// refused. (The kinds are the stand-in kinds of these suites; the rule is kind-free. ML-DSA with real signatures: Task 10.)
contract UARegistryVerifyOnlyWritesTest is UARegistryBase {
    uint16 internal constant P256 = 0x0101;
    uint16 internal constant FN = UAKinds.FNDSA512;
    address internal constant PC = address(0x5caa0013);

    UARegistry internal g1;
    UARegistry internal g2;
    UARegistry internal g3;
    bytes internal fnKey;
    bytes32 internal fnId;
    bytes32 internal pId;

    function _k(uint16 kind, address v, uint64 cap, bool vo) internal pure returns (UARegistry.KindConfig memory) {
        return UARegistry.KindConfig(kind, v, cap, vo, 0);
    }

    function _fnPk(uint256 salt) internal pure returns (bytes memory pk) {
        pk = new bytes(897);
        (pk[0], pk[3]) = (bytes1(0x09), bytes1(uint8(salt % 16)));
    }

    function setUp() public override {
        super.setUp();
        UARegistry.KindConfig[] memory b = _cfgs(address(mock));
        UARegistry.KindConfig[] memory k1 = new UARegistry.KindConfig[](b.length + 1);
        for (uint256 i; i < b.length; ++i) {
            k1[i] = b[i];
        }
        k1[b.length] = _k(FN, address(mock), 2_500_000, false);
        g1 = _deploy(address(0x6e01), chainUidA, address(0), false, BUDGET, address(0), true, k1);
        address all = address(new VerifyOnlyStandIn(PC, 0, 1)); // accepts everything
        UARegistry.KindConfig[] memory k2 = new UARegistry.KindConfig[](3);
        k2[0] = _k(P256, all, 250_000, true);
        k2[1] = _k(FN, all, 250_000, true);
        k2[2] = _k(UAKinds.PQZ_MLWE, address(mock), 1_000_000, false);
        g2 = _deploy(address(0x6e02), chainUidA, address(g1), false, BUDGET, address(0), true, k2);
        g3 = _deploy(
            address(0x6e03), chainUidA, address(g2), false, BUDGET, address(0), true, new UARegistry.KindConfig[](0)
        );
        fnKey = _fnPk(1);
        fnId = _register(g1, FN, fnKey);
        pId = _register(g1, P256, _key(P256));
    }

    function _two() internal view returns (bytes memory d, bytes32 ua) {
        Member[] memory m = new Member[](2);
        m[0] = Member(FN, fnId, 1);
        m[1] = Member(P256, pId, 1);
        d = _msigKey(2, m);
        ua = UAKinds.uaOf(UAKinds.MSIG, d);
    }

    /// The m-of-n PoP of `d` over the registration digest; `bad`: the `fndsa512` member's signature flipped.
    function _pop2(bytes memory d, bytes32 ua, IUARegistry.UAAttrs memory a, bool bad)
        internal
        view
        returns (bytes memory)
    {
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_POP_V2, _regDigest(ua, UAKinds.MSIG, a));
        IUARegistry.MemberSig[] memory s = new IUARegistry.MemberSig[](2);
        bytes memory fs = _sig(fnKey, UAKinds.uaMessage(FN, UAKinds.PURPOSE_MEMBER, md));
        if (bad) fs[0] = bytes1(uint8(fs[0]) ^ 1);
        s[_indexOf(d, fnId)] = IUARegistry.MemberSig(_indexOf(d, fnId), new IUARegistry.InnerSig[](0), fs);
        s[_indexOf(d, pId)] = IUARegistry.MemberSig(
            _indexOf(d, pId),
            new IUARegistry.InnerSig[](0),
            _sig(_key(P256), UAKinds.uaMessage(P256, UAKinds.PURPOSE_MEMBER, md))
        );
        return abi.encode(s);
    }

    /// §7 (e): the registration PoP of a gen-2 `msig` whose members gen 1 holds.
    function test_writes_acceptAll_registrationPop_msigWithGen1Members() public {
        (bytes memory d, bytes32 ua) = _two();
        bytes memory bad = _pop2(d, ua, _none(), true);
        vm.expectRevert(IUARegistry.UAPoP.selector);
        UACall.register(g2, UAKinds.MSIG, d, _none(), bad, "");
        assertEq(UACall.register(g2, UAKinds.MSIG, d, _none(), _pop2(d, ua, _none(), false), ""), ua); // the control
    }

    /// `acceptMembership` of a gen-1 member in a gen-2 `msig` (registered without a PoP: classical-dominant).
    function test_writes_acceptAll_acceptMembership() public {
        Member[] memory m = new Member[](2);
        m[0] = Member(P256, pId, 1);
        m[1] = Member(UAKinds.EVM_EOA, _pad(address(0xE0A1)), 1);
        bytes memory d = _msigKey(1, m);
        bytes32 ua = UACall.register(g2, UAKinds.MSIG, d, _none(), "", "");
        IUARegistry.MemberSig memory good = _acceptKeySig(d, P256, _key(P256));
        IUARegistry.MemberSig memory bad = _acceptKeySig(d, P256, _key(P256));
        bad.sig[0] = bytes1(uint8(bad.sig[0]) ^ 1);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        g2.acceptMembership(ua, bad);
        g2.acceptMembership(ua, good); // the control
        assertTrue(g2.memberAccepted(ua, good.index));
    }

    /// The `setPqzKey` record of a holder: an `msig` held here (gen 2), its gen-1 members signing.
    function test_writes_acceptAll_setPqzKey_msigHeldHere() public {
        (bytes memory d, bytes32 ua) = _two();
        UACall.register(g2, UAKinds.MSIG, d, _none(), _pop2(d, ua, _none(), false), "");
        _setPqzKey(g2, ua, d, 41);
    }

    /// The same `msig` registered in gen 1 and its key set on gen 2, its PQZ home (A6-I1): the members' holder checks them.
    function test_writes_acceptAll_setPqzKey_msigHeldInPredecessor() public {
        (bytes memory d, bytes32 ua) = _two();
        UACall.register(g1, UAKinds.MSIG, d, _none(), _pop2(d, ua, _none(), false), "");
        _setPqzKey(g2, ua, d, 42);
    }

    /// A single-key holder in gen 1 (`fndsa512`) sets its key on gen 2, its PQZ home and a verify-only carrier of its kind (M1's
    /// configuration, §7 (e)); and through gen 3, which carries nothing (§7 (f)), the write is refused there (not its home).
    function test_writes_acceptAll_setPqzKey_singleKey() public {
        bytes memory key = _pqzKey(43);
        bytes32 h = UAKinds.keyHashOf(UAKinds.PQZ_MLWE, key);
        bytes32 rd = UAKinds.pqzKeyRecordDigest(fnId, h, keccak256(hex"01"));
        bytes memory sig = _sig(fnKey, UAKinds.uaMessage(FN, UAKinds.PURPOSE_PQZ_KEY, rd));
        bytes memory bad = bytes.concat(sig);
        bad[0] = bytes1(uint8(bad[0]) ^ 1);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, fnId));
        g2.setPqzKey(fnId, 0, key, keccak256(hex"01"), UACall.sig(bad));
        g2.setPqzKey(fnId, 0, key, keccak256(hex"01"), UACall.sig(sig)); // the control
    }

    function _pqzKey(uint256 salt) internal pure returns (bytes memory k) {
        k = new bytes(PqzSet.PK);
        k[0] = bytes1(uint8(salt));
    }

    /// The two members of `d` (`fndsa512`, `p256`) over `rd` under `purpose`; `bad`: the `fndsa512` signature flipped.
    function _members(bytes memory d, bytes32 ua, bytes32 purpose, bytes32 rd, bool bad)
        internal
        view
        returns (IUARegistry.UASig memory a)
    {
        bytes32 md = _memberDigest(ua, purpose, rd);
        a.members = new IUARegistry.MemberSig[](2);
        bytes memory fs = _sig(fnKey, UAKinds.uaMessage(FN, UAKinds.PURPOSE_MEMBER, md));
        if (bad) fs[0] = bytes1(uint8(fs[0]) ^ 1);
        uint16 fi = _indexOf(d, fnId);
        uint16 pi = _indexOf(d, pId);
        a.members[fi] = IUARegistry.MemberSig(fi, new IUARegistry.InnerSig[](0), fs);
        a.members[pi] = IUARegistry.MemberSig(
            pi, new IUARegistry.InnerSig[](0), _sig(_key(P256), UAKinds.uaMessage(P256, UAKinds.PURPOSE_MEMBER, md))
        );
    }

    function _setPqzKey(UARegistry at, bytes32 ua, bytes memory d, uint256 salt) internal {
        bytes memory key = _pqzKey(salt);
        bytes32 rd = UAKinds.pqzKeyRecordDigest(ua, UAKinds.keyHashOf(UAKinds.PQZ_MLWE, key), keccak256(hex"01"));
        IUARegistry.UASig memory b = _members(d, ua, UAKinds.PURPOSE_PQZ_KEY, rd, true);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        at.setPqzKey(ua, 0, key, keccak256(hex"01"), b);
        at.setPqzKey(ua, 0, key, keccak256(hex"01"), _members(d, ua, UAKinds.PURPOSE_PQZ_KEY, rd, false)); // the control
    }

    // ----- setPqzScopedKey (class 2, scope 0) -----

    function _kem() internal pure returns (IUARegistry.KemKey memory k) {
        (k.scheme, k.mlkemEk, k.x25519) = (1, new bytes(1568), bytes32(uint256(7)));
        k.mlkemEk[0] = 0x01;
    }

    function _scopedRd(bytes32 ua, address scope, bytes memory key) internal view returns (bytes32) {
        return UAKinds.pqzScopedKeyRecordDigest(
            ua,
            scope == address(0) ? 2 : 3,
            chainUidA,
            scope,
            0,
            UAKinds.keyHashOf(UAKinds.PQZ_MLWE, key),
            keccak256(hex"01"),
            keccak256(UAKinds.kemPk(_kem())),
            type(uint64).max
        );
    }

    function _scoped(UARegistry at, bytes32 ua, address scope, bytes memory key, IUARegistry.UASig memory s) internal {
        at.setPqzScopedKey(ua, scope, 0, key, keccak256(hex"01"), _kem(), type(uint64).max, s);
    }

    /// An `msig` holds no shared key at first (ruling 9): its scoped rows name a token scope with an opening KEM (class 3).
    function _setScoped(UARegistry at, bytes32 ua, bytes memory d, uint256 salt) internal {
        bytes memory key = _pqzKey(salt);
        address scope = address(new MockScopeToken(1));
        bytes32 rd = _scopedRd(ua, scope, key);
        IUARegistry.UASig memory b = _members(d, ua, UAKinds.PURPOSE_PQZ_SCOPED_KEY, rd, true);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        _scoped(at, ua, scope, key, b);
        _scoped(at, ua, scope, key, _members(d, ua, UAKinds.PURPOSE_PQZ_SCOPED_KEY, rd, false)); // the control
    }

    function test_writes_acceptAll_setPqzScopedKey_msigHeldHere() public {
        (bytes memory d, bytes32 ua) = _two();
        UACall.register(g2, UAKinds.MSIG, d, _none(), _pop2(d, ua, _none(), false), "");
        _setScoped(g2, ua, d, 51);
    }

    function test_writes_acceptAll_setPqzScopedKey_msigHeldInPredecessor() public {
        (bytes memory d, bytes32 ua) = _two();
        UACall.register(g1, UAKinds.MSIG, d, _none(), _pop2(d, ua, _none(), false), "");
        _setScoped(g2, ua, d, 52);
    }

    function test_writes_acceptAll_setPqzScopedKey_singleKey() public {
        bytes memory key = _pqzKey(53);
        bytes memory sig =
            _sig(fnKey, UAKinds.uaMessage(FN, UAKinds.PURPOSE_PQZ_SCOPED_KEY, _scopedRd(fnId, address(0), key)));
        bytes memory bad = bytes.concat(sig);
        bad[0] = bytes1(uint8(bad[0]) ^ 1);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, fnId));
        _scoped(g2, fnId, address(0), key, UACall.sig(bad));
        _scoped(g2, fnId, address(0), key, UACall.sig(sig)); // the control
    }

    // ----- updateMsig and setKemKey -----

    /// `updateMsig` of a gen-2 `msig` whose members gen 1 holds: a bad member signature stays `UAUnauthorized`.
    function test_writes_acceptAll_updateMsig() public {
        (bytes memory d, bytes32 ua) = _two();
        UACall.register(g2, UAKinds.MSIG, d, _none(), _pop2(d, ua, _none(), false), "");
        (uint64 v, uint256 en,) = g2.msigStateOf(ua);
        IUARegistry.MsigStructure memory st = g2.msigOf(ua);
        uint64 until = uint64(block.number + 100);
        bytes32 typed = UAKinds.msigUpdateDigest(ua, chainUidA, address(g2), v + 1, st, en, until);
        IUARegistry.MemberSig[] memory bad = _members(d, ua, UAKinds.PURPOSE_MSIG_UPDATE, typed, true).members;
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        g2.updateMsig(ua, v + 1, st, en, until, bad, chainUidA);
        IUARegistry.MemberSig[] memory good = _members(d, ua, UAKinds.PURPOSE_MSIG_UPDATE, typed, false).members;
        g2.updateMsig(ua, v + 1, st, en, until, good, chainUidA); // the control
        (uint64 v2,,) = g2.msigStateOf(ua);
        assertEq(v2, v + 1);
    }

    /// `setKemKey` (an `msig` holds no KEM key, CTR-UA-32): a gen-1 single key's KEM write on gen 2, the accept-all carrier of
    /// its kind, is `UAUnauthorized` whatever its signature (the record is held elsewhere); its holder takes it.
    function test_writes_acceptAll_setKemKey_heldElsewhere() public {
        bytes memory pk = UAKinds.kemPk(_kem());
        bytes memory sig = _sig(fnKey, UAKinds.uaMessage(FN, UAKinds.PURPOSE_KEM, UAKinds.kemRecordDigest(fnId, 1, pk)));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, fnId));
        g2.setKemKey(fnId, 1, _kem(), UACall.sig(sig));
        g1.setKemKey(fnId, 1, _kem(), UACall.sig(sig)); // the control: at its holder
    }

    /// Review Focus 2 (R6): a gen-2 `msig` naming a gen-1 `msig` whose members are gen-1 keys: the inner one is forwarded whole to gen 1,
    /// so a bad member signature stays refused on the write (`acceptMembership` of the inner slot) and on the consumer path.
    function test_writes_innerMsig_forwardedWhole() public {
        (bytes memory di, bytes32 inner) = _two();
        UACall.register(g1, UAKinds.MSIG, di, _none(), _pop2(di, inner, _none(), false), "");
        Member[] memory m = new Member[](2);
        m[0] = Member(UAKinds.MSIG, inner, 1);
        m[1] = Member(UAKinds.EVM_EOA, _pad(address(0xE0A2)), 1);
        bytes memory d = _msigKey(1, m);
        bytes32 ua = UACall.register(g2, UAKinds.MSIG, d, _none(), "", "");
        uint16 slot = _indexOf(d, inner);
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_MEMBERSHIP, UAKinds.membershipDigest(ua, inner));
        bytes32 imd = UAKinds.memberDigest(inner, UAKinds.uaMessage(UAKinds.MSIG, UAKinds.PURPOSE_MEMBER, md));
        IUARegistry.InnerSig[] memory l = new IUARegistry.InnerSig[](2);
        bytes memory fs = _sig(fnKey, UAKinds.uaMessage(FN, UAKinds.PURPOSE_MEMBER, imd));
        fs[0] = bytes1(uint8(fs[0]) ^ 1);
        l[_indexOf(di, fnId)] = IUARegistry.InnerSig(_indexOf(di, fnId), fs);
        l[_indexOf(di, pId)] = IUARegistry.InnerSig(
            _indexOf(di, pId), _sig(_key(P256), UAKinds.uaMessage(P256, UAKinds.PURPOSE_MEMBER, imd))
        );
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        g2.acceptMembership(ua, IUARegistry.MemberSig(slot, l, ""));
    }
}
