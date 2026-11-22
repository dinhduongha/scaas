// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UARegistry} from "../../src/ua/UARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UARegistryBase} from "./UARegistryBase.sol";
import {VerifyOnlyStandIn} from "./UARegistryLine.t.sol";
import {UACall} from "./UACall.sol";

/// The consumer path (spec 2026-11-19-registry-verify-only-kinds §4, CTR-UA-60; plan Task 5) and the three-state call with its
/// fallback (§5, CTR-UA-68; Task 6). Gen 1 holds `p256` 0x0101 and `fndsa512` 0x0132 records (stand-in verifiers: the
/// `MockVerifier` rule); a later generation carries them verify-only with a `VerifyOnlyStandIn` of a chosen mode (0 the same rule
/// as the holder, 1 accept all, 2 refuse all, 3 – 8 no answer of each form).
contract UARegistryVerifyOnlyTest is UARegistryBase {
    uint16 internal constant P256 = 0x0101;
    uint16 internal constant FN = UAKinds.FNDSA512;
    address internal constant PC = address(0x5caa0013);
    uint64 internal constant CAP_VO = 250_000;
    bytes32 internal constant APP = keccak256("scaas.test.app");

    UARegistry internal g1;
    bytes internal fnKey;
    bytes32 internal fnId;
    bytes32 internal pId;
    uint256 internal at = 0x6f10; // the later generations' addresses, after gen 1's

    function setUp() public override {
        super.setUp();
        UARegistry.KindConfig[] memory b = _cfgs(address(mock));
        UARegistry.KindConfig[] memory k1 = new UARegistry.KindConfig[](b.length + 2);
        for (uint256 i; i < b.length; ++i) {
            k1[i] = b[i];
        }
        k1[b.length] = UARegistry.KindConfig(FN, address(mock), 2_500_000, false, 0);
        // mldsa65 on a verifier without a precompile (`PRECOMPILE() == 0`, the mock rule): what key form 1 needs of the home (§2)
        address noPc = address(new VerifyOnlyStandIn(address(0), 0, 0));
        k1[b.length + 1] = UARegistry.KindConfig(UAKinds.MLDSA65, noPc, 400_000, false, 0);
        g1 = _deploy(address(0x6f01), chainUidA, address(0), false, BUDGET, address(0), true, k1);
        fnKey = new bytes(897);
        (fnKey[0], fnKey[3]) = (bytes1(0x09), bytes1(0x01));
        fnId = _register(g1, FN, fnKey);
        pId = _register(g1, P256, _key(P256));
    }

    /// A generation over `pred` carrying both kinds verify-only with a stand-in of `mode`.
    function _over(address pred, uint8 mode) internal returns (UARegistry) {
        address v = address(new VerifyOnlyStandIn(PC, 0, mode));
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](2);
        k[0] = UARegistry.KindConfig(P256, v, CAP_VO, true, 0);
        k[1] = UARegistry.KindConfig(FN, v, CAP_VO, true, 0);
        return _deploy(address(uint160(++at)), chainUidA, pred, false, BUDGET, address(0), true, k);
    }

    function _plain(address pred) internal returns (UARegistry) {
        return _deploy(
            address(uint160(++at)), chainUidA, pred, false, BUDGET, address(0), true, new UARegistry.KindConfig[](0)
        );
    }

    /// The signer `p256` record's auth for `(purpose, DIGEST)`, flipped when `bad`.
    function _pAuth(bool bad) internal view returns (bytes memory) {
        bytes memory a = _auth(g1, P256, _key(P256), UAKinds.PURPOSE_METATX, DIGEST);
        if (bad) a[a.length - 1] = bytes1(uint8(a[a.length - 1]) ^ 1);
        return a;
    }

    function _ok(UARegistry r, bytes32 ua, bytes memory a) internal view returns (bool) {
        (bool ok,) = address(r).staticcall(_reqCall(ua, UAKinds.PURPOSE_METATX, DIGEST, a));
        return ok;
    }

    /// The portable signature of the `fndsa512` record over `(purpose, TYPED)`, flipped when `bad`.
    bytes32 internal constant TYPED = keccak256("scaas.test.typed");

    function _fnSig(bytes32 purpose, bool bad) internal view returns (IUARegistry.UASig memory s) {
        s.signature = _sig(fnKey, UAKinds.uaMessage(FN, purpose, TYPED));
        if (bad) s.signature[0] = bytes1(uint8(s.signature[0]) ^ 1);
    }

    function _portableOk(UARegistry r, bool app, bool bad) internal view returns (bool ok) {
        bytes memory call = app
            ? abi.encodeCall(IUARegistry.requirePortableApp, (fnId, APP, TYPED, _fnSig(UAKinds.appPurpose(APP), bad)))
            : abi.encodeCall(
                IUARegistry.requirePortable, (fnId, UAKinds.PURPOSE_PQCHAT, TYPED, _fnSig(UAKinds.PURPOSE_PQCHAT, bad))
            );
        (ok,) = address(r).staticcall(call);
    }

    // ----- Task 5: §4's table -----

    /// The signer (`_authorized`): this generation's verifier, never the holder's, on a verify-only kind.
    function test_signer_verifyOnly_ownVerifier() public {
        UARegistry same = _over(address(g1), 0);
        assertTrue(_ok(same, pId, _pAuth(false)), "the same rule: accepted");
        assertFalse(_ok(same, pId, _pAuth(true)), "a bad signature refused");
        UARegistry refuse = _over(address(g1), 2);
        assertFalse(_ok(refuse, pId, _pAuth(false)), "this generation's verifier answers, not gen 1's");
    }

    /// This generation's `msig`'s member held in gen 1, on the consumer path (`_memberOk` -> `_derived`, purpose `member`).
    function test_member_verifyOnly_ownVerifier() public {
        for (uint8 mode; mode < 3; mode += 2) {
            UARegistry g2 = _over(address(g1), mode);
            Member[] memory m = new Member[](1);
            m[0] = Member(P256, pId, 1);
            bytes memory d = _msigKey(1, m);
            bytes32 ua = UACall.register(g2, UAKinds.MSIG, d, _none(), "", "");
            g2.acceptMembership(ua, _acceptKeySig(d, P256, _key(P256))); // a write: the holder checks it
            bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX, DIGEST);
            IUARegistry.MemberSig[] memory s = new IUARegistry.MemberSig[](1);
            s[0] = IUARegistry.MemberSig(
                0, new IUARegistry.InnerSig[](0), _sig(_key(P256), g2.uaMessage(P256, UAKinds.PURPOSE_MEMBER, md))
            );
            IUARegistry.UASig memory a;
            a.members = s;
            (bool ok,) = address(g2)
                .staticcall(abi.encodeCall(IUARegistry.requireAuthorized, (ua, UAKinds.PURPOSE_METATX, DIGEST, a)));
            assertEq(ok, mode == 0, "the member by this generation's verifier");
        }
    }

    /// R6: a predecessor's `msig` (any consumer path) is forwarded whole: gen 2's refuse-all verifier is never asked for its members.
    function test_predecessorMsig_forwardedWhole() public {
        Member[] memory m = new Member[](1);
        m[0] = Member(P256, pId, 1);
        bytes memory d = _msigKey(1, m);
        bytes32 ua = UACall.register(g1, UAKinds.MSIG, d, _none(), "", "");
        g1.acceptMembership(ua, _acceptKeySig(d, P256, _key(P256)));
        UARegistry g2 = _over(address(g1), 2);
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX, DIGEST);
        IUARegistry.UASig memory a;
        a.members = new IUARegistry.MemberSig[](1);
        a.members[0] = IUARegistry.MemberSig(
            0, new IUARegistry.InnerSig[](0), _sig(_key(P256), g1.uaMessage(P256, UAKinds.PURPOSE_MEMBER, md))
        );
        g2.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, a);
    }

    function test_requirePortable_verifyOnly() public {
        assertTrue(_portableOk(_over(address(g1), 0), false, false));
        assertFalse(_portableOk(_over(address(g1), 0), false, true));
        assertFalse(_portableOk(_over(address(g1), 2), false, false), "this generation's verifier answers");
    }

    function test_requirePortableApp_verifyOnly() public {
        assertTrue(_portableOk(_over(address(g1), 0), true, false));
        assertFalse(_portableOk(_over(address(g1), 0), true, true));
        assertFalse(_portableOk(_over(address(g1), 2), true, false), "this generation's verifier answers");
    }

    /// §7 (f), N3: gen 3, which does not carry the kind, hands a gen-1 record to gen 1 directly: gen 2's accept-all is never asked.
    function test_kindNotCarried_goesToHolderDirectly() public {
        UARegistry g2 = _over(address(g1), 1);
        UARegistry g3 = _plain(address(g2));
        vm.expectCall(address(g2), abi.encodeWithSelector(IUARegistry.requireAuthorized.selector), 0);
        assertFalse(_ok(g3, pId, _pAuth(true)), "a bad signature stays refused");
        assertTrue(_ok(g3, pId, _pAuth(false)));
        assertFalse(_portableOk(g3, false, true));
        assertFalse(_portableOk(g3, true, true));
        assertTrue(_portableOk(g3, false, false), "the holder's requirePortable");
        assertTrue(_portableOk(g3, true, false), "the holder's requirePortableApp, under its appId");
    }

    /// §7 (f), N3 for a member: gen 3's `msig` names a gen-1 member of a kind gen 3 does not carry; the member goes to gen 1 directly,
    /// gen 2's accept-all never asked: a bad member signature stays refused.
    function test_kindNotCarried_member_goesToHolderDirectly() public {
        UARegistry g2 = _over(address(g1), 1);
        UARegistry g3 = _plain(address(g2));
        Member[] memory m = new Member[](1);
        m[0] = Member(P256, pId, 1);
        bytes memory d = _msigKey(1, m);
        bytes32 ua = UACall.register(g3, UAKinds.MSIG, d, _none(), "", "");
        g3.acceptMembership(ua, _acceptKeySig(d, P256, _key(P256)));
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX, DIGEST);
        IUARegistry.UASig memory a;
        a.members = new IUARegistry.MemberSig[](1);
        bytes memory good = _sig(_key(P256), g3.uaMessage(P256, UAKinds.PURPOSE_MEMBER, md));
        bytes memory bad = bytes.concat(good);
        bad[0] = bytes1(uint8(bad[0]) ^ 1);
        a.members[0] = IUARegistry.MemberSig(0, new IUARegistry.InnerSig[](0), bad);
        vm.expectCall(address(g2), abi.encodeWithSelector(IUARegistry.requireAuthorized.selector), 0);
        (bool ok,) = address(g3)
            .staticcall(abi.encodeCall(IUARegistry.requireAuthorized, (ua, UAKinds.PURPOSE_METATX, DIGEST, a)));
        assertFalse(ok, "a bad member signature stays refused");
        a.members[0].sig = good;
        g3.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, a); // the control
    }

    /// Review Focus 1: two verify-only carriers on one line; the reader uses its own verifier only.
    function test_twoVerifyOnlyCarriers_readerUsesOwn() public {
        UARegistry g2 = _over(address(g1), 1); // accept all
        UARegistry g3 = _over(address(g2), 0); // correct
        assertFalse(_ok(g3, pId, _pAuth(true)), "gen 2's accept-all is never asked");
        assertTrue(_ok(g3, pId, _pAuth(false)));
        assertFalse(_portableOk(g3, false, true));
    }

    /// The registration `pop` is never a later generation's check (`_portable` refuses the purpose).
    function test_pop_neverCheckedByLater() public {
        UARegistry g2 = _over(address(g1), 1);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, fnId));
        g2.requirePortable(fnId, UAKinds.PURPOSE_POP_V2, TYPED, _fnSig(UAKinds.PURPOSE_POP_V2, false));
    }

    /// A record no generation holds is refused on every entry.
    function test_unregistered_refused() public {
        UARegistry g2 = _over(address(g1), 1);
        bytes32 nobody = keccak256("nobody");
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, nobody));
        g2.requirePortable(nobody, UAKinds.PURPOSE_PQCHAT, TYPED, _fnSig(UAKinds.PURPOSE_PQCHAT, false));
        assertFalse(_ok(g2, nobody, _pAuth(false)));
    }

    /// The member's kind is `holderOf`'s (a gen-2 `msig` names a gen-1 member; gen 2 holds no record of it): the walk's kind matches
    /// the listed one and this generation's verifier checks it.
    function test_memberKind_fromHolderOf() public {
        UARegistry g2 = _over(address(g1), 0);
        (address h, uint16 k,) = g2.holderOf(pId);
        assertEq(abi.encode(h, k), abi.encode(address(g1), P256));
        assertEq(g2.kindOf(pId), P256);
        Member[] memory m = new Member[](1);
        m[0] = Member(P256, pId, 1);
        bytes memory d = _msigKey(1, m);
        bytes32 ua = UACall.register(g2, UAKinds.MSIG, d, _none(), "", "");
        g2.acceptMembership(ua, _acceptKeySig(d, P256, _key(P256)));
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX, DIGEST);
        IUARegistry.UASig memory a;
        a.members = new IUARegistry.MemberSig[](1);
        a.members[0] = IUARegistry.MemberSig(
            0, new IUARegistry.InnerSig[](0), _sig(_key(P256), g2.uaMessage(P256, UAKinds.PURPOSE_MEMBER, md))
        );
        g2.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, a);
    }

    /// This generation's `msig`'s stored paths on a consumer entry (`UARegistryCoreLib._memberOk`, `write = false`): a PQ-eligible
    /// gen-2 `msig` of the gen-1 `fndsa512` member under `requirePortable` takes this generation's verifier.
    function test_storedPath_member_verifyOnly() public {
        for (uint8 mode; mode < 3; mode += 2) {
            UARegistry g2 = _over(address(g1), mode);
            Member[] memory m = new Member[](1);
            m[0] = Member(FN, fnId, 1);
            bytes memory d = _msigKey(1, m);
            bytes32 ua = UAKinds.uaOf(UAKinds.MSIG, d);
            bytes32 pmd = _memberDigest(ua, UAKinds.PURPOSE_POP_V2, _regDigest(ua, UAKinds.MSIG));
            IUARegistry.MemberSig[] memory p = new IUARegistry.MemberSig[](1);
            p[0] = IUARegistry.MemberSig(
                0, new IUARegistry.InnerSig[](0), _sig(fnKey, UAKinds.uaMessage(FN, UAKinds.PURPOSE_MEMBER, pmd))
            );
            UACall.register(g2, UAKinds.MSIG, d, _none(), abi.encode(p), ""); // a write: gen 1 checks the member
            bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_PQCHAT, TYPED);
            IUARegistry.UASig memory a;
            a.members = new IUARegistry.MemberSig[](1);
            a.members[0] = IUARegistry.MemberSig(
                0, new IUARegistry.InnerSig[](0), _sig(fnKey, UAKinds.uaMessage(FN, UAKinds.PURPOSE_MEMBER, md))
            );
            (bool ok,) = address(g2)
                .staticcall(abi.encodeCall(IUARegistry.requirePortable, (ua, UAKinds.PURPOSE_PQCHAT, TYPED, a)));
            assertEq(ok, mode == 0, "the stored path's member by this generation's verifier");
        }
    }

    /// An inner `msig` held elsewhere (`UARegistry._memberOk`) is forwarded whole to its holder: gen 2's refuse-all is never asked.
    function test_innerMsig_heldElsewhere_forwardedWhole() public {
        Member[] memory mi = new Member[](1);
        mi[0] = Member(P256, pId, 1);
        bytes memory di = _msigKey(1, mi);
        bytes32 inner = UACall.register(g1, UAKinds.MSIG, di, _none(), "", "");
        g1.acceptMembership(inner, _acceptKeySig(di, P256, _key(P256)));
        UARegistry g2 = _over(address(g1), 2);
        Member[] memory m = new Member[](1);
        m[0] = Member(UAKinds.MSIG, inner, 1);
        bytes memory d = _msigKey(1, m);
        bytes32 ua = UACall.register(g2, UAKinds.MSIG, d, _none(), "", "");
        bytes32 amd = _membershipMd(ua, inner);
        bytes32 aimd = UAKinds.memberDigest(inner, UAKinds.uaMessage(UAKinds.MSIG, UAKinds.PURPOSE_MEMBER, amd));
        IUARegistry.InnerSig[] memory l = new IUARegistry.InnerSig[](1);
        l[0] = IUARegistry.InnerSig(0, _sig(_key(P256), UAKinds.uaMessage(P256, UAKinds.PURPOSE_MEMBER, aimd)));
        g2.acceptMembership(ua, IUARegistry.MemberSig(0, l, ""));
        bytes32 md = _memberDigest(ua, UAKinds.PURPOSE_METATX, DIGEST);
        bytes32 imd = UAKinds.memberDigest(inner, UAKinds.uaMessage(UAKinds.MSIG, UAKinds.PURPOSE_MEMBER, md));
        l[0] = IUARegistry.InnerSig(0, _sig(_key(P256), UAKinds.uaMessage(P256, UAKinds.PURPOSE_MEMBER, imd)));
        IUARegistry.UASig memory a;
        a.members = new IUARegistry.MemberSig[](1);
        a.members[0] = IUARegistry.MemberSig(0, l, "");
        g2.requireAuthorized(ua, UAKinds.PURPOSE_METATX, DIGEST, a);
    }

    /// Task 21 review P2-1: an inner `msig` held elsewhere is forwarded whole to its holder (R6), so the bound counts its members
    /// on the holder's path (gen 1's `p256` cap and hand-off), never this generation's verify-only cap: a gen-2 `{inner}` that
    /// fits only when priced at the verify-only cap is refused `UAKeyData(0x0120)` at 500,000; with the budget it registers.
    function test_innerMsig_heldElsewhere_boundAtHolderPath() public {
        Member[] memory mi = new Member[](1);
        mi[0] = Member(P256, pId, 1);
        bytes32 inner = UACall.register(g1, UAKinds.MSIG, _msigKey(1, mi), _none(), "", "");
        Member[] memory m = new Member[](1);
        m[0] = Member(UAKinds.MSIG, inner, 1);
        bytes memory d = _msigKey(1, m);
        address v = address(new VerifyOnlyStandIn(PC, 0, 0));
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](1);
        k[0] = UARegistry.KindConfig(P256, v, CAP_VO, true, 0);
        UARegistry tight = _deploy(address(uint160(++at)), chainUidA, address(g1), false, 500_000, address(0), true, k);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyData.selector, UAKinds.MSIG));
        UACall.register(tight, UAKinds.MSIG, d, _none(), "", "");
        UARegistry fits = _deploy(address(uint160(++at)), chainUidA, address(g1), false, BUDGET, address(0), true, k);
        UACall.register(fits, UAKinds.MSIG, d, _none(), "", "");
    }

    /// Key form 1 (§2, §4 "Key bytes"): the holder's complete cache; an incomplete one is `UAKeyNotCached`, its kind `holderOf`'s.
    function test_keyForm1_incompleteCache_UAKeyNotCached() public {
        bytes memory pk = new bytes(1952);
        pk[0] = 0x31;
        bytes32 ml = _register(g1, UAKinds.MLDSA65, pk);
        assertEq(g1.expandedKeyOf(ml)[0], address(0), "no cache at the holder");
        address v = address(new VerifyOnlyStandIn(PC, 1, 1));
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](1);
        k[0] = UARegistry.KindConfig(UAKinds.MLDSA65, v, CAP_VO, true, 1);
        UARegistry g2 = _deploy(address(uint160(++at)), chainUidA, address(g1), false, BUDGET, address(0), true, k);
        bytes memory sig = _sig(pk, UAKinds.uaMessage(UAKinds.MLDSA65, UAKinds.PURPOSE_METATX, DIGEST));
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAKeyNotCached.selector, ml));
        g2.requireAuthorized(ml, UAKinds.PURPOSE_METATX, DIGEST, UACall.sig(sig));
    }

    /// F11: a read of the holder that fails is never a verdict: `UAVerifyGas` (a holder whose `keyOf` fails).
    function test_failedRead_UAVerifyGas() public {
        ReadFailsLine line = new ReadFailsLine(chainUidA);
        UARegistry g2 = _over(address(line), 1);
        bytes memory sig = _sig(fnKey, UAKinds.uaMessage(FN, UAKinds.PURPOSE_METATX, DIGEST));
        vm.expectRevert(UAKinds.UAVerifyGas.selector);
        g2.requireAuthorized(fnId, UAKinds.PURPOSE_METATX, DIGEST, UACall.sig(sig));
    }

    /// Review Focus 2 on the stored paths (R6): a gen-2 `msig` naming a gen-1 `msig` of the `fndsa512` member, gen 2 carrying it
    /// verify-only with an accept-all stand-in. The inner structure keeps gen 1's verifiers on `requirePortable`: a bad member
    /// signature stays refused, the good one passes.
    function test_storedPath_innerMsig_heldElsewhere_holderVerifiers() public {
        Member[] memory mi = new Member[](1);
        mi[0] = Member(FN, fnId, 1);
        bytes memory di = _msigKey(1, mi);
        bytes32 inner = UAKinds.uaOf(UAKinds.MSIG, di);
        bytes32 pmd = _memberDigest(inner, UAKinds.PURPOSE_POP_V2, _regDigest(inner, UAKinds.MSIG));
        IUARegistry.MemberSig[] memory p = new IUARegistry.MemberSig[](1);
        p[0] = IUARegistry.MemberSig(
            0, new IUARegistry.InnerSig[](0), _sig(fnKey, UAKinds.uaMessage(FN, UAKinds.PURPOSE_MEMBER, pmd))
        );
        UACall.register(g1, UAKinds.MSIG, di, _none(), abi.encode(p), "");
        UARegistry g2 = _over(address(g1), 1);
        Member[] memory m = new Member[](1);
        m[0] = Member(UAKinds.MSIG, inner, 1);
        bytes memory d = _msigKey(1, m);
        bytes32 ua = UAKinds.uaOf(UAKinds.MSIG, d);
        UACall.register(
            g2,
            UAKinds.MSIG,
            d,
            _none(),
            abi.encode(_innerSigs(ua, inner, UAKinds.PURPOSE_POP_V2, _regDigest(ua, UAKinds.MSIG), false)),
            ""
        );
        IUARegistry.UASig memory a;
        a.members = _innerSigs(ua, inner, UAKinds.PURPOSE_PQCHAT, TYPED, true);
        vm.expectRevert(abi.encodeWithSelector(IUARegistry.UAUnauthorized.selector, ua));
        g2.requirePortable(ua, UAKinds.PURPOSE_PQCHAT, TYPED, a);
        a.members = _innerSigs(ua, inner, UAKinds.PURPOSE_PQCHAT, TYPED, false);
        g2.requirePortable(ua, UAKinds.PURPOSE_PQCHAT, TYPED, a); // the control
    }

    /// The outer `msig` `ua`'s slot 0 (the inner `msig`) signed by its `fndsa512` member over `(purpose, digest)`; `bad` flips it.
    function _innerSigs(bytes32 ua, bytes32 inner, bytes32 purpose, bytes32 digest, bool bad)
        internal
        view
        returns (IUARegistry.MemberSig[] memory s)
    {
        bytes32 md = _memberDigest(ua, purpose, digest);
        bytes32 imd = UAKinds.memberDigest(inner, UAKinds.uaMessage(UAKinds.MSIG, UAKinds.PURPOSE_MEMBER, md));
        IUARegistry.InnerSig[] memory l = new IUARegistry.InnerSig[](1);
        l[0] = IUARegistry.InnerSig(0, _sig(fnKey, UAKinds.uaMessage(FN, UAKinds.PURPOSE_MEMBER, imd)));
        if (bad) l[0].sig[0] = bytes1(uint8(l[0].sig[0]) ^ 1);
        s = new IUARegistry.MemberSig[](1);
        s[0] = IUARegistry.MemberSig(0, l, "");
    }

    // ----- Task 6: the three-state call and the fallback (§5, CTR-UA-68) -----

    /// Every stand-in answer: 1 accepts (even a bad signature: this generation's verdict), 0 refuses with no fallback (even a good
    /// one), every "no answer" (revert `PqNoAnswer`, revert empty, out of gas at the cap, empty return, two words, `abi.encode(2)`,
    /// Review Focus 3) falls back to the holder: good accepted, bad refused. On the signer, the member-free portable and the app path.
    function test_threeStates_andFallback() public {
        for (uint8 mode = 1; mode <= 8; ++mode) {
            UARegistry g2 = _over(address(g1), mode);
            bool good = _ok(g2, pId, _pAuth(false));
            bool bad = _ok(g2, pId, _pAuth(true));
            bool pg = _portableOk(g2, false, false);
            bool pb = _portableOk(g2, false, true);
            bool ag = _portableOk(g2, true, false);
            bool ab = _portableOk(g2, true, true);
            if (mode == 1) {
                assertTrue(good && bad && pg && pb && ag && ab, "1 accepts");
            } else if (mode == 2) {
                assertFalse(good || bad || pg || pb || ag || ab, "0 refuses, no fallback");
            } else {
                assertTrue(good && pg && ag, string.concat("no answer: the holder accepts, mode ", vm.toString(mode)));
                assertFalse(bad || pb || ab, string.concat("no answer: the holder refuses, mode ", vm.toString(mode)));
            }
        }
    }

    /// T-AUTH-4 on the new path: a caller that leaves less than this generation's cap plus its hold gets `UAVerifyGas`, never a
    /// fallback bought below the cap. The portable path holds too (P10: group kinds included, one code path).
    function test_gasBelowCap_UAVerifyGas() public {
        UARegistry g2 = _over(address(g1), 5); // out of gas at the cap: a fallback only with the full cap
        bytes memory call = _reqCall(pId, UAKinds.PURPOSE_METATX, DIGEST, _pAuth(false));
        (bool ok, bytes memory err) = address(g2).staticcall{gas: CAP_VO + 10_000}(call);
        assertFalse(ok);
        assertEq(err, abi.encodeWithSelector(UAKinds.UAVerifyGas.selector), "starved: UAVerifyGas");
        bytes memory pcall = abi.encodeCall(
            IUARegistry.requirePortable, (fnId, UAKinds.PURPOSE_PQCHAT, TYPED, _fnSig(UAKinds.PURPOSE_PQCHAT, false))
        );
        (ok, err) = address(g2).staticcall{gas: CAP_VO + 20_000}(pcall);
        assertFalse(ok);
        assertEq(err, abi.encodeWithSelector(UAKinds.UAVerifyGas.selector), "the portable path holds");
        assertTrue(_ok(g2, pId, _pAuth(false)), "with the gas: the holder's verdict");
    }

    /// P10 (N9): the group kinds' portable path holds too, at the cap `verifyBudget` (their holder's `verifyPop` runs the group check
    /// under it): a caller below `verifyBudget` plus its hold gets `UAVerifyGas`, never a fallback; with the gas, the verdict.
    function test_groupKind_verifyOnly_holds() public {
        string memory j = _kindsJson();
        uint256 i;
        while (vm.parseJsonUint(j, string.concat(".valid[", vm.toString(i), "].kind")) != UAKinds.MUSIG2_SECP256K1) {
            ++i;
        }
        bytes memory d = vm.parseJsonBytes(j, string.concat(".valid[", vm.toString(i), "].keyData"));
        UARegistry.KindConfig[] memory k = new UARegistry.KindConfig[](1);
        k[0] = UARegistry.KindConfig(UAKinds.MUSIG2_SECP256K1, address(mock), 400_000, false, 0);
        UARegistry h = _deploy(address(0x6f02), chainUidA, address(0), false, BUDGET, address(0), true, k);
        bytes32 ua = _register(h, UAKinds.MUSIG2_SECP256K1, d);
        k[0] =
            UARegistry.KindConfig(UAKinds.MUSIG2_SECP256K1, address(new VerifyOnlyStandIn(PC, 0, 1)), CAP_VO, true, 0);
        UARegistry g2 = _deploy(address(uint160(++at)), chainUidA, address(h), false, BUDGET, address(0), true, k);
        bytes memory call =
            abi.encodeCall(IUARegistry.requirePortable, (ua, UAKinds.PURPOSE_PQCHAT, TYPED, UACall.sig(hex"01")));
        (bool ok, bytes memory err) = address(g2).staticcall{gas: BUDGET + 50_000}(call);
        assertFalse(ok);
        assertEq(err, abi.encodeWithSelector(UAKinds.UAVerifyGas.selector), "held at verifyBudget");
        (ok,) = address(g2).staticcall{gas: BUDGET + BUDGET / 63 + 600_000}(call); // the library frame keeps 63/64
        assertTrue(ok, "with the gas: this generation's verdict");
    }

    /// N10: the fallback entry is the holder's entry for that path, the caller's `auth` unchanged: `requirePortableApp` with its
    /// `appId` (its derived purpose through `requirePortable` would be refused by the holder's closed list).
    function test_fallback_entry_perPath() public {
        UARegistry g2 = _over(address(g1), 3);
        vm.expectCall(
            address(g1),
            abi.encodeCall(IUARegistry.requirePortableApp, (fnId, APP, TYPED, _fnSig(UAKinds.appPurpose(APP), false)))
        );
        assertTrue(_portableOk(g2, true, false));
        vm.expectCall(
            address(g1),
            abi.encodeCall(
                IUARegistry.requirePortable,
                (fnId, UAKinds.PURPOSE_PQCHAT, TYPED, _fnSig(UAKinds.PURPOSE_PQCHAT, false))
            )
        );
        assertTrue(_portableOk(g2, false, false));
    }
}

/// A holder whose every read fails (F11).
contract FailingHolder {
    fallback() external {
        revert();
    }
}

/// A one-generation line whose `holderOf` names a `fndsa512` record at a `FailingHolder` (the probes of §11.3 answer).
contract ReadFailsLine {
    bytes32 public immutable chainUid;
    address public immutable holder;

    constructor(bytes32 chainUid_) {
        (chainUid, holder) = (chainUid_, address(new FailingHolder()));
    }

    function generation() external pure returns (uint8) {
        return 1;
    }

    function predecessor() external pure returns (address) {}

    function kindHome(uint16 kind) external view returns (address) {
        return kind == UAKinds.FNDSA512 || kind == 0x0101 ? address(this) : address(0);
    }

    function holderOf(bytes32) external view returns (address, uint16, address) {
        return (holder, UAKinds.FNDSA512, address(0));
    }

    function verifierOf(uint16) external pure returns (address) {}
    function verifyOnly(uint16) external pure returns (bool) {}
    function pqzHomeOf(bytes32) external pure returns (address) {}
    function expandedKeyOf(bytes32) external pure returns (address[3] memory) {}

    function txGasCap() external pure returns (uint64) {
        return 1 << 24;
    }

    function hederaNative() external pure returns (bool) {
        return false;
    }

    function kindEnabled(uint16) external pure returns (bool) {
        return false;
    }

    function kindOf(bytes32) external pure returns (uint16) {
        return UAKinds.FNDSA512;
    }

    function keyOwner(bytes32) external pure returns (bytes32) {}
    function checkedOf(bytes32) external pure returns (uint8, uint8, uint8) {}
    function memberSigHashOf(bytes32, uint256) external pure returns (bytes32) {}
    function msigStateOf(bytes32) external pure returns (uint64, uint256, uint256) {}
}
