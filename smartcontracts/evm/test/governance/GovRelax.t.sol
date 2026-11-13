// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {IAdmin} from "../../src/governance/IAdmin.sol";
import {GovernanceBase, GovernanceBaseCore, GovernanceUse} from "../../src/governance/GovernanceBase.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {GovernanceLib} from "../../src/governance/GovernanceLib.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {nid} from "../helpers/Ids.sol";
import {EnvKit} from "../helpers/EnvKit.sol";

/// `kindOf` from a table the test writes: an `msig` id, a single-key id, an unregistered one (0).
contract KindTable {
    mapping(bytes32 => uint16) public kinds;

    function set(bytes32 id, uint16 k) external { kinds[id] = k; }
    function kindOf(bytes32 id) external view returns (uint16) { return kinds[id]; }
}

/// An empty contract: a native holder with code.
contract Holder {}

/// The regulated masks a kind 8-13 passes (regulated-kinds spec §2.1, §3.6): roles 1, 3, 5, 6, 7, 10, 21; contract-only 3,
/// 5, 6, 7, 10, 21 (3 a native id only, RK-1); 22 `OPERATOR_TRANSFER` any holder (CTR-GOV-20); scalar 1, 6, 21, 22;
/// relaxation of 5, 6, 7 delayed. Round 3s (CTR-GOV-24): 8 and 9 are the lists, roles any holder (the issuer seat takes
/// them while they can be enabled). Through `GovernanceBase`'s own
/// wrappers, so the masks and the registry reach the library as a token passes them.
contract RelaxApp is GovernanceBase {
    uint256 internal constant ROLES =
        (1 << 1) | (1 << 3) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10) | (1 << 21) | (1 << 22);
    uint256 internal constant VALID = ROLES;
    uint256 internal constant ONLY = (1 << 3) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 10) | (1 << 21);
    uint256 internal constant SCALAR = (1 << 1) | (1 << 6) | (1 << 21) | (1 << 22);
    uint256 internal constant DELAYED = (1 << 5) | (1 << 6) | (1 << 7);
    address internal immutable REG;

    constructor(address reg) GovernanceBaseCore(address(0)) {
        REG = reg;
    }

    function init(uint256 features_, bytes32 owner_, uint64 delay, GovernanceLib.Roles memory roles) external {
        GovernanceLib.init(features_, 0, owner_, delay, address(0), roles, VALID, ROLES, ONLY, REG);
    }

    /// The power of `bit` for the caller, as a regulated entry runs it.
    function act(uint8 bit, uint256 x) external returns (bytes32) { return GovernanceUse.use(bit, _govSubject(), x); }

    /// The same power for a derived `subject`, as the router hands it to a governed entry (test stand-in for the router).
    function actFor(bytes32 subject, uint8 bit, uint256 x) external returns (bytes32) {
        return GovernanceUse.use(bit, subject, x);
    }

    /// `GovernanceLib.disableFeature`'s answer, which a regulated override reads before it clears its mirror.
    function disableApplied(uint8 bit) external returns (bool) {
        return GovernanceLib.disableFeature(bit, _govSubject(), DELAYED);
    }

    function barred(uint8 bit, bytes32 a) external view returns (bool) { return GovernanceLib.$().grants[bit][a].barred; }

    function _guardIn() internal pure override returns (bool) { return false; }
    function _guardOut(bool) internal pure override {}
    function _caller() internal view override returns (address) { return msg.sender; }
    /// @dev A test app has no chain word (not factory-made); its renounce is not exercised by chain (Fable recheck-2 P3-1).
    function _govChainUid() internal pure override returns (bytes32) { return bytes32(0); }
    function _validBits() internal pure override returns (uint256) { return VALID; }
    function _roleBits() internal pure override returns (uint256) { return ROLES; }
    function _contractOnlyBits() internal pure override returns (uint256) { return ONLY; }
    function _scalarBits() internal pure override returns (uint256) { return SCALAR; }
    function _scopeBits() internal pure override returns (uint256) { return 0; }
    function _delayedRelaxBits() internal pure override returns (uint256) { return DELAYED; }
    function _uaRegistry() internal view override returns (address) { return REG; }
}

/// @notice ua-mtx-merge T24: `GovernanceLib`'s relaxation state machine (regulated-kinds spec §3.6, RK-2, RK-3, CTR-GOV-09),
///         threshold holders of the regulated contract-only bits (RK-1, CTR-AS-03 Change), the issuer and compliance roles
///         at `init` and `RoleConflict`. Each refusal beside its positive control.
contract GovRelaxTest is Test {
    uint8 constant FREEZE = 5;
    uint8 constant FORCE = 6;
    uint8 constant PAUSE = 7;
    uint8 constant RECORD = 10;
    uint8 constant RATE = 3;
    uint8 constant REVOKE = 3;
    uint8 constant RENOUNCE = 4;
    uint8 constant DISABLE = 5;
    uint64 constant D = 2 days;
    uint128 constant NONE = type(uint128).max;
    uint8 constant MODERATE = 21;
    uint8 constant OPERATOR = 22;
    uint256 constant FEATURES = (1 << 1) | (1 << 3) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 10) | (1 << 21) | (1 << 22);
    address constant OWNER = address(0x0A);
    address constant NEXT = address(0x0D);
    address constant STRANGER = address(0x0E);
    bytes32 constant MSIG = keccak256("an msig UA");
    bytes32 constant SINGLE = keccak256("a single-key derived UA");

    KindTable reg;
    RelaxApp a;
    address issuer;
    address compliance;
    address other;

    function setUp() public {
        reg = new KindTable();
        reg.set(MSIG, UAKinds.MSIG);
        reg.set(SINGLE, 0x0101);
        issuer = address(new Holder());
        compliance = address(new Holder());
        other = address(new Holder());
        a = _app(D, _roles(nid(issuer), nid(compliance)), FEATURES);
    }

    function _roles(bytes32 iss, bytes32 comp) internal pure returns (GovernanceLib.Roles memory r) {
        (r.issuer, r.compliance) = (iss, comp);
    }

    function _app(uint64 delay, GovernanceLib.Roles memory r, uint256 features_) internal returns (RelaxApp x) {
        x = new RelaxApp(address(reg));
        x.init(features_, nid(OWNER), delay, r);
    }

    function _commit(uint8 action, uint8 bit, bytes32 account) internal pure returns (bytes32) {
        return keccak256(abi.encode(action, bit, account, bytes32(0)));
    }

    function _live(uint8 bit, bytes32 account) internal view returns (bool live) {
        (,,, live) = a.pendingGrant(bit, account);
    }

    /// Terms of a scalarless bit (5, 7): only `validUntil`, `maxUses` and `delegable` bind.
    function _t(uint64 validUntil, uint32 maxUses, bool delegable) internal pure returns (IGovernance.GrantTerms memory t) {
        (t.max, t.validUntil, t.maxUses, t.delegable) = (NONE, validUntil, maxUses, delegable);
    }

    // ------------------------------------------------------------------ init: issuer and compliance

    function test_initGrantsIssuerAndCompliance() public view {
        for (uint8 b = FREEZE; b <= PAUSE; ++b) assertTrue(a.hasRole(b, nid(issuer)), "issuer holds each of 5-7");
        assertTrue(a.hasRole(RECORD, nid(compliance)), "compliance holds 10");
        assertFalse(a.hasRole(RECORD, nid(issuer)));
        assertEq(a.holderCount(FREEZE), 1);
    }

    /// Positive control beside it: the issuer takes only the set bits of 5-7 (round 3s: and the list bits 8, 9 while they can
    /// be enabled, spec §6.3).
    function test_initIssuerTakesOnlySetBits() public {
        RelaxApp x = _app(D, _roles(nid(issuer), 0), (1 << 5) | (1 << 7));
        assertTrue(x.hasRole(FREEZE, nid(issuer)));
        assertTrue(x.hasRole(PAUSE, nid(issuer)));
        assertFalse(x.hasRole(FORCE, nid(issuer)));
        assertTrue(x.hasRole(8, nid(issuer)) && x.hasRole(9, nid(issuer)), "round 3s: the list bits, off and enableable");
        x = new RelaxApp(address(reg));
        x.init(1 << 1, nid(OWNER), D, _roles(nid(issuer), 0)); // round 3s: a seat of the list bits alone (was RoleWithoutFeature)
        assertFalse(x.hasRole(FREEZE, nid(issuer)));
        assertTrue(x.hasRole(8, nid(issuer)));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleWithoutFeature.selector, RECORD));
        x.init(1 << 5, nid(OWNER), D, _roles(0, nid(compliance)));
    }

    // ------------------------------------------------------------------ two calls on a masked bit

    function test_relaxRevokeTakesTwoCalls() public {
        vm.prank(OWNER);
        a.revokeRole(FREEZE, nid(issuer), EnvKit.codeUidOf(address(a)));
        assertTrue(a.hasRole(FREEZE, nid(issuer)), "proposal: still a holder");
        (uint64 eta, bytes32 proposer, bytes32 commit, bool live) = a.pendingGrant(FREEZE, nid(issuer));
        assertEq(eta, block.timestamp + D);
        assertEq(proposer, nid(OWNER));
        assertEq(commit, _commit(REVOKE, FREEZE, nid(issuer)));
        assertTrue(live);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantNotReady.selector, FREEZE, nid(issuer), eta));
        vm.prank(OWNER);
        a.revokeRole(FREEZE, nid(issuer), EnvKit.codeUidOf(address(a)));
        vm.warp(eta);
        vm.prank(OWNER);
        a.revokeRole(FREEZE, nid(issuer), EnvKit.codeUidOf(address(a)));
        assertFalse(a.hasRole(FREEZE, nid(issuer)), "confirm: gone");
        assertTrue(a.barred(FREEZE, nid(issuer)), "the owner's revoke bars at the confirm");
        assertFalse(_live(FREEZE, nid(issuer)));
    }

    function test_relaxRenounceTakesTwoCalls() public {
        vm.prank(issuer);
        a.renounceRole(FORCE, EnvKit.codeUidOf(address(a)));
        assertTrue(a.hasRole(FORCE, nid(issuer)));
        (,, bytes32 commit,) = a.pendingGrant(FORCE, nid(issuer));
        assertEq(commit, _commit(RENOUNCE, FORCE, nid(issuer)));
        vm.warp(block.timestamp + D);
        vm.prank(issuer);
        a.renounceRole(FORCE, EnvKit.codeUidOf(address(a)));
        assertFalse(a.hasRole(FORCE, nid(issuer)));
        assertFalse(a.barred(FORCE, nid(issuer)), "a renounce bars nothing");
    }

    function test_relaxDisableTakesTwoCalls() public {
        vm.prank(OWNER);
        a.disableFeature(PAUSE, EnvKit.codeUidOf(address(a)));
        assertTrue(a.features() & (1 << PAUSE) != 0, "proposal: the feature stays");
        (,, bytes32 commit, bool live) = a.pendingGrant(PAUSE, 0);
        assertEq(commit, _commit(DISABLE, PAUSE, 0));
        assertTrue(live, "keyed (bit, 0)");
        vm.warp(block.timestamp + D);
        vm.prank(OWNER);
        a.disableFeature(PAUSE, EnvKit.codeUidOf(address(a)));
        assertEq(a.features() & (1 << PAUSE), 0);
    }

    function test_disableReturnsAppliedOnlyAtConfirm() public {
        vm.prank(OWNER);
        assertFalse(a.disableApplied(FREEZE), "proposal: not applied");
        vm.warp(block.timestamp + D - 1);
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantNotReady.selector, FREEZE, bytes32(0), uint64(1 + D)));
        a.disableApplied(FREEZE);
        vm.warp(block.timestamp + 1);
        vm.prank(OWNER);
        assertTrue(a.disableApplied(FREEZE), "confirm: applied");
        // positive control: an unmasked bit applies in one call
        vm.prank(OWNER);
        assertTrue(a.disableApplied(RECORD));
    }

    /// Owner path and leaf path: terms that end before `now + grantDelay` wait; terms that end after are a narrowing (one call).
    function test_relaxSetGrantShortValidUntilTakesTwoCalls() public {
        uint64 cut = uint64(block.timestamp + D - 1);
        vm.prank(OWNER);
        a.setGrant(PAUSE, nid(issuer), _t(cut, 0, false), EnvKit.codeUidOf(address(a)));
        assertEq(a.grantOf(PAUSE, nid(issuer)).validUntil, 0, "owner path, proposal: nothing written");
        assertTrue(_live(PAUSE, nid(issuer)));
        vm.prank(issuer);
        a.act(PAUSE, 0); // still acts
        vm.warp(block.timestamp + D);
        vm.prank(OWNER);
        a.setGrant(PAUSE, nid(issuer), _t(cut, 0, false), EnvKit.codeUidOf(address(a)));
        assertEq(a.grantOf(PAUSE, nid(issuer)).validUntil, cut, "owner path, confirm: written");
        // positive control: a cut past `now + grantDelay` is a narrowing, one call
        uint64 far = uint64(block.timestamp + D + 1);
        vm.prank(OWNER);
        a.setGrant(FREEZE, nid(issuer), _t(far, 0, false), EnvKit.codeUidOf(address(a)));
        assertEq(a.grantOf(FREEZE, nid(issuer)).validUntil, far, "narrowing past the delay: at once");

        // leaf path: the issuer's delegable grant on 5 (owner, two calls), then a leaf with a short validUntil
        vm.prank(OWNER);
        a.setGrant(FREEZE, nid(issuer), _t(0, 10, true), EnvKit.codeUidOf(address(a)));
        vm.warp(block.timestamp + D);
        vm.prank(OWNER);
        a.setGrant(FREEZE, nid(issuer), _t(0, 10, true), EnvKit.codeUidOf(address(a)));
        uint64 leafCut = uint64(block.timestamp + D - 1);
        vm.prank(issuer);
        a.setGrant(FREEZE, nid(other), _t(leafCut, 1, false), EnvKit.codeUidOf(address(a)));
        assertFalse(a.hasRole(FREEZE, nid(other)), "leaf path, proposal: no leaf yet");
        (, bytes32 proposer,,) = a.pendingGrant(FREEZE, nid(other));
        assertEq(proposer, nid(issuer));
        vm.warp(block.timestamp + D);
        vm.prank(issuer);
        a.setGrant(FREEZE, nid(other), _t(leafCut, 1, false), EnvKit.codeUidOf(address(a)));
        assertTrue(a.hasRole(FREEZE, nid(other)), "leaf path, confirm: the leaf");
        // positive control: a leaf whose validUntil is past the delay is set at once
        address leaf2 = address(new Holder());
        vm.prank(issuer);
        a.setGrant(FREEZE, nid(leaf2), _t(uint64(block.timestamp + D + 1), 1, false), EnvKit.codeUidOf(address(a)));
        assertTrue(a.hasRole(FREEZE, nid(leaf2)));
    }

    /// RK-3: a proposal of each relaxation changes nothing: the role acts, `features` and `barred` stay.
    function test_proposeChangesNothing() public {
        vm.prank(OWNER);
        a.revokeRole(FREEZE, nid(issuer), EnvKit.codeUidOf(address(a)));
        vm.prank(issuer);
        a.renounceRole(FORCE, EnvKit.codeUidOf(address(a)));
        vm.prank(OWNER);
        a.disableFeature(PAUSE, EnvKit.codeUidOf(address(a)));
        assertEq(a.features(), FEATURES, "features unchanged");
        assertFalse(a.barred(FREEZE, nid(issuer)), "not barred");
        for (uint8 b = FREEZE; b <= PAUSE; ++b) {
            assertTrue(a.hasRole(b, nid(issuer)));
            vm.prank(issuer);
            a.act(b, 1);
        }
        assertEq(a.holderCount(FREEZE), 1);
    }

    // ------------------------------------------------------------------ one pending per key, the proposer only

    function test_grantThenRevokeExclude() public {
        vm.prank(OWNER);
        a.grantRole(FREEZE, nid(other), EnvKit.codeUidOf(address(a)));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantTermsMismatch.selector, FREEZE, nid(other)));
        vm.prank(OWNER);
        a.revokeRole(FREEZE, nid(other), EnvKit.codeUidOf(address(a)));
        vm.warp(block.timestamp + D);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantTermsMismatch.selector, FREEZE, nid(other)));
        vm.prank(OWNER);
        a.revokeRole(FREEZE, nid(other), EnvKit.codeUidOf(address(a)));
        // positive control: the grant confirms
        vm.prank(OWNER);
        a.grantRole(FREEZE, nid(other), EnvKit.codeUidOf(address(a)));
        assertTrue(a.hasRole(FREEZE, nid(other)));
    }

    function test_revokeThenGrantExclude() public {
        vm.prank(OWNER);
        a.revokeRole(FREEZE, nid(other), EnvKit.codeUidOf(address(a))); // a non-holder: the bar at the confirm
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantTermsMismatch.selector, FREEZE, nid(other)));
        vm.prank(OWNER);
        a.grantRole(FREEZE, nid(other), EnvKit.codeUidOf(address(a)));
        vm.prank(OWNER);
        a.revokeRole(PAUSE, nid(issuer), EnvKit.codeUidOf(address(a)));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantTermsMismatch.selector, PAUSE, nid(issuer)));
        vm.prank(OWNER);
        a.setGrant(PAUSE, nid(issuer), _t(0, 5, true), EnvKit.codeUidOf(address(a))); // a widening: a pure narrowing applies at once (spec §1.6)
        // positive control: cancel, then the grant proposes
        vm.prank(OWNER);
        a.cancelGrant(FREEZE, nid(other), EnvKit.codeUidOf(address(a)));
        vm.prank(OWNER);
        a.grantRole(FREEZE, nid(other), EnvKit.codeUidOf(address(a)));
        assertTrue(_live(FREEZE, nid(other)));
    }

    /// Fable D P2-1: a holder's live pending does not block the owner. The owner's revoke proposes over the issuer's
    /// renounce (it does not confirm it); the issuer can neither confirm nor replace nor cancel the owner's proposal; the
    /// owner confirms after `grantDelay` and bars. Negative control: the holder over the owner's live pending still reverts.
    function test_ownerProposesOverHolderPending() public {
        vm.prank(issuer);
        a.renounceRole(FREEZE, EnvKit.codeUidOf(address(a)));
        vm.prank(OWNER);
        a.revokeRole(FREEZE, nid(issuer), EnvKit.codeUidOf(address(a))); // proposes over the renounce
        assertTrue(a.hasRole(FREEZE, nid(issuer)), "proposal only");
        (uint64 eta, bytes32 proposer, bytes32 commit, bool live) = a.pendingGrant(FREEZE, nid(issuer));
        assertEq(proposer, nid(OWNER));
        assertEq(commit, _commit(REVOKE, FREEZE, nid(issuer)));
        assertEq(eta, block.timestamp + D);
        assertTrue(live);
        vm.prank(issuer);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantTermsMismatch.selector, FREEZE, nid(issuer)));
        a.renounceRole(FREEZE, EnvKit.codeUidOf(address(a))); // the squat: refused over the owner's proposal
        vm.prank(issuer);
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotAdmin.selector, nid(issuer)));
        a.cancelGrant(FREEZE, nid(issuer), EnvKit.codeUidOf(address(a)));
        vm.warp(eta);
        vm.prank(OWNER);
        a.revokeRole(FREEZE, nid(issuer), EnvKit.codeUidOf(address(a)));
        assertFalse(a.hasRole(FREEZE, nid(issuer)));
        assertTrue(a.barred(FREEZE, nid(issuer)));

        // a delegable holder's leaf proposal at `(bit, X)` does not block the owner's grant to X either
        vm.prank(OWNER);
        a.setGrant(PAUSE, nid(issuer), _t(0, 10, true), EnvKit.codeUidOf(address(a)));
        vm.warp(block.timestamp + D);
        vm.prank(OWNER);
        a.setGrant(PAUSE, nid(issuer), _t(0, 10, true), EnvKit.codeUidOf(address(a)));
        vm.prank(issuer);
        a.setGrant(PAUSE, nid(other), _t(uint64(block.timestamp + D - 1), 1, false), EnvKit.codeUidOf(address(a))); // a leaf proposal at (7, other)
        (, proposer,,) = a.pendingGrant(PAUSE, nid(other));
        assertEq(proposer, nid(issuer));
        vm.prank(OWNER);
        a.grantRole(PAUSE, nid(other), EnvKit.codeUidOf(address(a)));
        (, proposer, commit,) = a.pendingGrant(PAUSE, nid(other));
        assertEq(proposer, nid(OWNER));
        assertEq(commit, _commit(1, PAUSE, nid(other)));
        vm.warp(block.timestamp + D);
        vm.prank(OWNER);
        a.grantRole(PAUSE, nid(other), EnvKit.codeUidOf(address(a)));
        assertTrue(a.hasRole(PAUSE, nid(other)));
    }

    /// The other proposer may still confirm its own pending when the owner does not propose over it (positive control).
    function test_holderConfirmsOwnRenounce() public {
        vm.prank(issuer);
        a.renounceRole(FREEZE, EnvKit.codeUidOf(address(a)));
        vm.warp(block.timestamp + D);
        vm.prank(issuer);
        a.renounceRole(FREEZE, EnvKit.codeUidOf(address(a)));
        assertFalse(a.hasRole(FREEZE, nid(issuer)));
        assertFalse(a.barred(FREEZE, nid(issuer)));
    }

    /// Fable re-check C1, C2: every word that narrows a delayed bit's holder is a cut. FORCE (scalar) rows: a `total`, a
    /// `perWindow` and a raised `min` on the `WHOLE` issuer only propose (the issuer keeps forcing); a `LIMITED` root whose
    /// `delegable` is dropped (its leaves would die at once) only proposes. Control: the same terms confirm after the delay.
    function test_relaxSetGrantEveryNarrowingIsACut() public {
        IGovernance.GrantTerms[3] memory f;
        (f[0].max, f[0].total) = (NONE, 1);
        (f[1].max, f[1].perWindow, f[1].window) = (NONE, 1, 1 days);
        (f[2].max, f[2].min) = (NONE, 5);
        for (uint256 i; i < 3; ++i) {
            vm.prank(OWNER);
            a.setGrant(FORCE, nid(issuer), f[i], EnvKit.codeUidOf(address(a)));
            assertTrue(_live(FORCE, nid(issuer)), "FORCE narrowing: proposed");
            assertTrue(a.hasRole(FORCE, nid(issuer)));
            vm.prank(issuer);
            a.act(FORCE, 10); // still WHOLE: 10 > total 1, perWindow 1, and below min 5 would fail if written
            vm.prank(OWNER);
            a.cancelGrant(FORCE, nid(issuer), EnvKit.codeUidOf(address(a)));
        }
        vm.prank(OWNER);
        a.setGrant(FORCE, nid(issuer), f[0], EnvKit.codeUidOf(address(a)));
        vm.warp(block.timestamp + D);
        vm.prank(OWNER);
        a.setGrant(FORCE, nid(issuer), f[0], EnvKit.codeUidOf(address(a)));
        assertEq(a.grantOf(FORCE, nid(issuer)).total, 1, "control: confirmed after the delay");

        // C2: a LIMITED delegable root on FREEZE; dropping `delegable` is a cut
        vm.prank(OWNER);
        a.setGrant(FREEZE, nid(issuer), _t(0, 10, true), EnvKit.codeUidOf(address(a)));
        vm.warp(block.timestamp + D);
        vm.prank(OWNER);
        a.setGrant(FREEZE, nid(issuer), _t(0, 10, true), EnvKit.codeUidOf(address(a)));
        vm.prank(issuer);
        a.setGrant(FREEZE, nid(other), _t(uint64(block.timestamp + D + 1), 1, false), EnvKit.codeUidOf(address(a))); // a leaf, at once
        vm.prank(OWNER);
        a.setGrant(FREEZE, nid(issuer), _t(0, 10, false), EnvKit.codeUidOf(address(a)));
        assertTrue(a.grantOf(FREEZE, nid(issuer)).delegable, "delegable dropped: proposed only");
        assertTrue(_live(FREEZE, nid(issuer)));
        vm.prank(other);
        a.act(FREEZE, 0); // the leaf lives until the confirm
    }

    /// Fable D P2-2, A-4: on a delayed bit a new or lower `maxUses`, or a lower `max`, is a cut like a `validUntil` cut: the
    /// owner's call only proposes, the holder keeps acting until the confirm; the grantor's on its leaf likewise. Positive
    /// controls: the same terms apply at once on an unmasked bit, and a delayed-bit narrowing of neither word applies at once.
    function test_relaxSetGrantMaxUsesAndMaxAreCuts() public {
        vm.prank(OWNER);
        a.setGrant(FREEZE, nid(issuer), _t(0, 1, false), EnvKit.codeUidOf(address(a))); // WHOLE -> maxUses 1
        assertEq(a.grantOf(FREEZE, nid(issuer)).maxUses, 0, "proposal: nothing written");
        (, bytes32 proposer,, bool live) = a.pendingGrant(FREEZE, nid(issuer));
        assertTrue(live);
        assertEq(proposer, nid(OWNER));
        for (uint256 i; i < 3; ++i) {
            vm.prank(issuer);
            a.act(FREEZE, 0); // still unbounded
        }
        vm.warp(block.timestamp + D);
        vm.prank(OWNER);
        a.setGrant(FREEZE, nid(issuer), _t(0, 1, false), EnvKit.codeUidOf(address(a)));
        assertEq(a.grantOf(FREEZE, nid(issuer)).maxUses, 1, "confirm: written");

        // FORCE (scalar): a lower `max` waits
        IGovernance.GrantTerms memory f;
        f.max = 0;
        vm.prank(OWNER);
        a.setGrant(FORCE, nid(issuer), f, EnvKit.codeUidOf(address(a)));
        assertTrue(_live(FORCE, nid(issuer)), "max cut: proposed");
        vm.prank(issuer);
        a.act(FORCE, 5);

        // a LIMITED holder: a lower maxUses waits, an equal one is no cut
        vm.prank(OWNER);
        a.setGrant(PAUSE, nid(issuer), _t(0, 10, true), EnvKit.codeUidOf(address(a)));
        vm.warp(block.timestamp + D);
        vm.prank(OWNER);
        a.setGrant(PAUSE, nid(issuer), _t(0, 10, true), EnvKit.codeUidOf(address(a)));
        vm.prank(OWNER);
        a.setGrant(PAUSE, nid(issuer), _t(0, 9, true), EnvKit.codeUidOf(address(a)));
        assertEq(a.grantOf(PAUSE, nid(issuer)).maxUses, 10, "LIMITED, lower maxUses: proposed");
        vm.prank(OWNER);
        a.cancelGrant(PAUSE, nid(issuer), EnvKit.codeUidOf(address(a)));
        uint64 far = uint64(block.timestamp + D + 1);
        vm.prank(OWNER);
        a.setGrant(PAUSE, nid(issuer), _t(far, 10, true), EnvKit.codeUidOf(address(a))); // control: a narrowing of validUntil alone, past the delay
        assertEq(a.grantOf(PAUSE, nid(issuer)).validUntil, far, "no cut: at once");

        // leaf path: the grantor lowers its leaf's maxUses
        vm.prank(issuer);
        a.setGrant(PAUSE, nid(other), _t(far, 5, false), EnvKit.codeUidOf(address(a))); // a new leaf: at once
        assertEq(a.grantOf(PAUSE, nid(other)).maxUses, 5);
        vm.prank(issuer);
        a.setGrant(PAUSE, nid(other), _t(far, 1, false), EnvKit.codeUidOf(address(a)));
        assertEq(a.grantOf(PAUSE, nid(other)).maxUses, 5, "leaf cut: proposed");
        assertTrue(_live(PAUSE, nid(other)));

        // control: an unmasked bit (RECORD) takes the same cut at once
        vm.prank(OWNER);
        a.setGrant(RECORD, nid(compliance), _t(0, 1, false), EnvKit.codeUidOf(address(a)));
        assertEq(a.grantOf(RECORD, nid(compliance)).maxUses, 1, "unmasked: at once");
    }

    /// The holder cannot turn the owner's revoke into its renounce; a grantor cannot confirm the owner's revoke of its leaf
    /// (same action, another proposer: `NotProposer`).
    function test_holderCannotConfirmOwnerRevoke() public {
        vm.prank(OWNER);
        a.revokeRole(FREEZE, nid(issuer), EnvKit.codeUidOf(address(a)));
        vm.warp(block.timestamp + D);
        vm.prank(issuer);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantTermsMismatch.selector, FREEZE, nid(issuer)));
        a.renounceRole(FREEZE, EnvKit.codeUidOf(address(a)));
        vm.prank(OWNER);
        a.cancelGrant(FREEZE, nid(issuer), EnvKit.codeUidOf(address(a)));

        // a leaf of the issuer on 5
        vm.prank(OWNER);
        a.setGrant(FREEZE, nid(issuer), _t(0, 10, true), EnvKit.codeUidOf(address(a)));
        vm.warp(block.timestamp + D);
        vm.prank(OWNER);
        a.setGrant(FREEZE, nid(issuer), _t(0, 10, true), EnvKit.codeUidOf(address(a)));
        vm.prank(issuer);
        a.setGrant(FREEZE, nid(other), _t(0, 1, false), EnvKit.codeUidOf(address(a)));
        vm.prank(OWNER);
        a.revokeRole(FREEZE, nid(other), EnvKit.codeUidOf(address(a)));
        vm.warp(block.timestamp + D);
        vm.prank(issuer);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotProposer.selector, FREEZE, nid(other), nid(OWNER)));
        a.revokeRole(FREEZE, nid(other), EnvKit.codeUidOf(address(a)));
        assertTrue(a.hasRole(FREEZE, nid(other)));
        assertFalse(a.barred(FREEZE, nid(other)));
        // positive control: the owner confirms its own, and bars
        vm.prank(OWNER);
        a.revokeRole(FREEZE, nid(other), EnvKit.codeUidOf(address(a)));
        assertFalse(a.hasRole(FREEZE, nid(other)));
        assertTrue(a.barred(FREEZE, nid(other)));
    }

    function test_acceptAdminKillsPendingRelax() public {
        vm.prank(OWNER);
        a.revokeRole(FREEZE, nid(issuer), EnvKit.codeUidOf(address(a)));
        vm.prank(issuer);
        a.renounceRole(FORCE, EnvKit.codeUidOf(address(a)));
        vm.prank(OWNER);
        a.disableFeature(PAUSE, EnvKit.codeUidOf(address(a)));
        vm.prank(OWNER);
        a.transferAdmin(nid(NEXT), bytes32(0)); // a test app: no chain word
        assertTrue(_live(FREEZE, nid(issuer)), "control: live before the accept");
        vm.prank(NEXT);
        a.acceptAdmin();
        assertFalse(_live(FREEZE, nid(issuer)));
        assertFalse(_live(FORCE, nid(issuer)), "a holder's renounce dies too");
        assertFalse(_live(PAUSE, 0));
        vm.warp(block.timestamp + D);
        vm.prank(NEXT);
        a.revokeRole(FREEZE, nid(issuer), EnvKit.codeUidOf(address(a)));
        assertTrue(a.hasRole(FREEZE, nid(issuer)), "the new owner proposes anew");
        vm.prank(issuer);
        a.renounceRole(FORCE, EnvKit.codeUidOf(address(a)));
        assertTrue(a.hasRole(FORCE, nid(issuer)), "the holder proposes anew");
        vm.prank(NEXT);
        a.disableFeature(PAUSE, EnvKit.codeUidOf(address(a)));
        assertTrue(a.features() & (1 << PAUSE) != 0);
    }

    function test_confirmAfterWindowProposesAgain() public {
        vm.prank(OWNER);
        a.revokeRole(FREEZE, nid(issuer), EnvKit.codeUidOf(address(a)));
        vm.warp(block.timestamp + 2 * D + 1);
        assertFalse(_live(FREEZE, nid(issuer)));
        vm.expectEmit(true, true, false, true, address(a));
        emit IGovernance.RelaxProposed(FREEZE, nid(issuer), REVOKE, nid(OWNER), uint64(block.timestamp + D));
        vm.prank(OWNER);
        a.revokeRole(FREEZE, nid(issuer), EnvKit.codeUidOf(address(a)));
        assertTrue(a.hasRole(FREEZE, nid(issuer)), "a late confirm only proposes");
        // positive control: in the new window it applies
        vm.warp(block.timestamp + 2 * D);
        vm.prank(OWNER);
        a.revokeRole(FREEZE, nid(issuer), EnvKit.codeUidOf(address(a)));
        assertFalse(a.hasRole(FREEZE, nid(issuer)));
    }

    function test_cancelByProposer() public {
        vm.prank(issuer);
        a.renounceRole(FREEZE, EnvKit.codeUidOf(address(a)));
        vm.prank(STRANGER);
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotAdmin.selector, nid(STRANGER)));
        a.cancelGrant(FREEZE, nid(issuer), EnvKit.codeUidOf(address(a)));
        vm.prank(compliance); // a holder of another bit, not the proposer
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotAdmin.selector, nid(compliance)));
        a.cancelGrant(FREEZE, nid(issuer), EnvKit.codeUidOf(address(a)));
        vm.expectEmit(true, true, true, true, address(a));
        emit IGovernance.GrantCancelled(FREEZE, nid(issuer), nid(issuer));
        vm.prank(issuer);
        a.cancelGrant(FREEZE, nid(issuer), EnvKit.codeUidOf(address(a)));
        (uint64 eta,,,) = a.pendingGrant(FREEZE, nid(issuer));
        assertEq(eta, 0);
        // positive control: the owner cancels any pending
        vm.prank(issuer);
        a.renounceRole(FORCE, EnvKit.codeUidOf(address(a)));
        vm.prank(OWNER);
        a.cancelGrant(FORCE, nid(issuer), EnvKit.codeUidOf(address(a)));
        assertFalse(_live(FORCE, nid(issuer)));
    }

    // ------------------------------------------------------------------ unmasked, or no delay: one call

    function test_unmaskedBitsOneCallAsToday() public {
        vm.prank(OWNER);
        a.revokeRole(RECORD, nid(compliance), EnvKit.codeUidOf(address(a)));
        assertFalse(a.hasRole(RECORD, nid(compliance)), "bit 10 is not delayed (runbook)");
        assertTrue(a.barred(RECORD, nid(compliance)));
        vm.prank(OWNER);
        a.disableFeature(RECORD, EnvKit.codeUidOf(address(a)));
        assertEq(a.features() & (1 << RECORD), 0);
        // a grant keeps its two calls on every bit
        vm.prank(OWNER);
        a.grantRole(1, nid(other), EnvKit.codeUidOf(address(a)));
        assertFalse(a.hasRole(1, nid(other)));
    }

    function test_grantDelayZeroOneCall() public {
        a = _app(0, _roles(nid(issuer), nid(compliance)), FEATURES);
        vm.prank(OWNER);
        a.revokeRole(FREEZE, nid(issuer), EnvKit.codeUidOf(address(a)));
        assertFalse(a.hasRole(FREEZE, nid(issuer)));
        vm.prank(issuer);
        a.renounceRole(FORCE, EnvKit.codeUidOf(address(a)));
        assertFalse(a.hasRole(FORCE, nid(issuer)));
        vm.prank(OWNER);
        assertTrue(a.disableApplied(PAUSE));
    }

    // ------------------------------------------------------------------ RK-1: who may hold a regulated contract-only bit

    function test_msigIssuerGranted() public {
        vm.prank(OWNER);
        a.grantRole(FREEZE, MSIG, EnvKit.codeUidOf(address(a)));
        vm.warp(block.timestamp + D);
        vm.prank(OWNER);
        a.grantRole(FREEZE, MSIG, EnvKit.codeUidOf(address(a)));
        assertTrue(a.hasRole(FREEZE, MSIG));
        RelaxApp x = _app(D, _roles(MSIG, 0), FEATURES);
        assertTrue(x.hasRole(FORCE, MSIG), "init: an msig issuer");
        // the kind is read at the grant, never at a use: a later kind change moves nothing
        reg.set(MSIG, 0x0101);
        assertTrue(x.hasRole(FORCE, MSIG));
    }

    function test_singleKeyDerivedIssuerRefused() public {
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleNotContract.selector, FREEZE, SINGLE));
        vm.prank(OWNER);
        a.grantRole(FREEZE, SINGLE, EnvKit.codeUidOf(address(a)));
        bytes32 unknown = keccak256("not registered");
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleNotContract.selector, RECORD, unknown));
        vm.prank(OWNER);
        a.grantRole(RECORD, unknown, EnvKit.codeUidOf(address(a)));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleNotContract.selector, FREEZE, nid(STRANGER)));
        vm.prank(OWNER);
        a.grantRole(FREEZE, nid(STRANGER), EnvKit.codeUidOf(address(a))); // a native id without code
        RelaxApp x = new RelaxApp(address(reg));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleNotContract.selector, FREEZE, SINGLE));
        x.init(FEATURES, nid(OWNER), D, _roles(SINGLE, 0));
        // positive control: the msig proposes
        vm.prank(OWNER);
        a.grantRole(FREEZE, MSIG, EnvKit.codeUidOf(address(a)));
        assertTrue(_live(FREEZE, MSIG));
    }

    function test_msigRefusedForRateAdmin() public {
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleNotContract.selector, RATE, MSIG));
        vm.prank(OWNER);
        a.grantRole(RATE, MSIG, EnvKit.codeUidOf(address(a)));
        // positive control: a native id with code
        vm.prank(OWNER);
        a.grantRole(RATE, nid(other), EnvKit.codeUidOf(address(a)));
        assertTrue(_live(RATE, nid(other)));
    }

    function test_selfRefusedAsHolder() public {
        bytes32 self = nid(address(a));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleAccountPool.selector, FREEZE, self));
        vm.prank(OWNER);
        a.grantRole(FREEZE, self, EnvKit.codeUidOf(address(a)));
        RelaxApp x = new RelaxApp(address(reg));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleAccountPool.selector, FREEZE, nid(address(x))));
        x.init(FEATURES, nid(OWNER), D, _roles(nid(address(x)), 0));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.AdminAccountPool.selector, nid(address(x))));
        x.init(FEATURES, nid(address(x)), D, _roles(0, 0));
        // positive control
        vm.prank(OWNER);
        a.grantRole(FREEZE, nid(other), EnvKit.codeUidOf(address(a)));
    }

    /// CTR-GOV-20 (owner 2026-11-05): bit 22 `OPERATOR_TRANSFER` takes any holder. An EOA (a clerk at the point of sale)
    /// and a single-key UA, `LIMITED` with a daily `perWindow`, act within it and are refused past it; `WHOLE` for an
    /// operator; bits 5, 6, 7, 10 and 21 still refuse an EOA and a single-key UA.
    function test_operatorTransferAnyHolderLimitedDaily() public {
        address clerk = address(0xC1E2); // an EOA: no code
        IGovernance.GrantTerms memory t;
        (t.max, t.perWindow, t.window) = (NONE, 100, 1 days);
        bytes32[2] memory ids = [nid(clerk), SINGLE];
        for (uint256 i; i < 2; ++i) {
            vm.prank(OWNER);
            a.setGrant(OPERATOR, ids[i], t, EnvKit.codeUidOf(address(a)));
            vm.warp(block.timestamp + D);
            vm.prank(OWNER);
            a.setGrant(OPERATOR, ids[i], t, EnvKit.codeUidOf(address(a)));
            assertTrue(a.hasRole(OPERATOR, ids[i]), "any holder of bit 22");
        }
        uint256 day = block.timestamp - block.timestamp % 1 days;
        vm.warp(day + 1 hours);
        vm.startPrank(clerk);
        a.act(OPERATOR, 60);
        a.act(OPERATOR, 40); // the day's cap reached
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantExhausted.selector, uint8(3)));
        a.act(OPERATOR, 1);
        vm.warp(day + 1 days); // the next window
        a.act(OPERATOR, 100);
        vm.stopPrank();
        a.actFor(SINGLE, OPERATOR, 100); // the single-key UA: its own window
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantExhausted.selector, uint8(3)));
        a.actFor(SINGLE, OPERATOR, 1);
        // bits 5, 6, 7, 10, 21 still refuse an EOA and a single-key UA
        uint8[5] memory only = [FREEZE, FORCE, PAUSE, RECORD, MODERATE];
        for (uint256 i; i < 5; ++i) {
            vm.prank(OWNER);
            vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleNotContract.selector, only[i], nid(clerk)));
            a.grantRole(only[i], nid(clerk), EnvKit.codeUidOf(address(a)));
            vm.prank(OWNER);
            vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleNotContract.selector, only[i], SINGLE));
            a.grantRole(only[i], SINGLE, EnvKit.codeUidOf(address(a)));
        }
    }

    /// `WHOLE` for one or two operators: an EOA and a single-key UA, no cap.
    function test_operatorTransferWholeForAnEoaAndASingleKeyUA() public {
        address op = address(0x0FE2);
        bytes32[2] memory ids = [nid(op), SINGLE];
        for (uint256 i; i < 2; ++i) {
            vm.prank(OWNER);
            a.grantRole(OPERATOR, ids[i], EnvKit.codeUidOf(address(a)));
            vm.warp(block.timestamp + D);
            vm.prank(OWNER);
            a.grantRole(OPERATOR, ids[i], EnvKit.codeUidOf(address(a)));
            assertTrue(a.hasRole(OPERATOR, ids[i]));
        }
        vm.prank(op);
        assertEq(a.act(OPERATOR, type(uint128).max), 0, "WHOLE: no bound");
        a.actFor(SINGLE, OPERATOR, type(uint128).max);
        // positive control of the refusal: a stranger holds nothing
        vm.prank(STRANGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, OPERATOR, nid(STRANGER)));
        a.act(OPERATOR, 1);
    }

    // ------------------------------------------------------------------ RoleConflict: FORCE and RECORD never on one id

    function test_roleConflictForceRecord_init() public {
        RelaxApp x = new RelaxApp(address(reg));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleConflict.selector, RECORD, nid(other)));
        x.init(FEATURES, nid(OWNER), D, _roles(nid(other), nid(other)));
        // positive control: without FORCE the issuer may also be the compliance holder
        x.init(FEATURES & ~uint256(1 << FORCE), nid(OWNER), D, _roles(nid(other), nid(other)));
        assertTrue(x.hasRole(RECORD, nid(other)));
    }

    function test_roleConflictForceRecord_grant() public {
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleConflict.selector, RECORD, nid(issuer)));
        vm.prank(OWNER);
        a.grantRole(RECORD, nid(issuer), EnvKit.codeUidOf(address(a)));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleConflict.selector, FORCE, nid(compliance)));
        vm.prank(OWNER);
        a.grantRole(FORCE, nid(compliance), EnvKit.codeUidOf(address(a)));
        vm.prank(OWNER);
        a.grantRole(RECORD, nid(other), EnvKit.codeUidOf(address(a))); // positive control
        assertTrue(_live(RECORD, nid(other)));
    }

    function test_roleConflictForceRecord_setGrant() public {
        IGovernance.GrantTerms memory t;
        (t.max, t.total) = (100, 100);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleConflict.selector, FORCE, nid(compliance)));
        vm.prank(OWNER);
        a.setGrant(FORCE, nid(compliance), t, EnvKit.codeUidOf(address(a)));
        vm.prank(OWNER);
        a.setGrant(FORCE, nid(other), t, EnvKit.codeUidOf(address(a))); // positive control
        assertTrue(_live(FORCE, nid(other)));
    }

    function test_roleConflictForceRecord_leaf() public {
        IGovernance.GrantTerms memory t;
        (t.max, t.total, t.delegable) = (100, 100, true);
        vm.prank(OWNER);
        a.setGrant(FORCE, nid(issuer), t, EnvKit.codeUidOf(address(a)));
        vm.warp(block.timestamp + D);
        vm.prank(OWNER);
        a.setGrant(FORCE, nid(issuer), t, EnvKit.codeUidOf(address(a)));
        (t.total, t.delegable) = (10, false);
        vm.prank(issuer);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleConflict.selector, FORCE, nid(compliance)));
        a.setGrant(FORCE, nid(compliance), t, EnvKit.codeUidOf(address(a)));
        vm.prank(issuer); // positive control: a leaf on an id without RECORD
        a.setGrant(FORCE, nid(other), t, EnvKit.codeUidOf(address(a)));
        assertTrue(a.hasRole(FORCE, nid(other)));
    }

    // ------------------------------------------------------------------ the event

    function test_relaxProposedTopics() public {
        vm.recordLogs();
        vm.prank(OWNER);
        a.revokeRole(FREEZE, nid(issuer), EnvKit.codeUidOf(address(a)));
        Vm.Log[] memory l = vm.getRecordedLogs();
        assertEq(l.length, 1);
        assertEq(l[0].topics.length, 3, "bit and account indexed");
        assertEq(l[0].topics[0], keccak256("RelaxProposed(uint8,bytes32,uint8,bytes32,uint64)"));
        assertEq(l[0].topics[1], bytes32(uint256(FREEZE)));
        assertEq(l[0].topics[2], nid(issuer));
        assertEq(l[0].data, abi.encode(REVOKE, nid(OWNER), uint64(block.timestamp + D)));
        // positive control: a grant still emits `GrantProposed`
        vm.recordLogs();
        vm.prank(OWNER);
        a.grantRole(FREEZE, nid(other), EnvKit.codeUidOf(address(a)));
        l = vm.getRecordedLogs();
        assertEq(l[0].topics[0], IGovernance.GrantProposed.selector);
    }
}
