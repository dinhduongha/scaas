// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {DexPuller} from "../../src/dex/DexPuller.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {IAdmin} from "../../src/governance/IAdmin.sol";
import {IRescuable} from "../../src/governance/IRescuable.sol";
import {GovernanceBase, GovernanceBaseCore} from "../../src/governance/GovernanceBase.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {GovernanceLib} from "../../src/governance/GovernanceLib.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {Catalogue} from "../helpers/Catalogue.sol";
import {nid} from "../helpers/Ids.sol";
import {EnvKit} from "../helpers/EnvKit.sol";

/// An application with one scalar, scoped power (bit 128) and a `grantDelay`, for the `scope` word of spec §1.6.
contract DelayApp is GovernanceBase {
    uint8 internal constant APPROVE = 128;

    constructor(address owner_, uint64 delay) GovernanceBaseCore(address(0)) {
        GovernanceLib.Roles memory none;
        uint256 b = uint256(1) << APPROVE;
        GovernanceLib.init(b, 0, nid(owner_), delay, address(0), none, b, b, 0, address(0));
    }

    function _guardIn() internal pure override returns (bool) { return false; }
    function _guardOut(bool) internal pure override {}
    function _caller() internal view override returns (address) { return msg.sender; }
    /// @dev A test app has no chain word (not factory-made); its renounce is not exercised by chain (Fable recheck-2 P3-1).
    function _govChainUid() internal pure override returns (bytes32) { return bytes32(0); }
    function _validBits() internal pure override returns (uint256) { return uint256(1) << APPROVE; }
    function _roleBits() internal pure override returns (uint256) { return uint256(1) << APPROVE; }
    function _contractOnlyBits() internal pure override returns (uint256) { return 0; }
    function _scalarBits() internal pure override returns (uint256) { return uint256(1) << APPROVE; }
    function _scopeBits() internal pure override returns (uint256) { return uint256(1) << APPROVE; }
}

/// @notice D4 (spec §1.6, CTR-GOV-04 and its Change; B-01, B-27; Codex 2, 7; agy C-3, I-2; Fable M-1): a new holder and every
///         widened word take two calls by the same owner generation, with the same terms, inside `[eta, eta + grantDelay]`; a
///         pure narrowing runs at once; a pending dies with an owner's revoke, a renounce, a narrowing, a change of owner.
contract GovDelayTest is Test {
    bytes32 constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    uint8 constant MINT = GovernanceBits.MINTABLE;
    address constant OWNER = address(0x0A);
    address constant MANAGER = address(0x0B);
    address constant OFFICER = address(0x0C);
    address constant NEXT = address(0x0D);
    address constant TO = address(0xCAFE);
    uint128 constant NONE = type(uint128).max;
    uint64 constant D = 2 days;

    OpenFactory f;
    NormalToken t;

    function setUp() public {
        vm.warp(1_800_000_000);
        f = EnvKit.factory(address(this), UID, 0);
        Catalogue.plain(f, IOpenFactory.TokenKind.NORMAL, 1, type(NormalToken).creationCode, address(0), address(0), false);
        Catalogue.plain(f, IOpenFactory.TokenKind.WRAPPED, 1, type(WrappedToken).creationCode, address(0), address(0), false);
        Catalogue.dex(f, 1, type(SCaaSDex).creationCode, address(0));
        t = _token("t", D);
    }

    function _cfg(uint64 delay) internal pure returns (IFactoryToken.TokenConfig memory c) {
        (c.name, c.symbol, c.decimals, c.features, c.admin, c.grantDelay) = ("G", "G", 18, 7, nid(OWNER), delay);
    }

    function _token(bytes32 salt, uint64 delay) internal returns (NormalToken) {
        return NormalToken(f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(_cfg(delay)), salt));
    }

    function _open() internal pure returns (IGovernance.GrantTerms memory g) {
        g.max = NONE;
    }

    /// Every word `MINT` binds, bounded.
    function _bounded() internal view returns (IGovernance.GrantTerms memory g) {
        (g.min, g.max, g.total, g.perWindow, g.window) = (10, 100, 1000, 500, 1 days);
        (g.validUntil, g.maxUses) = (uint64(block.timestamp + 30 days), 50);
    }

    function _set(address holder, IGovernance.GrantTerms memory g) internal {
        vm.prank(OWNER);
        t.setGrant(MINT, nid(holder), g, EnvKit.codeUidOf(address(t)));
    }

    function _grant(address holder) internal {
        vm.prank(OWNER);
        t.grantRole(MINT, nid(holder), EnvKit.codeUidOf(address(t)));
    }

    /// Propose, wait the delay, confirm.
    function _set2(address holder, IGovernance.GrantTerms memory g) internal {
        _set(holder, g);
        vm.warp(block.timestamp + D);
        _set(holder, g);
    }

    function _grant2(address holder) internal {
        _grant(holder);
        vm.warp(block.timestamp + D);
        _grant(holder);
    }

    function _pending(address account) internal view returns (uint64 eta, bytes32 proposer, bytes32 h, bool live) {
        return t.pendingGrant(MINT, nid(account));
    }

    function _live(address account) internal view returns (bool live) {
        (,,, live) = _pending(account);
    }

    function _eta(address account) internal view returns (uint64 eta) {
        (eta,,,) = _pending(account);
    }

    /// ua-mtx-merge T24 (regulated-kinds spec §3.6, RK-2): the pending commits to the action, the key and, for `SET`, the
    /// terms: `keccak256(abi.encode(action, bit, account, argsHash))`; before, `termsHash` was the terms' hash, 0 for a grant.
    function _commit(uint8 action, address account, bytes32 argsHash) internal pure returns (bytes32) {
        return keccak256(abi.encode(action, MINT, nid(account), argsHash));
    }

    function _same(IGovernance.Grant memory g, IGovernance.GrantTerms memory x) internal pure returns (bool) {
        return g.min == x.min && g.max == x.max && g.total == x.total && g.perWindow == x.perWindow && g.window == x.window
            && g.validUntil == x.validUntil && g.maxUses == x.maxUses && g.delegable == x.delegable && g.scope == x.scope;
    }

    /// The edit proposes: the record is unchanged and a live pending holds `x`.
    function _proposes(address holder, IGovernance.GrantTerms memory x, string memory word) internal {
        IGovernance.Grant memory before = t.grantOf(MINT, nid(holder));
        _set(holder, x);
        IGovernance.Grant memory g = t.grantOf(MINT, nid(holder));
        assertEq(abi.encode(g), abi.encode(before), word);
        (uint64 eta,, bytes32 h, bool live) = _pending(holder);
        assertTrue(live, word);
        assertEq(eta, block.timestamp + D, word);
        assertEq(h, _commit(2, holder, keccak256(abi.encode(x))), word);
        vm.prank(OWNER);
        t.cancelGrant(MINT, nid(holder), EnvKit.codeUidOf(address(t)));
    }

    /// The edit applies at once: the record holds `x` and no pending is written.
    function _runsAtOnce(address holder, IGovernance.GrantTerms memory x, string memory word) internal {
        _set(holder, x);
        assertTrue(_same(t.grantOf(MINT, nid(holder)), x), word);
        assertEq(_eta(holder), 0, word);
    }

    // ------------------------------------------------------------------ two calls

    function test_newHolderTakesTwoCalls() public {
        _grant(MANAGER);
        assertFalse(t.hasRole(MINT, nid(MANAGER)), "proposed, not granted");
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, MINT, MANAGER));
        t.mint(TO, 1);
        vm.warp(block.timestamp + D);
        _grant(MANAGER);
        assertTrue(t.hasRole(MINT, nid(MANAGER)));
        assertEq(_eta(MANAGER), 0, "the confirm deletes the pending");

        IGovernance.GrantTerms memory g = _open();
        g.total = 5;
        _set(OFFICER, g);
        assertFalse(t.hasRole(MINT, nid(OFFICER)));
        vm.warp(block.timestamp + D);
        _set(OFFICER, g);
        assertTrue(t.hasRole(MINT, nid(OFFICER)));
        assertEq(t.grantOf(MINT, nid(OFFICER)).total, 5);
    }

    /// B-01: from a `LIMITED` root with every word bounded, each widened word alone proposes.
    function test_eachWidenedWordTakesTwoCalls() public {
        IGovernance.GrantTerms memory b = _bounded();
        _set2(MANAGER, b);
        IGovernance.GrantTerms memory x;
        x = _bounded(); x.min = 9; _proposes(MANAGER, x, "min");
        x = _bounded(); x.max = 101; _proposes(MANAGER, x, "max");
        x = _bounded(); x.total = 1001; _proposes(MANAGER, x, "total");
        x = _bounded(); x.perWindow = 501; _proposes(MANAGER, x, "perWindow");
        x = _bounded(); x.window = 2 days; _proposes(MANAGER, x, "window");
        x = _bounded(); x.validUntil += 1; _proposes(MANAGER, x, "validUntil");
        x = _bounded(); x.maxUses = 51; _proposes(MANAGER, x, "maxUses");
        x = _bounded(); x.delegable = true; _proposes(MANAGER, x, "delegable");
        DelayApp a = new DelayApp(OWNER, D); // scope, on a scoped bit
        IGovernance.GrantTerms memory s = _open();
        s.scope = bytes32(uint256(7));
        vm.prank(OWNER);
        a.setGrant(128, nid(MANAGER), s, EnvKit.codeUidOf(address(a)));
        vm.warp(block.timestamp + D);
        vm.prank(OWNER);
        a.setGrant(128, nid(MANAGER), s, EnvKit.codeUidOf(address(a)));
        s.scope = bytes32(uint256(8));
        vm.prank(OWNER);
        a.setGrant(128, nid(MANAGER), s, EnvKit.codeUidOf(address(a)));
        assertEq(a.grantOf(128, nid(MANAGER)).scope, bytes32(uint256(7)), "scope");
        (,,, bool live) = a.pendingGrant(128, nid(MANAGER));
        assertTrue(live, "scope");
    }

    /// B-01: from the same root, each narrowed word alone applies at once; the delegation ends at once too.
    function test_eachNarrowedWordRunsAtOnce() public {
        IGovernance.GrantTerms memory x = _bounded();
        x.delegable = true;
        _set2(MANAGER, x);
        x.delegable = false; _runsAtOnce(MANAGER, x, "delegable");
        x.min = 11; _runsAtOnce(MANAGER, x, "min");
        x.max = 99; _runsAtOnce(MANAGER, x, "max");
        x.total = 999; _runsAtOnce(MANAGER, x, "total");
        x.perWindow = 499; _runsAtOnce(MANAGER, x, "perWindow");
        x.validUntil -= 1; _runsAtOnce(MANAGER, x, "validUntil");
        x.maxUses = 49; _runsAtOnce(MANAGER, x, "maxUses");
        _runsAtOnce(MANAGER, x, "the same terms");
        _grant2(OFFICER); // a `WHOLE` root: any non-delegable terms narrow it
        _runsAtOnce(OFFICER, _bounded(), "whole to limited");
    }

    /// Codex 7: `0 → finite` narrows on each of `total`, `perWindow`, `validUntil`, `maxUses`.
    function test_finiteOnEachUnboundedWordRunsAtOnce() public {
        IGovernance.GrantTerms memory x = _open();
        _set2(MANAGER, x);
        x.total = 1000; _runsAtOnce(MANAGER, x, "total");
        (x.perWindow, x.window) = (500, 1 days); _runsAtOnce(MANAGER, x, "perWindow");
        x.validUntil = uint64(block.timestamp + 1 days); _runsAtOnce(MANAGER, x, "validUntil");
        x.maxUses = 5; _runsAtOnce(MANAGER, x, "maxUses");
    }

    /// Codex 7: a new `window` comes with the limit it carries; a window changed under a limit is a widening.
    function test_windowWithItsLimitRunsAtOnce() public {
        IGovernance.GrantTerms memory x = _open();
        x.total = 1000;
        _set2(MANAGER, x);
        (x.perWindow, x.window) = (500, 1 days);
        _runsAtOnce(MANAGER, x, "a window with its limit");
        x.window = 1 days - 1;
        _proposes(MANAGER, x, "a window changed under a limit");
    }

    /// Codex 7: `finite → 0` is a widening on each word.
    function test_finiteToUnboundedTakesTwoCalls() public {
        IGovernance.GrantTerms memory b = _bounded();
        _set2(MANAGER, b);
        IGovernance.GrantTerms memory x;
        x = _bounded(); x.total = 0; _proposes(MANAGER, x, "total");
        x = _bounded(); (x.perWindow, x.window) = (0, 0); _proposes(MANAGER, x, "perWindow");
        x = _bounded(); x.validUntil = 0; _proposes(MANAGER, x, "validUntil");
        x = _bounded(); x.maxUses = 0; _proposes(MANAGER, x, "maxUses");
        x = _bounded(); x.max = NONE; _proposes(MANAGER, x, "max");
        x = _bounded(); x.min = 0; _proposes(MANAGER, x, "min");
    }

    /// B-01, derived: the owner's edit of a leaf makes a root and drops the parent's bound, so it takes two calls, however
    /// narrow the terms.
    function test_leafMadeARootTakesTwoCalls() public {
        IGovernance.GrantTerms memory m = _open();
        (m.total, m.delegable) = (100, true);
        _set2(MANAGER, m);
        IGovernance.GrantTerms memory l = _open();
        l.total = 10;
        vm.prank(MANAGER);
        t.setGrant(MINT, nid(OFFICER), l, EnvKit.codeUidOf(address(t))); // the leaf path takes no delay
        assertEq(t.grantOf(MINT, nid(OFFICER)).grantor, nid(MANAGER));
        l.total = 5;
        _set(OFFICER, l);
        assertEq(t.grantOf(MINT, nid(OFFICER)).grantor, nid(MANAGER), "proposed: still a leaf");
        assertEq(t.grantOf(MINT, nid(OFFICER)).total, 10);
        vm.warp(block.timestamp + D);
        _set(OFFICER, l);
        assertEq(t.grantOf(MINT, nid(OFFICER)).grantor, bytes32(0), "a root");
        assertEq(t.grantOf(MINT, nid(OFFICER)).total, 5);
    }

    function test_grantRoleOnLimitedTakesTwoCalls() public {
        IGovernance.GrantTerms memory x = _open();
        x.total = 5;
        _set2(MANAGER, x);
        _grant(MANAGER);
        assertTrue(_live(MANAGER));
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantExhausted.selector, uint8(2)));
        t.mint(TO, 6);
        vm.warp(block.timestamp + D);
        _grant(MANAGER);
        vm.prank(MANAGER);
        t.mint(TO, 6);
        _grant(MANAGER); // `WHOLE`: a no-op, nothing proposed
        assertEq(_eta(MANAGER), 0);
    }

    // ------------------------------------------------------------------ the confirm

    function test_confirmWithOtherTermsReverts() public {
        IGovernance.GrantTerms memory x = _open();
        x.total = 5;
        _set(MANAGER, x);
        vm.warp(block.timestamp + D);
        IGovernance.GrantTerms memory y = _open();
        y.total = 6;
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantTermsMismatch.selector, MINT, MANAGER));
        t.setGrant(MINT, nid(MANAGER), y, EnvKit.codeUidOf(address(t)));
        vm.prank(OWNER); // `grantRole` is terms 0
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantTermsMismatch.selector, MINT, MANAGER));
        t.grantRole(MINT, nid(MANAGER), EnvKit.codeUidOf(address(t)));
        _set(MANAGER, x); // positive control
        assertEq(t.grantOf(MINT, nid(MANAGER)).total, 5);
    }

    function test_confirmBeforeEtaReverts() public {
        _grant(MANAGER);
        uint64 eta = uint64(block.timestamp + D);
        vm.warp(eta - 1);
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantNotReady.selector, MINT, MANAGER, eta));
        t.grantRole(MINT, nid(MANAGER), EnvKit.codeUidOf(address(t)));
        vm.warp(eta); // positive control: at `eta`
        _grant(MANAGER);
        assertTrue(t.hasRole(MINT, nid(MANAGER)));
    }

    function test_afterTheWindowThePendingIsDead() public {
        _grant(MANAGER);
        _grant(OFFICER);
        uint64 eta = uint64(block.timestamp + D);
        vm.warp(eta + D); // the last second of the window: positive control
        _grant(OFFICER);
        assertTrue(t.hasRole(MINT, nid(OFFICER)));
        vm.warp(eta + D + 1);
        assertFalse(_live(MANAGER));
        _grant(MANAGER); // proposes again
        assertFalse(t.hasRole(MINT, nid(MANAGER)));
        assertEq(_eta(MANAGER), block.timestamp + D);
    }

    function test_afterRenounceNobodyConfirms() public {
        _grant(MANAGER);
        assertTrue(_live(MANAGER));
        vm.prank(OWNER);
        t.renounceAdmin(EnvKit.codeUidOf(address(t)));
        assertFalse(_live(MANAGER));
        vm.warp(block.timestamp + D);
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotAdmin.selector, OWNER));
        t.grantRole(MINT, nid(MANAGER), EnvKit.codeUidOf(address(t)));
        assertFalse(t.hasRole(MINT, nid(MANAGER)));
    }

    function test_afterTransferTheNewOwnerProposesAgain() public {
        _grant(MANAGER);
        vm.prank(OWNER);
        t.transferAdmin(nid(NEXT), EnvKit.codeUidOf(address(t)));
        vm.prank(NEXT);
        t.acceptAdmin();
        assertFalse(_live(MANAGER));
        vm.warp(block.timestamp + D);
        vm.prank(NEXT);
        t.grantRole(MINT, nid(MANAGER), EnvKit.codeUidOf(address(t))); // proposes, it does not confirm OWNER's
        assertFalse(t.hasRole(MINT, nid(MANAGER)));
        (, bytes32 proposer,, bool live) = _pending(MANAGER);
        assertEq(proposer, nid(NEXT));
        assertTrue(live);
        vm.warp(block.timestamp + D);
        vm.prank(NEXT);
        t.grantRole(MINT, nid(MANAGER), EnvKit.codeUidOf(address(t)));
        assertTrue(t.hasRole(MINT, nid(MANAGER)));
    }

    /// Codex 2: A → B → A: the generation counts completed changes of owner, so A's first pending stays dead.
    function test_aToBToAKillsThePending() public {
        _grant(MANAGER);
        vm.prank(OWNER);
        t.transferAdmin(nid(NEXT), EnvKit.codeUidOf(address(t)));
        vm.prank(NEXT);
        t.acceptAdmin();
        vm.prank(NEXT);
        t.transferAdmin(nid(OWNER), EnvKit.codeUidOf(address(t)));
        vm.prank(OWNER);
        t.acceptAdmin();
        assertEq(t.admin(), nid(OWNER));
        assertFalse(_live(MANAGER));
        vm.warp(block.timestamp + D);
        _grant(MANAGER);
        assertFalse(t.hasRole(MINT, nid(MANAGER)), "a new proposal, not a confirm");
    }

    /// Codex 2: a transfer cancelled or never accepted kills nothing.
    function test_cancelledTransferKillsNothing() public {
        _grant(MANAGER);
        _grant(OFFICER);
        vm.startPrank(OWNER);
        t.transferAdmin(nid(NEXT), EnvKit.codeUidOf(address(t)));
        t.transferAdmin(bytes32(0), EnvKit.codeUidOf(address(t)));
        vm.stopPrank();
        vm.warp(block.timestamp + D);
        _grant(MANAGER);
        assertTrue(t.hasRole(MINT, nid(MANAGER)));
        vm.prank(OWNER);
        t.transferAdmin(nid(NEXT), EnvKit.codeUidOf(address(t))); // pending, never accepted
        _grant(OFFICER);
        assertTrue(t.hasRole(MINT, nid(OFFICER)));
    }

    function test_delayZeroIsOneCall() public {
        t = _token("z", 0);
        _grant(MANAGER);
        assertTrue(t.hasRole(MINT, nid(MANAGER)));
        _set(OFFICER, _open());
        assertTrue(t.hasRole(MINT, nid(OFFICER)));
        IGovernance.GrantTerms memory x = _open();
        x.delegable = true;
        x.total = 5;
        _set(OFFICER, x); // a widening, at once
        assertTrue(t.grantOf(MINT, nid(OFFICER)).delegable);
        assertEq(_eta(OFFICER), 0);
        assertEq(t.lastProposedAt(), 0);
    }

    // ------------------------------------------------------------------ what deletes a pending (agy C-3, Fable M-1)

    function test_revokeDeletesThePending() public {
        IGovernance.GrantTerms memory x = _open();
        x.total = 5;
        _set2(MANAGER, x);
        x.total = 50;
        _set(MANAGER, x);
        assertTrue(_live(MANAGER));
        vm.prank(OWNER);
        t.revokeRole(MINT, nid(MANAGER), EnvKit.codeUidOf(address(t)));
        assertEq(_eta(MANAGER), 0);
        assertTrue(t.grantOf(MINT, nid(MANAGER)).barred);
        vm.warp(block.timestamp + D);
        _set(MANAGER, x); // not a confirm: it proposes again
        assertFalse(t.hasRole(MINT, nid(MANAGER)));
        assertTrue(t.grantOf(MINT, nid(MANAGER)).barred);
        assertTrue(_live(MANAGER));
    }

    function test_grantorRevokeKeepsThePending() public {
        IGovernance.GrantTerms memory m = _open();
        (m.total, m.delegable) = (100, true);
        _set2(MANAGER, m);
        IGovernance.GrantTerms memory l = _open();
        l.total = 10;
        vm.prank(MANAGER);
        t.setGrant(MINT, nid(OFFICER), l, EnvKit.codeUidOf(address(t)));
        _set(OFFICER, l); // the owner proposes to make the leaf a root
        uint64 eta = _eta(OFFICER);
        vm.prank(MANAGER);
        t.revokeRole(MINT, nid(OFFICER), EnvKit.codeUidOf(address(t)));
        assertEq(_eta(OFFICER), eta, "kept");
        assertTrue(_live(OFFICER));
        vm.warp(eta);
        _set(OFFICER, l);
        assertTrue(t.hasRole(MINT, nid(OFFICER)));
        assertEq(t.grantOf(MINT, nid(OFFICER)).grantor, bytes32(0), "the root the owner proposed");
        vm.prank(OWNER);
        t.revokeRole(MINT, nid(MANAGER), EnvKit.codeUidOf(address(t)));
        vm.prank(OFFICER);
        t.mint(TO, 1); // alive without its old parent
    }

    function test_renounceDeletesThePending() public {
        IGovernance.GrantTerms memory x = _open();
        x.total = 5;
        _set2(MANAGER, x);
        x.total = 50;
        _set(MANAGER, x);
        vm.prank(MANAGER);
        t.renounceRole(MINT, EnvKit.codeUidOf(address(t)));
        assertEq(_eta(MANAGER), 0);
        assertFalse(t.grantOf(MINT, nid(MANAGER)).barred, "a renounce bars nobody");
    }

    function test_narrowingDeletesThePending() public {
        IGovernance.GrantTerms memory x = _open();
        x.total = 5;
        _set2(MANAGER, x);
        IGovernance.GrantTerms memory w = _open();
        w.total = 50;
        _set(MANAGER, w);
        x.total = 4;
        _set(MANAGER, x); // a narrowing, at once
        assertEq(t.grantOf(MINT, nid(MANAGER)).total, 4);
        assertEq(_eta(MANAGER), 0);
        vm.warp(block.timestamp + D);
        _set(MANAGER, w); // proposes again
        assertEq(t.grantOf(MINT, nid(MANAGER)).total, 4);
    }

    function _cancelled(Vm.Log[] memory logs) internal pure returns (uint256 k) {
        for (uint256 i; i < logs.length; ++i) if (logs[i].topics[0] == IGovernance.GrantCancelled.selector) ++k;
    }

    function test_cancelGrantLiveAndDead() public {
        _grant(MANAGER);
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotAdmin.selector, MANAGER));
        t.cancelGrant(MINT, nid(MANAGER), EnvKit.codeUidOf(address(t)));
        vm.expectEmit(address(t));
        emit IGovernance.GrantCancelled(MINT, nid(MANAGER), nid(OWNER));
        vm.prank(OWNER);
        t.cancelGrant(MINT, nid(MANAGER), EnvKit.codeUidOf(address(t)));
        assertEq(_eta(MANAGER), 0, "live, cancelled");
        _grant(MANAGER);
        vm.warp(block.timestamp + 2 * D + 1);
        assertFalse(_live(MANAGER));
        vm.prank(OWNER);
        t.cancelGrant(MINT, nid(MANAGER), EnvKit.codeUidOf(address(t)));
        assertEq(_eta(MANAGER), 0, "dead, cancelled");
        vm.recordLogs();
        vm.prank(OWNER);
        t.cancelGrant(MINT, nid(MANAGER), EnvKit.codeUidOf(address(t)));
        assertEq(_cancelled(vm.getRecordedLogs()), 0, "none: a no-op");
        _grant(MANAGER); // a cancelled pending is proposed again
        assertTrue(_live(MANAGER));
    }

    function test_pendingGrantSaysLive() public {
        IGovernance.GrantTerms memory x = _open();
        x.total = 5;
        vm.expectEmit(address(t));
        emit IGovernance.GrantProposed(MINT, nid(MANAGER), nid(OWNER), uint64(block.timestamp + D), false, x);
        _set(MANAGER, x);
        (uint64 eta, bytes32 proposer, bytes32 h, bool live) = _pending(MANAGER);
        assertEq(eta, block.timestamp + D);
        assertEq(proposer, nid(OWNER));
        assertEq(h, _commit(2, MANAGER, keccak256(abi.encode(x))));
        assertTrue(live);
        _grant(OFFICER);
        (,, h,) = _pending(OFFICER);
        assertEq(h, _commit(1, OFFICER, 0), "grantRole: action 1, args 0");
        vm.warp(eta + D);
        assertTrue(_live(MANAGER));
        vm.warp(eta + D + 1);
        (uint64 eta2, bytes32 p2, bytes32 h2, bool live2) = _pending(MANAGER);
        assertEq(eta2, eta, "a dead pending is still reported");
        assertEq(p2, nid(OWNER));
        assertEq(h2, _commit(2, MANAGER, keccak256(abi.encode(x))));
        assertFalse(live2);
    }

    // ------------------------------------------------------------------ creation (B-27, A20, GD-3)

    function test_delayAboveThirtyDaysRefused() public {
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantDelayTooLong.selector, uint64(30 days + 1)));
        f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(_cfg(30 days + 1)), "d");
        NormalToken n = _token("d", 30 days);
        assertEq(n.grantDelay(), 30 days);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantDelayTooLong.selector, uint64(30 days + 1)));
        f.createDex(1, abi.encode(ISCaaSDex.DexConfig(nid(OWNER), 0, address(0xAA), false, 30 days + 1, address(0), 0, 0)), "x");
        SCaaSDex d = SCaaSDex(f.createDex(1, abi.encode(ISCaaSDex.DexConfig(nid(OWNER), 0, address(0xAA), false, 30 days, address(0), 0, 0)), "x"));
        assertEq(d.grantDelay(), 30 days);
    }

    /// B-27: `initHolder` holds both bits from creation, whatever the delay; the powers run at once.
    function test_dexInitHoldsBothBitsWithADelay() public {
        SCaaSDex d = SCaaSDex(f.createDex(1, abi.encode(ISCaaSDex.DexConfig(nid(OWNER), 0, address(0xAA), false, D, address(0), 0, 0)), "d"));
        assertEq(d.grantDelay(), D);
        assertTrue(d.hasRole(GovernanceBits.LISTING, nid(OWNER)));
        assertTrue(d.hasRole(GovernanceBits.FEE_ROUTING, nid(OWNER)));
        assertEq(d.holderCount(GovernanceBits.LISTING), 1);
        (uint64 eta,,,) = d.pendingGrant(GovernanceBits.LISTING, nid(OWNER));
        assertEq(eta, 0, "nothing proposed");
        vm.startPrank(OWNER);
        d.setListedOnly(true);
        d.setFeeSplit(0, address(0xBB));
        vm.stopPrank();
        assertEq(d.treasury(), address(0xBB));
    }

    /// A20: INIT counts once, an idempotent grant moves nothing, a pending never counts.
    function test_holderCountCountsInitOnceAndNeverAPending() public {
        IFactoryToken.TokenConfig memory c = _cfg(D);
        c.roles.minter = nid(MANAGER);
        NormalToken n = NormalToken(f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), "h"));
        assertEq(n.holderCount(MINT), 1);
        vm.startPrank(OWNER);
        n.grantRole(MINT, nid(MANAGER), EnvKit.codeUidOf(address(n)));
        assertEq(n.holderCount(MINT), 1);
        n.grantRole(MINT, nid(OFFICER), EnvKit.codeUidOf(address(n)));
        n.setGrant(MINT, nid(NEXT), _open(), EnvKit.codeUidOf(address(n)));
        assertEq(n.holderCount(MINT), 1, "two pendings, no holder");
        vm.warp(block.timestamp + D);
        n.grantRole(MINT, nid(OFFICER), EnvKit.codeUidOf(address(n)));
        assertEq(n.holderCount(MINT), 2);
        vm.stopPrank();
    }

    function test_lastProposedAtMoves() public {
        assertEq(t.lastProposedAt(), 0);
        _grant(MANAGER);
        uint256 t1 = block.timestamp;
        assertEq(t.lastProposedAt(), t1);
        vm.warp(t1 + 1 hours);
        _grant(OFFICER);
        assertEq(t.lastProposedAt(), t1 + 1 hours);
        vm.warp(t1 + D);
        _grant(MANAGER); // a confirm proposes nothing
        assertEq(t.lastProposedAt(), t1 + 1 hours);
    }

    /// GD-3: the new `TokenConfig` and `DexConfig` fields fail closed without their bit: `maxSupply` on `NORMAL` and without
    /// `MINTABLE` on `WRAPPED` (T9), `rescueTo` without `RESCUABLE` (T10); the DEX's `rescueTo` is its puller's (T10).
    function test_configFieldsFailClosedUntilBuilt() public {
        IFactoryToken.TokenConfig memory c = _cfg(0);
        c.maxSupply = 1;
        vm.expectRevert(abi.encodeWithSelector(IFactoryToken.ConfigFieldForOtherKind.selector, uint8(5)));
        f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), "c");
        c.maxSupply = 0;
        c.rescueTo = address(0xBEEF);
        vm.expectRevert(IRescuable.RescueConfigInvalid.selector);
        f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), "c");
        MockERC20 usd = new MockERC20("USD", "USD", 6);
        IFactoryToken.TokenConfig memory w = _cfg(0);
        (w.features, w.decimals) = (1, 6);
        w.legs = new IFactoryToken.Leg[](1);
        w.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        w.maxSupply = 1;
        vm.expectRevert(IWrappedToken.MaxSupplyInvalid.selector);
        f.createToken(IOpenFactory.TokenKind.WRAPPED, 1, abi.encode(w), "w");
        w.maxSupply = 0;
        w.rescueTo = address(0xBEEF);
        vm.expectRevert(IRescuable.RescueConfigInvalid.selector);
        f.createToken(IOpenFactory.TokenKind.WRAPPED, 1, abi.encode(w), "w");
        // governance T10 (spec §6.2): the DEX's `rescueTo` is its puller's, accepted; the DEX rescues nothing itself
        SCaaSDex dx = SCaaSDex(f.createDex(1, abi.encode(ISCaaSDex.DexConfig(nid(OWNER), 0, address(0xAA), false, 0, address(0xBEEF), 0, 0)), "y"));
        assertEq(DexPuller(dx.puller()).rescueTo(), address(0xBEEF));
        w.rescueTo = address(0); // positive controls
        f.createToken(IOpenFactory.TokenKind.WRAPPED, 1, abi.encode(w), "w");
        c.rescueTo = address(0);
        f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), "c");
        f.createDex(1, abi.encode(ISCaaSDex.DexConfig(nid(OWNER), 0, address(0xAA), false, 0, address(0), 0, 0)), "x");
    }
}
