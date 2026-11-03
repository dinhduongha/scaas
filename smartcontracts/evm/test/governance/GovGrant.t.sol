// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test, Vm, console} from "forge-std/Test.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {GovernanceLib} from "../../src/governance/GovernanceLib.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {DexLegs} from "../helpers/DexLegs.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {Catalogue} from "../helpers/Catalogue.sol";

/// A token whose every transfer out calls its hook: the way into a running settlement.
contract GovHookERC20 is MockERC20 {
    address public hookTarget;

    constructor() MockERC20("Hook", "HK", 18) {}

    function setHook(address h) external { hookTarget = h; }

    function _update(address from, address to, uint256 v) internal override {
        super._update(from, to, v);
        if (from != address(0) && hookTarget != address(0)) GovDexHolder(hookTarget).hook();
    }
}

/// The DEX's owner, holding bits 11 and 12, calls each of the four powers from inside a settlement and records how each
/// answered (0: it ran).
contract GovDexHolder {
    SCaaSDex public dex;
    bytes4[] public errs;

    function setDex(SCaaSDex d) external { dex = d; }

    function n() external view returns (uint256) { return errs.length; }

    function hook() external {
        if (errs.length != 0) return;
        try dex.setMarket(address(0x51), address(0x52), true) { errs.push(0); } catch (bytes memory r) { errs.push(bytes4(r)); }
        try dex.setExchangeTarget(address(0x53), true) { errs.push(0); } catch (bytes memory r) { errs.push(bytes4(r)); }
        try dex.setListedOnly(true) { errs.push(0); } catch (bytes memory r) { errs.push(bytes4(r)); }
        try dex.setFeeSplit(0, address(0xAA)) { errs.push(0); } catch (bytes memory r) { errs.push(bytes4(r)); }
    }
}

/// @notice The prototype's `Grant` (CTR-GOV-02): every bound with its positive control, two levels, the epoch kill, spent
///         carried on edit, `holderCount`, the renounce rule; a limited holder bound on a wrapped kind and on the DEX too.
contract GovGrantTest is Test {
    bytes32 constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    uint8 constant MINT = GovernanceBits.MINTABLE;
    address constant OWNER = address(0x0A);
    address constant MANAGER = address(0x0B);
    address constant OFFICER = address(0x0C);
    address constant OFFICER2 = address(0x0D);
    address constant TO = address(0xCAFE);
    uint128 constant NONE = type(uint128).max;

    OpenFactory f;
    NormalToken t;

    function setUp() public {
        vm.warp(1_800_000_000);
        f = new OpenFactory(address(this), UID, 0);
        Catalogue.plain(f, IOpenFactory.TokenKind.NORMAL, 1, type(NormalToken).creationCode, address(0), address(0), false);
        Catalogue.plain(f, IOpenFactory.TokenKind.WRAPPED, 1, type(WrappedToken).creationCode, address(0), address(0), false);
        t = _token("t", 0);
    }

    function _token(bytes32 salt, uint256 locked) internal returns (NormalToken) {
        IFactoryToken.TokenConfig memory c;
        c.name = "G";
        c.symbol = "G";
        c.decimals = 18;
        c.features = (1 << 0) | (1 << 1) | (1 << 2);
        c.lockedFeatures = locked;
        c.owner = OWNER;
        return NormalToken(f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), salt));
    }

    function _open() internal pure returns (IGovernance.GrantTerms memory g) {
        g.max = NONE;
    }

    function _set(address holder, IGovernance.GrantTerms memory g) internal {
        vm.prank(OWNER);
        t.setGrant(MINT, holder, g);
    }

    function _mint(address who, uint256 v) internal {
        vm.prank(who);
        t.mint(TO, v);
    }

    function _refused(address who, uint256 v, bytes memory err) internal {
        vm.prank(who);
        vm.expectRevert(err);
        t.mint(TO, v);
    }

    function _ex(uint8 field) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IGovernance.GrantExhausted.selector, field);
    }

    function test_wholeShapeHasNoRecord() public {
        vm.prank(OWNER);
        t.grantRole(MINT, MANAGER);
        _mint(MANAGER, type(uint128).max);
        assertTrue(t.hasRole(MINT, MANAGER));
        assertEq(t.grantOf(MINT, MANAGER).spentTotal, 0);
        assertEq(t.holderCount(MINT), 1);
    }

    function test_bandOnTheScalar() public {
        IGovernance.GrantTerms memory g = _open();
        (g.min, g.max) = (10, 20);
        _set(MANAGER, g);
        _refused(MANAGER, 9, _ex(0));
        _mint(MANAGER, 10);
        _mint(MANAGER, 20);
        _refused(MANAGER, 21, _ex(1));
        assertEq(t.balanceOf(TO), 30);
    }

    function test_total() public {
        IGovernance.GrantTerms memory g = _open();
        g.total = 100;
        _set(MANAGER, g);
        _mint(MANAGER, 60);
        _mint(MANAGER, 40);
        _refused(MANAGER, 1, _ex(2));
    }

    function test_windowOnTheGrid() public {
        IGovernance.GrantTerms memory g = _open();
        (g.perWindow, g.window) = (50, 1 days);
        _set(MANAGER, g);
        _mint(MANAGER, 50);
        _refused(MANAGER, 1, _ex(3));
        vm.warp(block.timestamp + 1 days);
        _mint(MANAGER, 50);
    }

    function test_maxUsesAndExpiry() public {
        IGovernance.GrantTerms memory g = _open();
        (g.maxUses, g.validUntil) = (2, uint64(block.timestamp + 1 hours));
        _set(MANAGER, g);
        _mint(MANAGER, 1);
        _mint(MANAGER, 1);
        _refused(MANAGER, 1, _ex(5));
        g.maxUses = 0;
        _set(MANAGER, g);
        _mint(MANAGER, 1);
        vm.warp(block.timestamp + 1 hours + 1);
        _refused(MANAGER, 1, abi.encodeWithSelector(IGovernance.GrantExpired.selector, MINT, MANAGER));
    }

    function test_mintToUABoundToo() public {
        IGovernance.GrantTerms memory g = _open();
        g.max = 5;
        _set(MANAGER, g);
        vm.prank(MANAGER);
        vm.expectRevert(_ex(1));
        t.mintToUA(bytes32(uint256(1) << 200), 6);
    }

    function test_editNeverRefreshesABudget() public {
        IGovernance.GrantTerms memory g = _open();
        (g.total, g.perWindow, g.window, g.maxUses) = (100, 100, 1 days, 3);
        _set(MANAGER, g);
        _mint(MANAGER, 90);
        _set(MANAGER, g);
        assertEq(t.grantOf(MINT, MANAGER).spentTotal, 90);
        assertEq(t.grantOf(MINT, MANAGER).uses, 1);
        _refused(MANAGER, 11, _ex(2));
        vm.prank(OWNER);
        t.revokeRole(MINT, MANAGER);
        _set(MANAGER, g);
        _refused(MANAGER, 11, _ex(2)); // revoke, then grant again, keeps the spent as well
    }

    function _manager(uint128 total) internal {
        IGovernance.GrantTerms memory g = _open();
        (g.min, g.max, g.total, g.delegable, g.scope) = (1, 100, total, true, bytes32(uint256(7)));
        _set(MANAGER, g);
    }

    function _leafTerms(uint128 total) internal pure returns (IGovernance.GrantTerms memory g) {
        (g.min, g.max, g.total, g.scope) = (1, 50, total, bytes32(uint256(7)));
    }

    function test_leafDebitsItsParent() public {
        _manager(100);
        vm.startPrank(MANAGER);
        t.setGrant(MINT, OFFICER, _leafTerms(60));
        t.setGrant(MINT, OFFICER2, _leafTerms(60));
        vm.stopPrank();
        assertEq(t.holderCount(MINT), 3);
        _mint(OFFICER, 50);
        _mint(OFFICER2, 50);
        _refused(OFFICER, 1, _ex(2)); // the parent's 100, though the leaf has room
        assertEq(t.grantOf(MINT, MANAGER).spentTotal, 100);
    }

    function test_leafMustNarrow() public {
        _manager(100);
        IGovernance.GrantTerms memory g = _leafTerms(60);
        g.min = 0;
        _setLeaf(g, 0);
        g = _leafTerms(60);
        g.max = 101;
        _setLeaf(g, 1);
        g = _leafTerms(101);
        _setLeaf(g, 2);
        g = _leafTerms(0); // unbounded under a bounded parent
        _setLeaf(g, 2);
        g = _leafTerms(60);
        g.delegable = true;
        _setLeaf(g, 6);
        g = _leafTerms(60);
        g.scope = bytes32(uint256(8));
        _setLeaf(g, 7);
        vm.prank(MANAGER);
        t.setGrant(MINT, OFFICER, _leafTerms(60)); // the positive control
    }

    function _setLeaf(IGovernance.GrantTerms memory g, uint8 field) internal {
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantNotNarrower.selector, field));
        t.setGrant(MINT, OFFICER, g);
    }

    function test_onlyDelegableGrants_andOnlyItsOwnLeaves() public {
        vm.prank(OFFICER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotOwner.selector, OFFICER));
        t.setGrant(MINT, OFFICER2, _leafTerms(1));
        IGovernance.GrantTerms memory g = _open();
        _set(OFFICER, g); // limited, not delegable
        vm.prank(OFFICER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotOwner.selector, OFFICER));
        t.setGrant(MINT, OFFICER2, _leafTerms(1));
        _manager(100);
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotOwner.selector, MANAGER));
        t.setGrant(MINT, OFFICER, _leafTerms(1)); // not its leaf
    }

    function test_revokingTheParentKillsLeaves_andAGrantBackDoesNotRevive() public {
        _manager(100);
        vm.prank(MANAGER);
        t.setGrant(MINT, OFFICER, _leafTerms(60));
        _mint(OFFICER, 1);
        vm.prank(OWNER);
        t.revokeRole(MINT, MANAGER);
        _refused(OFFICER, 1, _ex(7));
        _manager(100);
        _refused(OFFICER, 1, _ex(7));
    }

    function test_grantorRevokesItsLeaf_noOneElse() public {
        _manager(100);
        vm.prank(MANAGER);
        t.setGrant(MINT, OFFICER, _leafTerms(60));
        vm.prank(OFFICER2);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotOwner.selector, OFFICER2));
        t.revokeRole(MINT, OFFICER);
        vm.prank(MANAGER);
        t.revokeRole(MINT, OFFICER);
        assertFalse(t.hasRole(MINT, OFFICER));
        assertEq(t.holderCount(MINT), 1);
    }

    function test_holderCount_idempotent_andRenounce() public {
        vm.startPrank(OWNER);
        t.grantRole(MINT, MANAGER);
        t.grantRole(MINT, MANAGER);
        assertEq(t.holderCount(MINT), 1);
        vm.stopPrank();
        _set(MANAGER, _open());
        assertEq(t.holderCount(MINT), 1, "whole to limited counts once");
        vm.prank(MANAGER);
        t.renounceRole(MINT);
        assertEq(t.holderCount(MINT), 0);
    }

    function test_renounceRefusedWhileAnUnlockedBitHasHolders() public {
        vm.startPrank(OWNER);
        t.grantRole(MINT, MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.OwnerHasHolders.selector, MINT));
        t.renounceOwnership();
        t.revokeRole(MINT, MANAGER);
        t.renounceOwnership();
        vm.stopPrank();
        assertEq(t.owner(), address(0));
    }

    function test_renounceWithALockedBitsHolderSurvives() public {
        NormalToken l = _token("l", 1 << MINT);
        vm.startPrank(OWNER);
        l.grantRole(MINT, MANAGER);
        l.renounceOwnership();
        vm.stopPrank();
        assertEq(l.owner(), address(0));
        vm.prank(MANAGER);
        l.mint(TO, 1);
    }

    function test_renounceWithADisabledBitsHolder() public {
        vm.startPrank(OWNER);
        t.grantRole(MINT, MANAGER);
        t.disableFeature(MINT);
        t.renounceOwnership();
        vm.stopPrank();
        assertEq(t.owner(), address(0));
    }

    function test_refusals() public {
        vm.startPrank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureReserved.selector, uint8(128)));
        t.grantRole(128, MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleAccountPool.selector, MINT, MetaTxLib.UA_POOL));
        t.grantRole(MINT, MetaTxLib.UA_POOL);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleAccountPool.selector, MINT, MetaTxLib.SHIELD_POOL));
        t.setGrant(MINT, MetaTxLib.SHIELD_POOL, _open());
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NoSuchRole.selector, uint8(0)));
        t.setGrant(0, MANAGER, _open()); // a capability has no holder
        IGovernance.GrantTerms memory g = _open();
        g.perWindow = 1;
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantNotNarrower.selector, uint8(3)));
        t.setGrant(MINT, MANAGER, g); // no window for a per-window bound
        vm.stopPrank();
    }

    /// `hasRole` is true for a limited holder: every power on the wrapped kinds must go through `use`.
    function test_wrappedPowerIsBound() public {
        MockERC20 usd = new MockERC20("USD", "USD", 6);
        IFactoryToken.TokenConfig memory c;
        c.name = "W";
        c.symbol = "W";
        c.decimals = 6;
        c.features = (1 << 0) | (1 << GovernanceBits.WRAP_DISABLEABLE);
        c.owner = OWNER;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        WrappedToken w = WrappedToken(payable(f.createToken(IOpenFactory.TokenKind.WRAPPED, 1, abi.encode(c), "w")));
        IGovernance.GrantTerms memory g = _open();
        g.validUntil = uint64(block.timestamp + 1 hours);
        vm.prank(OWNER);
        w.setGrant(GovernanceBits.WRAP_DISABLEABLE, MANAGER, g);
        vm.warp(block.timestamp + 2 hours);
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantExpired.selector, GovernanceBits.WRAP_DISABLEABLE, MANAGER));
        w.disableWrap(address(usd), bytes32(uint256(1)));
    }

    function test_dexPowerIsBound() public {
        Catalogue.dex(f, 1, type(SCaaSDex).creationCode, address(0));
        SCaaSDex d = SCaaSDex(f.createDex(1, abi.encode(ISCaaSDex.DexConfig(OWNER, 0, address(0xAA), false)), "d"));
        assertTrue(d.hasRole(GovernanceBits.LISTING, OWNER));
        IGovernance.GrantTerms memory g = _open();
        g.maxUses = 1;
        vm.prank(OWNER);
        d.setGrant(GovernanceBits.LISTING, MANAGER, g);
        vm.startPrank(MANAGER);
        d.setListedOnly(true);
        vm.expectRevert(_ex(5));
        d.setListedOnly(false);
        vm.stopPrank();
        vm.prank(OFFICER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, GovernanceBits.FEE_ROUTING, OFFICER));
        d.setFeeSplit(0, address(0xAA));
    }

    /// The DELEGATECALLs of the current call to `GovernanceLib` with selector `sel`.
    function _libCalls(Vm.AccountAccess[] memory acc, bytes4 sel) internal pure returns (uint256 k) {
        for (uint256 i; i < acc.length; ++i) {
            if (acc[i].kind == VmSafe.AccountAccessKind.DelegateCall && acc[i].data.length >= 4 && bytes4(acc[i].data) == sel) ++k;
        }
    }

    /// B-26: `use` is `GovernanceUse`, inlined; a whole-shape holder makes no call, a limited one exactly one DELEGATECALL to
    /// `GovernanceLib.useLimited` (no copy of its body in the token).
    function test_limitedUseIsOneDelegatecall() public {
        vm.prank(OWNER);
        t.grantRole(MINT, MANAGER);
        vm.startStateDiffRecording();
        _mint(MANAGER, 1);
        assertEq(_libCalls(vm.stopAndReturnStateDiff(), GovernanceLib.useLimited.selector), 0, "whole shape: no call");
        IGovernance.GrantTerms memory g = _open();
        g.total = 100;
        _set(OFFICER, g);
        vm.startStateDiffRecording();
        _mint(OFFICER, 1);
        assertEq(_libCalls(vm.stopAndReturnStateDiff(), GovernanceLib.useLimited.selector), 1, "limited: one DELEGATECALL");
    }

    /// B-27: the DEX's owner holds bits 11 and 12 from `initialize` through `initHolder`, once each, not by `grantRole`.
    function test_dexInitHoldsBothBitsThroughInitHolder() public {
        Catalogue.dex(f, 1, type(SCaaSDex).creationCode, address(0));
        vm.startStateDiffRecording();
        SCaaSDex d = SCaaSDex(f.createDex(1, abi.encode(ISCaaSDex.DexConfig(OWNER, 0, address(0xAA), false)), "d"));
        Vm.AccountAccess[] memory acc = vm.stopAndReturnStateDiff();
        assertEq(_libCalls(acc, GovernanceLib.initHolder.selector), 2, "initHolder, once per bit");
        assertEq(_libCalls(acc, GovernanceLib.grantRole.selector), 0, "no grantRole at init");
        assertTrue(d.hasRole(GovernanceBits.LISTING, OWNER));
        assertTrue(d.hasRole(GovernanceBits.FEE_ROUTING, OWNER));
        assertEq(d.holderCount(GovernanceBits.LISTING), 1);
        assertEq(d.holderCount(GovernanceBits.FEE_ROUTING), 1);
        assertEq(d.owner(), OWNER);
        // no owner: no holder either
        d = SCaaSDex(f.createDex(1, abi.encode(ISCaaSDex.DexConfig(address(0), 0, address(0xAA), false)), "d0"));
        assertEq(d.holderCount(GovernanceBits.LISTING), 0);
        assertEq(d.holderCount(GovernanceBits.FEE_ROUTING), 0);
    }

    /// B-31: every `GovernanceBase` contract answers `IGovernance` and `IERC165`, the DEX too.
    function test_dexAnswersIGovernance() public {
        Catalogue.dex(f, 1, type(SCaaSDex).creationCode, address(0));
        SCaaSDex d = SCaaSDex(f.createDex(1, abi.encode(ISCaaSDex.DexConfig(OWNER, 0, address(0xAA), false)), "d"));
        assertTrue(d.supportsInterface(type(IGovernance).interfaceId));
        assertTrue(d.supportsInterface(type(IERC165).interfaceId));
        assertFalse(d.supportsInterface(0xffffffff));
        assertTrue(t.supportsInterface(type(IGovernance).interfaceId)); // the same id on a token
    }

    /// B-31: no governance entry runs inside a settlement. The DEX's owner holds both bits and calls each of the four
    /// powers from a token hook while `mtxSettle` runs; each is refused by the guard. The settlement itself goes through.
    function test_dexPowerRefusedInsideASettlement() public {
        GovDexHolder h = new GovDexHolder();
        Catalogue.dex(f, 1, type(SCaaSDex).creationCode, address(0));
        SCaaSDex d = SCaaSDex(f.createDex(1, abi.encode(ISCaaSDex.DexConfig(address(h), 0, address(0xAA), false)), "d"));
        h.setDex(d);
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.features, c.initialSupply, c.initialHolder) = ("A", "A", 1, 1e6, vm.addr(ALICE_PK));
        NormalToken a = NormalToken(f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), "a"));
        GovHookERC20 hk = new GovHookERC20();
        vm.prank(address(h));
        d.setMarket(address(a), address(hk), true); // control: outside a settlement it runs
        hk.mint(vm.addr(DAVE_PK), 1e6);
        address puller = d.puller();
        vm.prank(vm.addr(DAVE_PK));
        hk.approve(puller, type(uint256).max);
        hk.setHook(address(h));
        DexLegs.Settlement[] memory ss = new DexLegs.Settlement[](1);
        ss[0] = _hookSettlement(d, a, address(hk));
        vm.prank(address(0xBEEF));
        bool[] memory ok = d.mtxSettle(DexLegs.wire(ss));
        assertTrue(ok[0], "the settlement runs");
        assertEq(h.n(), 4);
        bytes4 guard = bytes4(keccak256("ReentrancyGuardReentrantCall()"));
        for (uint256 i; i < 4; ++i) assertEq(h.errs(i), guard);
    }

    uint256 constant ALICE_PK = 0xA11CE;
    uint256 constant DAVE_PK = 0xDA7E;

    /// Dave sells 2000 of the hook token for 1000 A; Alice sells 1000 A for it, at Dave's price.
    function _hookSettlement(SCaaSDex d, NormalToken a, address hk) internal view returns (DexLegs.Settlement memory st) {
        st.ref = bytes32(uint256(1));
        st.makers = new DexLegs.Leg[](1);
        ITradeToken.TradeOrder memory o = _tradeOrder(vm.addr(DAVE_PK), address(a), 2000, 1000, address(d));
        st.makers[0] = DexLegs.Leg(hk, o, _sign(DAVE_PK, d.dexOrderDigest(hk, o)), 2000);
        o = _tradeOrder(vm.addr(ALICE_PK), hk, 1000, 2000, address(d));
        st.taker = DexLegs.Leg(address(a), o, _sign(ALICE_PK, a.tradeOrderDigest(o)), 1000);
    }

    function _sign(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    function _tradeOrder(address from, address receiveToken, uint256 amount, uint256 receiveAmount, address dex)
        internal view returns (ITradeToken.TradeOrder memory o)
    {
        (o.from, o.receiveToken, o.amount, o.receiveAmount, o.dex) = (from, receiveToken, amount, receiveAmount, dex);
        (o.batch, o.nonce, o.validUntil) = (1, 1, block.timestamp + 300);
    }

    // ------------------------------------------------------------------ gas, for docs/research/governance/prototype/

    function _gas(string memory label, address sender, address target, bytes memory cd) internal {
        vm.cool(target);
        vm.prank(sender);
        uint256 g0 = gasleft();
        (bool ok,) = target.call(cd);
        uint256 used = g0 - gasleft();
        assertTrue(ok, label);
        console.log("GOVGAS", label, used);
    }

    function test_gas_setGrant_fresh() public {
        IGovernance.GrantTerms memory g = _open();
        (g.min, g.total, g.perWindow, g.window, g.validUntil, g.maxUses) = (1, 1e6, 1e5, 1 days, uint64(block.timestamp + 365 days), 1000);
        g.scope = bytes32(uint256(7));
        _gas("setGrant fresh, every field set", OWNER, address(t), abi.encodeCall(IGovernance.setGrant, (MINT, MANAGER, g)));
    }

    function test_gas_mintLimited_everyBound() public {
        IGovernance.GrantTerms memory g = _open();
        (g.min, g.total, g.perWindow, g.window, g.validUntil, g.maxUses) = (1, 1e6, 1e5, 1 days, uint64(block.timestamp + 365 days), 1000);
        _set(MANAGER, g);
        _mint(MANAGER, 1);
        _gas("mint limited, every bound, second use", MANAGER, address(t), abi.encodeCall(NormalToken.mint, (TO, 1)));
    }

    function test_gas_mintLeaf() public {
        IGovernance.GrantTerms memory g = _open();
        (g.total, g.perWindow, g.window, g.delegable) = (1e6, 1e5, 1 days, true);
        _set(MANAGER, g);
        IGovernance.GrantTerms memory l = _open();
        (l.total, l.perWindow, l.window) = (1e4, 1e3, 1 days);
        vm.prank(MANAGER);
        t.setGrant(MINT, OFFICER, l);
        _mint(OFFICER, 1);
        _gas("mint leaf, parent debited, second use", OFFICER, address(t), abi.encodeCall(NormalToken.mint, (TO, 1)));
    }
}
