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
import {GovernanceBase, GovernanceUse} from "../../src/governance/GovernanceBase.sol";
import {ITradeToken} from "../../src/trade/ITradeToken.sol";
import {DexLegs} from "../helpers/DexLegs.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {Catalogue} from "../helpers/Catalogue.sol";
import {BranchApp} from "./GovAttackV2.t.sol";
import {nid} from "../helpers/Ids.sol";

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

/// An application in the top band (CTR-GOV-10's Change, owner 2026-11-04): bits 128 and 255, powers with no scalar or scope.
contract TopBandApp is GovernanceBase {
    uint256 internal constant BITS = (uint256(1) << 128) | (uint256(1) << 255);
    mapping(uint8 => uint256) public acted;

    constructor(address owner_) GovernanceBase(address(0)) {
        GovernanceLib.Roles memory none;
        GovernanceLib.init(BITS, 0, nid(owner_), 0, address(0), none, BITS, BITS, 0);
    }

    function _guardIn() internal pure override returns (bool) { return false; }
    function _guardOut(bool) internal pure override {}
    function _caller() internal view override returns (address) { return msg.sender; }
    function _validBits() internal pure override returns (uint256) { return BITS; }
    function _roleBits() internal pure override returns (uint256) { return BITS; }
    function _contractOnlyBits() internal pure override returns (uint256) { return 0; }
    function _scalarBits() internal pure override returns (uint256) { return 0; }
    function _scopeBits() internal pure override returns (uint256) { return 0; }

    function act(uint8 bit) external {
        GovernanceUse.use(bit, _govSubject(), 0);
        ++acted[bit];
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
        c.owner = nid(OWNER);
        return NormalToken(f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), salt));
    }

    function _open() internal pure returns (IGovernance.GrantTerms memory g) {
        g.max = NONE;
    }

    function _set(address holder, IGovernance.GrantTerms memory g) internal {
        vm.prank(OWNER);
        t.setGrant(MINT, nid(holder), g);
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
        t.grantRole(MINT, nid(MANAGER));
        _mint(MANAGER, type(uint128).max);
        assertTrue(t.hasRole(MINT, nid(MANAGER)));
        assertEq(t.grantOf(MINT, nid(MANAGER)).spentTotal, 0);
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
        assertEq(t.grantOf(MINT, nid(MANAGER)).spentTotal, 90);
        assertEq(t.grantOf(MINT, nid(MANAGER)).uses, 1);
        _refused(MANAGER, 11, _ex(2));
        vm.prank(OWNER);
        t.revokeRole(MINT, nid(MANAGER));
        _set(MANAGER, g);
        _refused(MANAGER, 11, _ex(2)); // revoke, then grant again, keeps the spent as well
    }

    function _manager(uint128 total) internal {
        IGovernance.GrantTerms memory g = _open();
        (g.min, g.max, g.total, g.delegable) = (1, 100, total, true);
        _set(MANAGER, g);
    }

    function _leafTerms(uint128 total) internal pure returns (IGovernance.GrantTerms memory g) {
        (g.min, g.max, g.total) = (1, 50, total);
    }

    function test_leafDebitsItsParent() public {
        _manager(100);
        vm.startPrank(MANAGER);
        t.setGrant(MINT, nid(OFFICER), _leafTerms(60));
        t.setGrant(MINT, nid(OFFICER2), _leafTerms(60));
        vm.stopPrank();
        assertEq(t.holderCount(MINT), 3);
        _mint(OFFICER, 50);
        _mint(OFFICER2, 50);
        _refused(OFFICER, 1, _ex(2)); // the parent's 100, though the leaf has room
        assertEq(t.grantOf(MINT, nid(MANAGER)).spentTotal, 100);
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
        vm.prank(MANAGER);
        t.setGrant(MINT, nid(OFFICER), _leafTerms(60)); // the positive control
        // scope, on a contract whose power reads it: the order is the contract's (equality by default)
        BranchApp a = new BranchApp(OWNER);
        IGovernance.GrantTerms memory p = _open();
        (p.total, p.delegable, p.scope) = (100, true, bytes32(uint256(7)));
        vm.prank(OWNER);
        a.setGrant(128, nid(MANAGER), p);
        (p.total, p.delegable, p.scope) = (10, false, bytes32(uint256(8)));
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantNotNarrower.selector, uint8(7)));
        a.setGrant(128, nid(OFFICER), p);
        p.scope = bytes32(uint256(7));
        vm.prank(MANAGER);
        a.setGrant(128, nid(OFFICER), p);
    }

    function _setLeaf(IGovernance.GrantTerms memory g, uint8 field) internal {
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantNotNarrower.selector, field));
        t.setGrant(MINT, nid(OFFICER), g);
    }

    function test_onlyDelegableGrants_andOnlyItsOwnLeaves() public {
        vm.prank(OFFICER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotOwner.selector, OFFICER));
        t.setGrant(MINT, nid(OFFICER2), _leafTerms(1));
        IGovernance.GrantTerms memory g = _open();
        _set(OFFICER, g); // limited, not delegable
        vm.prank(OFFICER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotOwner.selector, OFFICER));
        t.setGrant(MINT, nid(OFFICER2), _leafTerms(1));
        _manager(100);
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotOwner.selector, MANAGER));
        t.setGrant(MINT, nid(OFFICER), _leafTerms(1)); // not its leaf
    }

    function test_revokingTheParentKillsLeaves_andAGrantBackDoesNotRevive() public {
        _manager(100);
        vm.prank(MANAGER);
        t.setGrant(MINT, nid(OFFICER), _leafTerms(60));
        _mint(OFFICER, 1);
        vm.prank(OWNER);
        t.revokeRole(MINT, nid(MANAGER));
        _refused(OFFICER, 1, _ex(7));
        _manager(100);
        _refused(OFFICER, 1, _ex(7));
    }

    function test_grantorRevokesItsLeaf_noOneElse() public {
        _manager(100);
        vm.prank(MANAGER);
        t.setGrant(MINT, nid(OFFICER), _leafTerms(60));
        vm.prank(OFFICER2);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotOwner.selector, OFFICER2));
        t.revokeRole(MINT, nid(OFFICER));
        vm.prank(MANAGER);
        t.revokeRole(MINT, nid(OFFICER));
        assertFalse(t.hasRole(MINT, nid(OFFICER)));
        assertEq(t.holderCount(MINT), 1);
    }

    function test_holderCount_idempotent_andRenounce() public {
        vm.startPrank(OWNER);
        t.grantRole(MINT, nid(MANAGER));
        t.grantRole(MINT, nid(MANAGER));
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
        t.grantRole(MINT, nid(MANAGER));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.OwnerHasHolders.selector, MINT));
        t.renounceOwnership();
        t.revokeRole(MINT, nid(MANAGER));
        t.renounceOwnership();
        vm.stopPrank();
        assertEq(t.owner(), bytes32(0));
    }

    function test_renounceWithALockedBitsHolderSurvives() public {
        NormalToken l = _token("l", 1 << MINT);
        vm.startPrank(OWNER);
        l.grantRole(MINT, nid(MANAGER));
        l.renounceOwnership();
        vm.stopPrank();
        assertEq(l.owner(), bytes32(0));
        vm.prank(MANAGER);
        l.mint(TO, 1);
    }

    function test_renounceWithADisabledBitsHolder() public {
        vm.startPrank(OWNER);
        t.grantRole(MINT, nid(MANAGER));
        t.disableFeature(MINT);
        t.renounceOwnership();
        vm.stopPrank();
        assertEq(t.owner(), bytes32(0));
    }

    function test_refusals() public {
        vm.startPrank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NoSuchRole.selector, uint8(128)));
        t.grantRole(128, nid(MANAGER)); // an application bit this kind does not have, no band refusal (CTR-GOV-10)
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleAccountPool.selector, MINT, MetaTxLib.UA_POOL));
        t.grantRole(MINT, nid(MetaTxLib.UA_POOL));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.RoleAccountPool.selector, MINT, MetaTxLib.SHIELD_POOL));
        t.setGrant(MINT, nid(MetaTxLib.SHIELD_POOL), _open());
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NoSuchRole.selector, uint8(0)));
        t.setGrant(0, nid(MANAGER), _open()); // a capability has no holder
        vm.stopPrank();
    }

    /// CTR-GOV-10's Change (owner 2026-11-04): bits 128-255 are each application's and no band is refused. An application
    /// takes 128 and 255, grants and uses them; a token kind refuses an application bit by its own mask, not by a band.
    function test_bitsAbove127AreApplicationBits() public {
        TopBandApp a = new TopBandApp(OWNER);
        assertEq(a.features(), (uint256(1) << 128) | (uint256(1) << 255));
        vm.startPrank(OWNER);
        a.grantRole(128, nid(MANAGER));
        a.grantRole(255, nid(MANAGER));
        vm.stopPrank();
        vm.startPrank(MANAGER);
        a.act(128);
        a.act(255);
        vm.stopPrank();
        assertEq(a.acted(255), 1);
        assertEq(a.holderCount(128), 1);
        IGovernance.GrantTerms memory g = _open();
        g.maxUses = 1;
        vm.prank(OWNER);
        a.setGrant(255, nid(OFFICER), g);
        vm.prank(OFFICER);
        a.act(255);
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.owner, c.features) = ("G", "G", 18, nid(OWNER), 1 | (uint256(1) << 200));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, uint8(200)));
        f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), "b");
    }

    /// CTR-GOV-10's Change: bits 64-127 are SCaaS's, in the one global table; a kind without one refuses it as any SCaaS bit
    /// it lacks, and the role of a bit it lacks is no role.
    function test_bits64To127AreScaasBits() public {
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.owner) = ("G", "G", 18, nid(OWNER));
        c.features = 1 | (uint256(1) << 64);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, uint8(64)));
        f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), "s");
        c.features = 1 | (uint256(1) << 127);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureInvalidForKind.selector, uint8(127)));
        f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), "s");
        vm.startPrank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NoSuchRole.selector, uint8(127)));
        t.grantRole(127, nid(MANAGER));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NoSuchRole.selector, uint8(128)));
        t.grantRole(128, nid(MANAGER));
        vm.stopPrank();
    }

    function _word(IGovernance target, uint8 bit, IGovernance.GrantTerms memory g, uint8 field) internal {
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantWordRefused.selector, bit, field));
        target.setGrant(bit, nid(MANAGER), g);
    }

    /// B-09 (spec §1.5): on a bit outside `_scalarBits()` each of `min`, `max`, `total`, `perWindow`, `window` is refused by
    /// name; only `validUntil`, `maxUses`, `delegable` bind it. A wrapped kind's `WRAP_DISABLEABLE` and the DEX's `LISTING`.
    function test_eachWordRefusedOnAScalarlessBit() public {
        WrappedToken w = _wrapped("ws");
        SCaaSDex d = _dexOf("ds");
        uint8[2] memory bits = [GovernanceBits.WRAP_DISABLEABLE, GovernanceBits.LISTING];
        IGovernance[2] memory on = [IGovernance(address(w)), IGovernance(address(d))];
        for (uint256 i; i < 2; ++i) {
            IGovernance.GrantTerms memory g = _open();
            g.min = 1;
            _word(on[i], bits[i], g, 0);
            g = _open();
            g.max = 1;
            _word(on[i], bits[i], g, 1);
            g = _open();
            g.total = 1;
            _word(on[i], bits[i], g, 2);
            g = _open();
            (g.perWindow, g.window) = (1, 1 days);
            _word(on[i], bits[i], g, 3);
            g = _open();
            g.window = 1 days;
            _word(on[i], bits[i], g, 8);
            g = _open(); // positive control: the three words that bind such a bit
            (g.validUntil, g.maxUses, g.delegable) = (uint64(block.timestamp + 1 days), 3, true);
            vm.prank(OWNER);
            on[i].setGrant(bits[i], nid(MANAGER), g);
            assertEq(on[i].grantOf(bits[i], nid(MANAGER)).maxUses, 3);
        }
    }

    /// `perWindow` and `window` come together, both directions: `GrantWordRefused(bit, 3)`.
    function test_windowWithoutPerWindowRefused() public {
        IGovernance.GrantTerms memory g = _open();
        g.perWindow = 1;
        _word(t, MINT, g, 3);
        g = _open();
        g.window = 1 days;
        _word(t, MINT, g, 3);
        (g.perWindow, g.window) = (1, 1 days); // positive control
        _set(MANAGER, g);
        assertEq(t.grantOf(MINT, nid(MANAGER)).window, 1 days);
    }

    function _granted(Vm.Log[] memory logs) internal pure returns (uint256 k) {
        for (uint256 i; i < logs.length; ++i) if (logs[i].topics[0] == IGovernance.RoleGranted.selector) ++k;
    }

    /// B-31: `setGrant` on a new holder emits `RoleGranted`, so the indexed holder list is whole; an edit does not.
    function test_newHolderEmitsRoleGranted() public {
        vm.expectEmit(address(t));
        emit IGovernance.RoleGranted(MINT, nid(MANAGER), nid(OWNER));
        _set(MANAGER, _open());
        vm.recordLogs();
        _set(MANAGER, _open());
        assertEq(_granted(vm.getRecordedLogs()), 0, "an edit adds no holder");
        _manager(100);
        vm.expectEmit(address(t));
        emit IGovernance.RoleGranted(MINT, nid(OFFICER), nid(MANAGER));
        vm.prank(MANAGER);
        t.setGrant(MINT, nid(OFFICER), _leafTerms(10));
    }

    /// B-06 and GD-14: with no owner, a minter survives creation only on a locked bit.
    function test_lockedMinterSurvivesNoOwner() public {
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.features, c.roles.minter) = ("G", "G", 18, 7, nid(MANAGER));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.OwnerHasHolders.selector, MINT));
        f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), "n0");
        c.lockedFeatures = 1 << MINT;
        NormalToken n = NormalToken(f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), "n0"));
        assertEq(n.owner(), bytes32(0));
        assertTrue(n.hasRole(MINT, nid(MANAGER)));
        vm.prank(MANAGER);
        n.mint(TO, 1);
    }

    function _wrapped(bytes32 salt) internal returns (WrappedToken) {
        MockERC20 usd = new MockERC20("USD", "USD", 6);
        IFactoryToken.TokenConfig memory c;
        (c.name, c.symbol, c.decimals, c.owner) = ("W", "W", 6, nid(OWNER));
        c.features = (1 << 0) | (1 << GovernanceBits.WRAP_DISABLEABLE);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        return WrappedToken(payable(f.createToken(IOpenFactory.TokenKind.WRAPPED, 1, abi.encode(c), salt)));
    }

    function _dexOf(bytes32 salt) internal returns (SCaaSDex) {
        Catalogue.dex(f, 1, type(SCaaSDex).creationCode, address(0));
        return SCaaSDex(f.createDex(1, abi.encode(ISCaaSDex.DexConfig(nid(OWNER), 0, address(0xAA), false, 0, address(0))), salt));
    }

    /// `hasRole` is true for a limited holder: every power on the wrapped kinds must go through `use`.
    function test_wrappedPowerIsBound() public {
        MockERC20 usd = new MockERC20("USD", "USD", 6);
        IFactoryToken.TokenConfig memory c;
        c.name = "W";
        c.symbol = "W";
        c.decimals = 6;
        c.features = (1 << 0) | (1 << GovernanceBits.WRAP_DISABLEABLE);
        c.owner = nid(OWNER);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        WrappedToken w = WrappedToken(payable(f.createToken(IOpenFactory.TokenKind.WRAPPED, 1, abi.encode(c), "w")));
        IGovernance.GrantTerms memory g = _open();
        g.validUntil = uint64(block.timestamp + 1 hours);
        vm.prank(OWNER);
        w.setGrant(GovernanceBits.WRAP_DISABLEABLE, nid(MANAGER), g);
        vm.warp(block.timestamp + 2 hours);
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantExpired.selector, GovernanceBits.WRAP_DISABLEABLE, MANAGER));
        w.disableWrap(address(usd), bytes32(uint256(1)));
    }

    function test_dexPowerIsBound() public {
        Catalogue.dex(f, 1, type(SCaaSDex).creationCode, address(0));
        SCaaSDex d = SCaaSDex(f.createDex(1, abi.encode(ISCaaSDex.DexConfig(nid(OWNER), 0, address(0xAA), false, 0, address(0))), "d"));
        assertTrue(d.hasRole(GovernanceBits.LISTING, nid(OWNER)));
        IGovernance.GrantTerms memory g = _open();
        g.maxUses = 1;
        vm.prank(OWNER);
        d.setGrant(GovernanceBits.LISTING, nid(MANAGER), g);
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
        t.grantRole(MINT, nid(MANAGER));
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
        SCaaSDex d = SCaaSDex(f.createDex(1, abi.encode(ISCaaSDex.DexConfig(nid(OWNER), 0, address(0xAA), false, 0, address(0))), "d"));
        Vm.AccountAccess[] memory acc = vm.stopAndReturnStateDiff();
        assertEq(_libCalls(acc, GovernanceLib.initHolder.selector), 2, "initHolder, once per bit");
        assertEq(_libCalls(acc, GovernanceLib.grantRole.selector), 0, "no grantRole at init");
        assertTrue(d.hasRole(GovernanceBits.LISTING, nid(OWNER)));
        assertTrue(d.hasRole(GovernanceBits.FEE_ROUTING, nid(OWNER)));
        assertEq(d.holderCount(GovernanceBits.LISTING), 1);
        assertEq(d.holderCount(GovernanceBits.FEE_ROUTING), 1);
        assertEq(d.owner(), nid(OWNER));
        // no owner: no holder either
        d = SCaaSDex(f.createDex(1, abi.encode(ISCaaSDex.DexConfig(0, 0, address(0xAA), false, 0, address(0))), "d0"));
        assertEq(d.holderCount(GovernanceBits.LISTING), 0);
        assertEq(d.holderCount(GovernanceBits.FEE_ROUTING), 0);
    }

    /// B-31: every `GovernanceBase` contract answers `IGovernance` and `IERC165`, the DEX too.
    function test_dexAnswersIGovernance() public {
        Catalogue.dex(f, 1, type(SCaaSDex).creationCode, address(0));
        SCaaSDex d = SCaaSDex(f.createDex(1, abi.encode(ISCaaSDex.DexConfig(nid(OWNER), 0, address(0xAA), false, 0, address(0))), "d"));
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
        SCaaSDex d = SCaaSDex(f.createDex(1, abi.encode(ISCaaSDex.DexConfig(nid(address(h)), 0, address(0xAA), false, 0, address(0))), "d"));
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

    // ------------------------------------------------------------------ leaves, revoke, roots (spec §1.5, §1.7; T6)

    bytes32 constant GOV_ROOT = 0x0a3a361961b35589cdb03530b6f9e23a4db6ca9a0dad5ddf5d7761c7fabc8700;
    address constant OFFICER3 = address(0x0E);

    /// `Counts` of `bit` on `on`, read from `scaas.governance` + 6 (no view returns `roots`); `holders` is `holderCount`.
    function _counts(address on, uint8 bit) internal view returns (uint256 holders, uint256 roots) {
        uint256 w = uint256(vm.load(on, keccak256(abi.encode(uint256(bit), uint256(GOV_ROOT) + 6))));
        (holders, roots) = (uint128(w), w >> 128);
        assertEq(holders, IGovernance(on).holderCount(bit), "holders is holderCount");
    }

    function _isOn(address on, uint256 holders, uint256 roots) internal view {
        (uint256 h, uint256 r) = _counts(on, MINT);
        assertEq(h, holders, "holders");
        assertEq(r, roots, "roots");
    }

    function _is(uint256 holders, uint256 roots) internal view {
        _isOn(address(t), holders, roots);
    }

    function _revoke(address a) internal {
        vm.prank(OWNER);
        t.revokeRole(MINT, nid(a));
    }

    function _leaf(address a, uint128 total) internal {
        vm.prank(MANAGER);
        t.setGrant(MINT, nid(a), _leafTerms(total));
    }

    function _renounceRefused() internal {
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.OwnerHasHolders.selector, MINT));
        t.renounceOwnership();
    }

    function _renounce() internal {
        vm.prank(OWNER);
        t.renounceOwnership();
        assertEq(t.owner(), bytes32(0));
    }

    /// Row 1: the owner's apply, either entry, or INIT, on `r == 0`: holders +1, roots +1. A leaf revoked by its grantor keeps
    /// `grantor` in its record; the owner's grant makes it a root all the same (agy C-1), and it revokes to zero.
    function test_counts_row1() public {
        vm.prank(OWNER);
        t.grantRole(MINT, nid(OFFICER));
        _is(1, 1);
        _set(OFFICER2, _open());
        _is(2, 2);
        _revoke(OFFICER);
        _revoke(OFFICER2);
        _is(0, 0);
        _manager(100);
        _leaf(OFFICER3, 10);
        vm.prank(MANAGER);
        t.revokeRole(MINT, nid(OFFICER3));
        assertEq(t.grantOf(MINT, nid(OFFICER3)).grantor, nid(MANAGER), "the kept record");
        _is(1, 1);
        _set(OFFICER3, _open()); // setGrant
        _is(2, 2);
        assertEq(t.grantOf(MINT, nid(OFFICER3)).grantor, bytes32(0));
        vm.prank(OFFICER3);
        t.renounceRole(MINT);
        _is(1, 1);
        _leaf(OFFICER3, 10);
        vm.prank(MANAGER);
        t.revokeRole(MINT, nid(OFFICER3));
        vm.prank(OWNER);
        t.grantRole(MINT, nid(OFFICER3)); // grantRole
        _is(2, 2);
        _revoke(OFFICER3);
        _revoke(MANAGER);
        _is(0, 0);
        _renounce();
        IFactoryToken.TokenConfig memory c; // INIT
        (c.name, c.symbol, c.decimals, c.features, c.lockedFeatures, c.roles.minter) = ("G", "G", 18, 7, 1 << MINT, nid(MANAGER));
        _isOn(f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), "r1"), 1, 1);
    }

    /// Row 2: a delegable holder adds a leaf: holders +1, roots 0; the leaf blocks no renounce.
    function test_counts_row2() public {
        _manager(100);
        _is(1, 1);
        _leaf(OFFICER, 10);
        _is(2, 1);
        _revoke(MANAGER);
        _is(1, 0);
        _renounce();
    }

    /// Row 3: the grantor edits its leaf: no count moves.
    function test_counts_row3() public {
        _manager(100);
        _leaf(OFFICER, 10);
        _leaf(OFFICER, 20);
        _is(2, 1);
        assertEq(t.grantOf(MINT, nid(OFFICER)).total, 20);
        assertEq(t.grantOf(MINT, nid(OFFICER)).grantor, nid(MANAGER));
    }

    /// Row 4: the owner's `setGrant` on a leaf makes a `LIMITED` root: roots +1. Then the old root goes, the renounce is refused,
    /// and the new root's revoke does not underflow.
    function test_counts_row4() public {
        _manager(100);
        _leaf(OFFICER, 10);
        _set(OFFICER, _leafTerms(10));
        _is(2, 2);
        assertEq(t.grantOf(MINT, nid(OFFICER)).grantor, bytes32(0));
        _revoke(MANAGER);
        _is(1, 1);
        _renounceRefused();
        _mint(OFFICER, 1); // a root: alive though its old parent went
        _revoke(OFFICER);
        _is(0, 0);
        _renounce();
    }

    /// Row 5: the owner's `grantRole` on a leaf makes a `WHOLE` root: roots +1, the same sequence after.
    function test_counts_row5() public {
        _manager(100);
        _leaf(OFFICER, 10);
        vm.prank(OWNER);
        t.grantRole(MINT, nid(OFFICER));
        _is(2, 2);
        assertEq(t.grantOf(MINT, nid(OFFICER)).grantor, bytes32(0));
        _revoke(MANAGER);
        _is(1, 1);
        _renounceRefused();
        _mint(OFFICER, 1000);
        _revoke(OFFICER);
        _is(0, 0);
        _renounce();
    }

    /// Row 6: the owner's `setGrant` or `grantRole` on a root: no count moves.
    function test_counts_row6() public {
        _manager(100);
        _set(MANAGER, _open());
        _is(1, 1);
        vm.prank(OWNER);
        t.grantRole(MINT, nid(MANAGER));
        _is(1, 1);
        _set(MANAGER, _open());
        _is(1, 1);
    }

    /// Row 7: a root revoked or renounced: holders −1, roots −1, the record kept.
    function test_counts_row7() public {
        vm.prank(OWNER);
        t.grantRole(MINT, nid(OFFICER));
        IGovernance.GrantTerms memory g = _open();
        g.total = 7;
        _set(OFFICER2, g);
        _is(2, 2);
        _revoke(OFFICER);
        _is(1, 1);
        vm.prank(OFFICER2);
        t.renounceRole(MINT);
        _is(0, 0);
        assertEq(t.grantOf(MINT, nid(OFFICER2)).total, 7, "the record is kept");
        _renounce();
    }

    /// Row 8: a leaf revoked by the owner, by its grantor, or renounced: holders −1, roots 0, the record kept.
    function test_counts_row8() public {
        _manager(100);
        _leaf(OFFICER, 10);
        _leaf(OFFICER2, 10);
        _leaf(OFFICER3, 10);
        _is(4, 1);
        _revoke(OFFICER);
        _is(3, 1);
        vm.prank(MANAGER);
        t.revokeRole(MINT, nid(OFFICER2));
        _is(2, 1);
        vm.prank(OFFICER3);
        t.renounceRole(MINT);
        _is(1, 1);
        assertEq(t.grantOf(MINT, nid(OFFICER3)).total, 10, "the record is kept");
        assertEq(t.grantOf(MINT, nid(OFFICER3)).grantor, nid(MANAGER));
    }

    /// Row 9: the owner's revoke of a non-holder bars it and moves no count.
    function test_counts_row9() public {
        _manager(100);
        _revoke(OFFICER);
        _is(1, 1);
        assertTrue(t.grantOf(MINT, nid(OFFICER)).barred);
        assertFalse(t.hasRole(MINT, nid(OFFICER)));
    }

    /// Row 10: a leaf whose parent went is dead and listed; nothing moves its counts.
    function test_counts_row10() public {
        _manager(100);
        _leaf(OFFICER, 10);
        _revoke(MANAGER);
        _is(1, 0);
        _refused(OFFICER, 1, _ex(7));
        _is(1, 0);
    }

    /// Row 11: a root past `validUntil` cannot act and still counts.
    function test_counts_row11() public {
        IGovernance.GrantTerms memory g = _open();
        g.validUntil = uint64(block.timestamp + 1 hours);
        _set(MANAGER, g);
        vm.warp(block.timestamp + 2 hours);
        _refused(MANAGER, 1, abi.encodeWithSelector(IGovernance.GrantExpired.selector, MINT, MANAGER));
        _is(1, 1);
    }

    /// C7: an expired root counts as live until it is revoked; the renounce waits for that revoke.
    function test_expiredRootCountsUntilRevoked() public {
        IGovernance.GrantTerms memory g = _open();
        g.validUntil = uint64(block.timestamp + 1 hours);
        _set(MANAGER, g);
        vm.warp(block.timestamp + 2 hours);
        _renounceRefused();
        _revoke(MANAGER);
        _renounce();
    }

    /// B-07: `hasRole` means listed, not able to act: a dead leaf is listed, counted, and its record readable.
    function test_hasRoleMeansListed() public {
        _manager(100);
        _leaf(OFFICER, 10);
        _revoke(MANAGER);
        assertTrue(t.hasRole(MINT, nid(OFFICER)));
        assertEq(t.holderCount(MINT), 1);
        assertEq(t.grantOf(MINT, nid(OFFICER)).total, 10);
        _refused(OFFICER, 1, _ex(7));
        _revoke(OFFICER);
        assertFalse(t.hasRole(MINT, nid(OFFICER)));
    }

    /// B-05: only the owner re-admits a barred account, by either entry; then the bar is gone.
    function test_ownerReadmitsABarredAccount() public {
        _manager(100);
        _leaf(OFFICER, 10);
        _revoke(OFFICER);
        assertTrue(t.grantOf(MINT, nid(OFFICER)).barred);
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantBarred.selector, MINT, OFFICER));
        t.setGrant(MINT, nid(OFFICER), _leafTerms(10));
        vm.prank(OWNER);
        t.grantRole(MINT, nid(OFFICER));
        assertFalse(t.grantOf(MINT, nid(OFFICER)).barred, "grantRole re-admits");
        _mint(OFFICER, 1);
        _revoke(OFFICER);
        assertTrue(t.grantOf(MINT, nid(OFFICER)).barred);
        _set(OFFICER, _open());
        assertFalse(t.grantOf(MINT, nid(OFFICER)).barred, "setGrant re-admits");
        _mint(OFFICER, 1);
        vm.prank(OFFICER);
        t.renounceRole(MINT); // a renounce bars nobody
        _leaf(OFFICER, 10);
        assertEq(t.grantOf(MINT, nid(OFFICER)).grantor, nid(MANAGER));
    }

    /// Claude M-8: a leaf that renounces before the owner's revoke is barred all the same.
    function test_leafThatRenouncesFirstIsBarred() public {
        _manager(100);
        _leaf(OFFICER, 10);
        vm.prank(OFFICER);
        t.renounceRole(MINT);
        _revoke(OFFICER);
        assertTrue(t.grantOf(MINT, nid(OFFICER)).barred);
        _is(1, 1);
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantBarred.selector, MINT, OFFICER));
        t.setGrant(MINT, nid(OFFICER), _leafTerms(10));
        _leaf(OFFICER2, 10); // positive control
    }

    /// agy I-3: an expired parent adds nobody, though the terms narrow.
    function test_expiredParentAddsNobody() public {
        IGovernance.GrantTerms memory g = _open();
        (g.min, g.max, g.total, g.delegable, g.validUntil) = (1, 100, 100, true, uint64(block.timestamp + 1 hours));
        _set(MANAGER, g);
        IGovernance.GrantTerms memory l = _leafTerms(10);
        l.validUntil = g.validUntil;
        vm.prank(MANAGER); // positive control
        t.setGrant(MINT, nid(OFFICER), l);
        vm.warp(block.timestamp + 1 hours + 1);
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantExpired.selector, MINT, MANAGER));
        t.setGrant(MINT, nid(OFFICER2), l);
    }

    /// agy I-3: a parent with nothing left adds nobody: `total` spent on a scalar bit, `maxUses` used on the DEX's `LISTING`.
    function test_exhaustedParentAddsNobody() public {
        _manager(100);
        _mint(MANAGER, 90);
        _leaf(OFFICER, 10); // positive control: what remains
        _mint(OFFICER, 10);
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantNotNarrower.selector, uint8(2)));
        t.setGrant(MINT, nid(OFFICER2), _leafTerms(1));

        SCaaSDex d = _dexOf("ex");
        IGovernance.GrantTerms memory g = _open();
        (g.maxUses, g.delegable) = (2, true);
        vm.prank(OWNER);
        d.setGrant(GovernanceBits.LISTING, nid(MANAGER), g);
        (g.maxUses, g.delegable) = (1, false);
        vm.startPrank(MANAGER);
        d.setListedOnly(true);
        d.setGrant(GovernanceBits.LISTING, nid(OFFICER), g); // positive control: one use left
        d.setListedOnly(false);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantNotNarrower.selector, uint8(5)));
        d.setGrant(GovernanceBits.LISTING, nid(OFFICER2), g);
        vm.stopPrank();
    }

    /// agy I-3: a leaf's `maxUses` is bounded by what remains of its parent's.
    function test_leafMaxUsesByWhatRemains() public {
        IGovernance.GrantTerms memory g = _open();
        (g.total, g.maxUses, g.delegable) = (100, 5, true);
        _set(MANAGER, g);
        _mint(MANAGER, 1);
        _mint(MANAGER, 1);
        _mint(MANAGER, 1);
        IGovernance.GrantTerms memory l = _leafTerms(10);
        l.maxUses = 3;
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantNotNarrower.selector, uint8(5)));
        t.setGrant(MINT, nid(OFFICER), l);
        l.maxUses = 2;
        vm.prank(MANAGER);
        t.setGrant(MINT, nid(OFFICER), l);
        _mint(OFFICER, 1);
        _mint(OFFICER, 1);
        _refused(OFFICER, 1, _ex(5));
    }

    uint256 constant T0 = 700 * 30 days; // on the 10-day and the 30-day grid

    function _windowed(uint32 window) internal returns (IGovernance.GrantTerms memory g) {
        g = _open();
        (g.perWindow, g.window) = (100, window);
        _set(MANAGER, g);
    }

    function _windowRefused(IGovernance.GrantTerms memory g) internal {
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantWindowInUse.selector, MINT, MANAGER));
        t.setGrant(MINT, nid(MANAGER), g);
    }

    /// agy I-1: 100 spent at day 15 on a 10-day grid; at day 21 the old period is over, but on a 30-day grid day 15 lies in the
    /// current period, so the change is refused and no second 100 is minted that day.
    function test_windowChangeIntoASpentPeriodRefused() public {
        vm.warp(T0 + 15 days);
        IGovernance.GrantTerms memory g = _windowed(10 days);
        _mint(MANAGER, 100);
        vm.warp(T0 + 21 days);
        g.window = 30 days;
        _windowRefused(g);
        g.window = 10 days; // positive control: the window unchanged
        _set(MANAGER, g);
        assertEq(t.grantOf(MINT, nid(MANAGER)).window, 10 days);
    }

    /// agy I-1: once the spent period is over on the new grid too, the change runs and the new period is whole.
    function test_windowChangeAfterBothGridsPassed() public {
        vm.warp(T0 + 15 days);
        IGovernance.GrantTerms memory g = _windowed(10 days);
        _mint(MANAGER, 100);
        g.window = 30 days;
        vm.warp(T0 + 30 days - 1);
        _windowRefused(g);
        vm.warp(T0 + 30 days);
        _set(MANAGER, g);
        _mint(MANAGER, 100);
        _refused(MANAGER, 1, _ex(3));
    }

    /// agy I-1: a `WHOLE` holder had no bound; the stale words of its kept record refuse nothing.
    function test_wholeHolderStaleWindowRefusesNothing() public {
        vm.warp(T0 + 15 days);
        IGovernance.GrantTerms memory g = _windowed(10 days);
        _mint(MANAGER, 100);
        vm.warp(T0 + 21 days);
        g.window = 30 days;
        _windowRefused(g); // positive control: while LIMITED
        vm.prank(OWNER);
        t.grantRole(MINT, nid(MANAGER));
        _set(MANAGER, g);
        assertEq(t.grantOf(MINT, nid(MANAGER)).window, 30 days);
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
        _gas("setGrant fresh, every word NORMAL binds", OWNER, address(t), abi.encodeCall(IGovernance.setGrant, (MINT, nid(MANAGER), g)));
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
        t.setGrant(MINT, nid(OFFICER), l);
        _mint(OFFICER, 1);
        _gas("mint leaf, parent debited, second use", OFFICER, address(t), abi.encodeCall(NormalToken.mint, (TO, 1)));
    }
}
