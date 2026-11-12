// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {IAdmin} from "../../src/governance/IAdmin.sol";
import {GovernanceBase, GovernanceBaseCore, GovernanceUse} from "../../src/governance/GovernanceBase.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {GovernanceLib} from "../../src/governance/GovernanceLib.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {Catalogue} from "../helpers/Catalogue.sol";
import {nid} from "../helpers/Ids.sol";
import {EnvKit} from "../helpers/EnvKit.sol";

/// A third-party application on the base, v2 §1.6 shape: bit 128, the scope is a branch, the contract applies the predicate.
contract BranchApp is GovernanceBase {
    uint8 internal constant APPROVE = 128;
    mapping(bytes32 => uint256) public approved;

    constructor(address owner_) GovernanceBaseCore(address(0)) {
        GovernanceLib.Roles memory none;
        GovernanceLib.init(uint256(1) << APPROVE, 0, nid(owner_), 0, address(0), none, uint256(1) << APPROVE, uint256(1) << APPROVE, 0,
            address(0));
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

    function approve(bytes32 branch, uint128 principal) external {
        require(GovernanceUse.use(APPROVE, _govSubject(), principal) == branch, "branch");
        approved[branch] += principal;
    }
}

/// `createTokenUnregistered`'s implementation is anyone's: this one reports no feature and seizes at will.
contract LyingLeg {
    address public immutable factory;
    bytes32 public immutable chainUid;
    mapping(address => uint256) public balanceOf;

    constructor(address f, bytes32 uid) {
        (factory, chainUid) = (f, uid);
    }

    function kind() external pure returns (uint8) { return 0; }
    function modules() external pure returns (address[] memory) {} // T66b: no body module
    function validateEnv(IFactoryToken.ChainEnv calldata) external pure {}
    function initialize(bytes32, uint64, bytes calldata) external {}
    function underlyings() external pure returns (address[] memory) {}
    function features() external pure returns (uint256) { return 1; } // PAYABLE only: no bit 6, no bit 9
    function lockedFeatures() external pure returns (uint256) { return 1; }
    function admin() external pure returns (address) {}
    function decimals() external pure returns (uint8) { return 18; }
    function seize(address from, address to, uint256 v) external {
        balanceOf[from] -= v;
        balanceOf[to] += v;
    }
    function fund(address a, uint256 v) external { balanceOf[a] += v; }
}

/// Attack round on the permission model v2 and the prototype: docs/research/governance/permission-model-v2-attack.md. Each
/// `test_attack_*` passes while its hole is open and holds a positive control, so a fix makes it fail: read a failure as "fixed",
/// then turn it into the refusal. Each `test_refuted_*` is a claim the round tried and could not make fail.
contract GovAttackV2Test is Test {
    bytes32 constant UID = 0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464;
    uint8 constant MINT = GovernanceBits.MINTABLE;
    uint8 constant LISTING = GovernanceBits.LISTING;
    uint8 constant FEE_ROUTING = GovernanceBits.FEE_ROUTING;
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
        f = EnvKit.factory(address(this), UID, 0);
        Catalogue.plain(f, IOpenFactory.TokenKind.NORMAL, 1, type(NormalToken).creationCode, address(0), address(0), false);
        Catalogue.plain(f, IOpenFactory.TokenKind.WRAPPED, 1, type(WrappedToken).creationCode, address(0), address(0), false);
        t = _token("t", 0, OWNER);
    }

    function _config(uint256 locked, address owner_) internal pure returns (IFactoryToken.TokenConfig memory c) {
        c.name = "G";
        c.symbol = "G";
        c.decimals = 18;
        c.features = (1 << 0) | (1 << 1) | (1 << 2);
        c.lockedFeatures = locked;
        c.admin = nid(owner_);
    }

    function _token(bytes32 salt, uint256 locked, address owner_) internal returns (NormalToken) {
        return NormalToken(f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(_config(locked, owner_)), salt));
    }

    function _open() internal pure returns (IGovernance.GrantTerms memory g) {
        g.max = NONE;
    }

    function _manager(uint128 total) internal {
        IGovernance.GrantTerms memory g = _open();
        (g.total, g.delegable) = (total, true);
        vm.prank(OWNER);
        t.setGrant(MINT, nid(MANAGER), g);
    }

    function _leaf(uint128 total) internal {
        IGovernance.GrantTerms memory g = _open();
        g.total = total;
        vm.prank(MANAGER);
        t.setGrant(MINT, nid(OFFICER), g);
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

    function _dex(bytes32 salt) internal returns (SCaaSDex) {
        Catalogue.dex(f, 1, type(SCaaSDex).creationCode, address(0));
        return SCaaSDex(f.createDex(1, abi.encode(ISCaaSDex.DexConfig(nid(OWNER), 0, address(0xAA), false, 0, address(0))), salt));
    }

    // ------------------------------------------------------------------ delay (B-01, B-02)

    /// B-01, fixed (spec §1.6, CTR-GOV-04's Change): with a `grantDelay`, `setGrant` that makes a holder takes the owner's
    /// two calls, as `grantRole` does; the first proposes, the confirm in the window applies.
    function test_fixed_setGrantMakesAnUnboundedHolderInOneCall() public {
        IFactoryToken.TokenConfig memory c = _config(0, OWNER);
        c.grantDelay = 2 days;
        NormalToken d = NormalToken(f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), "d"));
        vm.prank(OWNER);
        d.setGrant(MINT, nid(OFFICER), _open());
        assertFalse(d.hasRole(MINT, nid(OFFICER)));
        vm.prank(OFFICER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, MINT, OFFICER));
        d.mint(TO, 1);
        vm.warp(block.timestamp + 2 days);
        vm.prank(OWNER); // positive control: the confirm
        d.setGrant(MINT, nid(OFFICER), _open());
        vm.prank(OFFICER);
        d.mint(TO, type(uint128).max);
        assertEq(d.balanceOf(TO), type(uint128).max);
    }

    /// B-02, fixed (spec §1.5, C3): a delegable grant needs a finite budget, `total` on a scalar bit and `maxUses` on another.
    /// The budget bounds what the leaves spend, not how many there are: a leaf is still added with no owner call.
    function test_fixed_delegableHolderAddsAHolderWithNoOwnerCall() public {
        IGovernance.GrantTerms memory g = _open();
        g.delegable = true;
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantBudgetRequired.selector, MINT));
        t.setGrant(MINT, nid(MANAGER), g);
        g.maxUses = 5; // a use count is no budget on a scalar bit
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantBudgetRequired.selector, MINT));
        t.setGrant(MINT, nid(MANAGER), g);
        SCaaSDex d = _dex("d");
        g.maxUses = 0;
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantBudgetRequired.selector, LISTING));
        d.setGrant(LISTING, nid(MANAGER), g);
        g.maxUses = 2; // positive control on a scalarless bit
        vm.prank(OWNER);
        d.setGrant(LISTING, nid(MANAGER), g);

        _manager(100); // positive control: a leaf with no owner call, spending the parent's 100 only
        _leaf(100);
        _mint(MANAGER, 50);
        _refused(OFFICER, 51, _ex(2));
        _mint(OFFICER, 50);
        assertEq(t.grantOf(MINT, nid(MANAGER)).spentTotal, 100);
    }

    // ------------------------------------------------------------------ the factory enum (B-03)

    /// B-03, fixed (CTR-GOV-16): kind 8 is a real member. It decodes on this factory and is refused by name until a release
    /// is published, and the registrar can enable it, so a frozen factory can still make it.
    function test_fixed_aReservedKindDecodes() public {
        bytes memory cfg = abi.encode(_config(0, OWNER));
        (bool ok,) = address(f).call(abi.encodeWithSelector(f.createToken.selector, uint8(0), uint64(1), cfg, bytes32("a")));
        assertTrue(ok); // positive control: the same call, kind 0
        bytes memory ret;
        (ok, ret) = address(f).call(abi.encodeWithSelector(f.createToken.selector, uint8(8), uint64(1), cfg, bytes32("b")));
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(IOpenFactory.VersionUnknown.selector, uint8(8), uint64(1)));
        (ok,) = address(f).call(abi.encodeWithSelector(f.setTokenKindEnabled.selector, uint8(8), true, EnvKit.uidOf(address(f))));
        assertTrue(ok);
        assertTrue(f.tokenKindEnabled(IOpenFactory.TokenKind.NORMAL_REGULATED));
    }

    /// B-03, stated: a token of a second factory stays an outside leg to the first's `isToken`, whatever its bits.
    function test_stated_aSecondFactorysTokenIsOutsideToTheFirst() public {
        OpenFactory f2 = EnvKit.factory(address(this), UID, 0);
        Catalogue.plain(f2, IOpenFactory.TokenKind.NORMAL, 1, type(NormalToken).creationCode, address(0), address(0), false);
        address other = f2.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(_config(0, OWNER)), "x");
        assertTrue(f2.isToken(other)); // positive control
        assertFalse(f.isToken(other));
    }

    // ------------------------------------------------------------------ the revoke (B-04, B-05)

    /// B-04, fixed (spec §1.5): a grantor revokes only while the account is its `LIMITED` leaf and it still holds the bit. The
    /// owner's take-over clears `grantor`; a revoked grantor cannot reach even its own dead leaf.
    function test_fixed_revokedGrantorStripsAnOwnerGrantedHolder() public {
        _manager(100);
        _leaf(50);
        vm.startPrank(OWNER);
        t.grantRole(MINT, nid(OFFICER)); // the owner takes the officer over: whole shape
        t.revokeRole(MINT, nid(MANAGER)); // and removes the manager
        vm.stopPrank();
        assertFalse(t.hasRole(MINT, nid(MANAGER)));
        assertEq(t.grantOf(MINT, nid(OFFICER)).grantor, bytes32(0));

        vm.prank(OFFICER2); // a stranger is refused
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotAdmin.selector, OFFICER2));
        t.revokeRole(MINT, nid(OFFICER));
        vm.prank(MANAGER); // a holder of nothing, and the officer is no longer its leaf
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotAdmin.selector, MANAGER));
        t.revokeRole(MINT, nid(OFFICER));
        assertTrue(t.hasRole(MINT, nid(OFFICER)));

        _manager(100); // a revoked grantor and its own leaf: refused while it holds nothing
        vm.prank(MANAGER);
        t.setGrant(MINT, nid(OFFICER2), _leafTerms(50));
        vm.prank(OWNER);
        t.revokeRole(MINT, nid(MANAGER));
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotAdmin.selector, MANAGER));
        t.revokeRole(MINT, nid(OFFICER2));
        _manager(100); // positive control: a grantor that holds revokes its leaf
        vm.prank(MANAGER);
        t.revokeRole(MINT, nid(OFFICER2));
        assertFalse(t.hasRole(MINT, nid(OFFICER2)));
    }

    function _leafTerms(uint128 total) internal pure returns (IGovernance.GrantTerms memory g) {
        g.max = NONE;
        g.total = total;
    }

    /// B-05, fixed (spec §1.5): the owner's revoke bars the account; its parent cannot grant it back.
    function test_fixed_parentGrantsBackALeafTheOwnerRevoked() public {
        _manager(100);
        _leaf(50);
        vm.prank(OWNER);
        t.revokeRole(MINT, nid(OFFICER));
        _refused(OFFICER, 1, abi.encodeWithSelector(IGovernance.MissingRole.selector, MINT, OFFICER));
        assertTrue(t.grantOf(MINT, nid(OFFICER)).barred);
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantBarred.selector, MINT, OFFICER));
        t.setGrant(MINT, nid(OFFICER), _leafTerms(50));
        vm.prank(MANAGER); // positive control: another account is added
        t.setGrant(MINT, nid(OFFICER2), _leafTerms(50));
        _mint(OFFICER2, 1);
    }

    // ------------------------------------------------------------------ the renounce rule (B-06, B-07, B-08)

    /// B-06, fixed (spec §1.7): `init` runs the renounce rule when `owner == 0`, so no token is born with an unlocked holder
    /// and no owner. A locked bit's holder survives, as at a renounce.
    function test_fixed_createdWithoutOwnerKeepsAnUnlockedMinter() public {
        IFactoryToken.TokenConfig memory c = _config(0, address(0));
        c.roles.minter = nid(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.AdminHasHolders.selector, MINT));
        f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), "n");

        c.lockedFeatures = 1 << MINT; // positive control: the lock promises the power
        NormalToken n = NormalToken(f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), "n"));
        assertEq(n.admin(), bytes32(0));
        vm.prank(MANAGER);
        n.mint(TO, 1);
    }

    /// B-07, fixed (spec §1.7): the renounce rule reads live roots. A dead leaf stays listed and counted in `holderCount`, and
    /// does not block the renounce.
    function test_fixed_deadLeavesBlockTheRenounce() public {
        _manager(100);
        _leaf(50);
        _mint(OFFICER, 1);
        vm.prank(OWNER); // positive control: a live root blocks it
        vm.expectRevert(abi.encodeWithSelector(IGovernance.AdminHasHolders.selector, MINT));
        t.renounceAdmin(EnvKit.codeUidOf(address(t)));
        vm.prank(OWNER);
        t.revokeRole(MINT, nid(MANAGER));
        _refused(OFFICER, 1, _ex(7)); // dead
        assertTrue(t.hasRole(MINT, nid(OFFICER))); // and reported as a holder
        assertEq(t.holderCount(MINT), 1);
        vm.prank(OWNER);
        t.renounceAdmin(EnvKit.codeUidOf(address(t)));
        assertEq(t.admin(), bytes32(0));
    }

    /// B-08, fixed (spec §1.5): once the owner is 0 nothing above changes, the holder list included: a locked bit's delegable
    /// holder survives the renounce and adds nobody.
    function test_fixed_afterRenounceALockedBitsHolderAddsHolders() public {
        t = _token("l", 1 << MINT, OWNER);
        _manager(100);
        vm.prank(MANAGER); // positive control: with an owner, the leaf is added
        t.setGrant(MINT, nid(OFFICER2), _leafTerms(10));
        vm.prank(OWNER);
        t.renounceAdmin(EnvKit.codeUidOf(address(t)));
        assertEq(t.admin(), bytes32(0));
        assertEq(t.holderCount(MINT), 2);
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotAdmin.selector, MANAGER));
        t.setGrant(MINT, nid(OFFICER), _leafTerms(50));
        assertEq(t.holderCount(MINT), 2);
        _mint(MANAGER, 50); // the locked power itself survives
    }

    // ------------------------------------------------------------------ the grant record (B-09 to B-12)

    function _wordRefused(SCaaSDex d, uint8 bit, IGovernance.GrantTerms memory g, uint8 field) internal {
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantWordRefused.selector, bit, field));
        d.setGrant(bit, nid(MANAGER), g);
    }

    /// B-09, fixed (spec §1.5, G11): a bound the contract does not read is refused at `setGrant`, not stored. The DEX's powers
    /// pass no scalar, so `total`, `perWindow` and `window` are refused there.
    function test_fixed_noScalarMeansNoTotalAndNoWindow() public {
        SCaaSDex d = _dex("d");
        IGovernance.GrantTerms memory g = _open();
        g.total = 1;
        _wordRefused(d, LISTING, g, 2);
        g = _open();
        (g.perWindow, g.window) = (1, 1 days);
        _wordRefused(d, LISTING, g, 3);
        g = _open();
        g.window = 1 days;
        _wordRefused(d, LISTING, g, 8);
        assertFalse(d.hasRole(LISTING, nid(MANAGER)));

        g = _open();
        g.maxUses = 1; // positive control: `maxUses` does bind (`GovGrant` shows it for `validUntil`)
        vm.prank(OWNER);
        d.setGrant(FEE_ROUTING, nid(MANAGER), g);
        vm.startPrank(MANAGER);
        d.setFeeSplit(0, address(0xAA));
        vm.expectRevert(_ex(5));
        d.setFeeSplit(0, address(0xAA));
        vm.stopPrank();
    }

    /// B-09, fixed: `min` and `max` on a power with no scalar are refused, so a floor cannot brick it.
    function test_fixed_aFloorBricksAPowerWithNoScalar() public {
        SCaaSDex d = _dex("d");
        IGovernance.GrantTerms memory g = _open();
        g.min = 1;
        _wordRefused(d, LISTING, g, 0);
        g = _open();
        g.max = 5;
        _wordRefused(d, LISTING, g, 1);
        vm.prank(OWNER); // positive control: the open terms are accepted, and the power runs
        d.setGrant(LISTING, nid(MANAGER), _open());
        vm.prank(MANAGER);
        d.setListedOnly(true);
    }

    /// B-10, fixed (spec §1.5): a `scope` on a power that does not read it is refused; a scoped power refuses scope 0.
    function test_fixed_aScopeOnABuiltPowerBindsNothing() public {
        IGovernance.GrantTerms memory g = _open();
        g.scope = bytes32(uint256(uint160(TO)));
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantWordRefused.selector, MINT, uint8(7)));
        t.setGrant(MINT, nid(MANAGER), g);
        BranchApp a = new BranchApp(OWNER);
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantWordRefused.selector, uint8(128), uint8(7)));
        a.setGrant(128, nid(MANAGER), _open());
        vm.prank(OWNER); // positive control: a scope where the power reads it
        a.setGrant(128, nid(MANAGER), g);
        vm.prank(MANAGER);
        a.approve(g.scope, 1);
    }

    /// B-11, fixed (spec §1.5): the owner's edit that changes a parent's scope bumps its epoch, so its leaves die.
    function test_fixed_leafKeepsAScopeItsParentLost() public {
        BranchApp a = new BranchApp(OWNER);
        (bytes32 b7, bytes32 b8) = (bytes32(uint256(7)), bytes32(uint256(8)));
        IGovernance.GrantTerms memory g = _open();
        (g.delegable, g.scope, g.total) = (true, b7, 100);
        vm.prank(OWNER);
        a.setGrant(128, nid(MANAGER), g);
        IGovernance.GrantTerms memory l = _open();
        (l.scope, l.total) = (b7, 50);
        vm.prank(MANAGER);
        a.setGrant(128, nid(OFFICER), l);
        vm.prank(OFFICER); // positive control: the leaf acts in branch 7 while its parent is there
        a.approve(b7, 2);

        g.scope = b8; // the owner moves the manager; the edit is not a revoke
        vm.prank(OWNER);
        a.setGrant(128, nid(MANAGER), g);
        vm.prank(MANAGER); // positive control: the parent is out of branch 7
        vm.expectRevert(bytes("branch"));
        a.approve(b7, 1);
        vm.prank(OFFICER);
        vm.expectRevert(_ex(7));
        a.approve(b7, 5);
        assertEq(a.approved(b7), 2);
        assertEq(a.grantOf(128, nid(MANAGER)).spentTotal, 2);
    }

    /// B-11, fixed: the same for `delegable`: the owner ends the delegation, the leaves die.
    function test_fixed_endingDelegationLeavesTheLeaves() public {
        _manager(100);
        _leaf(50);
        _mint(OFFICER, 1); // positive control: alive under a delegating parent
        IGovernance.GrantTerms memory g = _open();
        g.total = 100;
        vm.prank(OWNER);
        t.setGrant(MINT, nid(MANAGER), g);
        assertFalse(t.grantOf(MINT, nid(MANAGER)).delegable);
        _refused(OFFICER, 1, _ex(7));
    }

    /// B-12, fixed (spec §1.5): changing `window` while the spent period still runs on the new grid is refused.
    function test_fixed_changingTheWindowRefreshesTheBudget() public {
        IGovernance.GrantTerms memory g = _open();
        (g.perWindow, g.window) = (50, 1 days);
        vm.startPrank(OWNER);
        t.setGrant(MINT, nid(MANAGER), g);
        vm.stopPrank();
        _mint(MANAGER, 50);
        _refused(MANAGER, 1, _ex(3)); // positive control: exhausted
        vm.prank(OWNER);
        t.setGrant(MINT, nid(MANAGER), g); // the same terms: carried, as `GovGrant` pins
        _refused(MANAGER, 1, _ex(3));
        g.window = 1 days + 1; // one second longer, narrower by any reading
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantWindowInUse.selector, MINT, MANAGER));
        t.setGrant(MINT, nid(MANAGER), g);
        _refused(MANAGER, 1, _ex(3)); // the same second
        assertEq(t.balanceOf(TO), 50);
    }

    // ------------------------------------------------------------------ the DEX (B-13)

    /// B-13: today's admin moved with the admin word. `owner` moves alone: the old one keeps both powers, the new one has neither.
    function test_attack_dexTransferLeavesThePowersBehind() public {
        SCaaSDex d = _dex("d");
        address next = address(0x1234);
        address evil = address(0xE11);
        vm.prank(OWNER);
        d.transferAdmin(nid(next), EnvKit.codeUidOf(address(d)));
        vm.prank(next);
        d.acceptAdmin();
        assertEq(d.admin(), nid(next));
        vm.prank(next);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, FEE_ROUTING, next));
        d.setFeeSplit(0, next);
        vm.prank(OWNER);
        d.setFeeSplit(0, evil);
        assertEq(d.treasury(), evil);
    }

    // ------------------------------------------------------------------ the holder sketch (B-14, refuted R-*)

    // The sketch gave way to the real `GovernanceRouter` (plan T11, CTR-GOV-15 Change): B-14 is
    // `test_fixed_theRoutersOpIsNotReachableAsABytesBlob`, R-02 `test_refuted_replayAcrossRoutersAndChains` and
    // `test_refuted_relayerAltersTheTarget`, R-03 `test_refuted_formerOwnersEnvelope`, R-04
    // `test_refuted_targetReentersTheRouter`, in `GovRouter.t.sol`.

    // ------------------------------------------------------------------ smaller holes (B-15 to B-19)

    /// B-15, fixed (spec §6.1): `isToken` is true for an implementation nobody vetted, so `features()` there is a self-report.
    /// The leg check asks the factory `isRegisteredToken`, so the lying leg is an outside leg: never asked for its features,
    /// accepted and disclosed as outside, and its own code still moves its balances (stated: an outside leg is as good as its
    /// issuer). Positive control: a registered leg's `features()` is read once.
    function test_fixed_isTokenTrustsAnUnregisteredLeg() public {
        LyingLeg impl = new LyingLeg(address(f), UID);
        address leg = f.createTokenUnregistered(IOpenFactory.TokenKind.NORMAL, address(impl), "", "leg");
        assertTrue(f.isToken(leg));
        assertFalse(f.isRegisteredToken(leg));

        IFactoryToken.TokenConfig memory c = _config(0, OWNER);
        c.features = 1;
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(leg, 1, 1);
        vm.expectCall(address(f), abi.encodeCall(IOpenFactory.isRegisteredToken, (leg)), 1);
        vm.expectCall(leg, abi.encodeCall(IGovernance.features, ()), 0);
        address w = f.createToken(IOpenFactory.TokenKind.WRAPPED, 1, abi.encode(c), "w");
        LyingLeg(leg).fund(w, 10);
        LyingLeg(leg).seize(w, TO, 10);
        assertEq(LyingLeg(leg).balanceOf(w), 0);

        address good = f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(_config(0, OWNER)), "good");
        c.legs[0] = IFactoryToken.Leg(good, 1, 1);
        vm.expectCall(good, abi.encodeCall(IGovernance.features, ()), 1);
        f.createToken(IOpenFactory.TokenKind.WRAPPED, 1, abi.encode(c), "w2");
    }

    /// B-16: a revoked rate admin's proposal outlives it. Wrap stays paused, and the owner has no way to cancel but to grant a
    /// canceller, which CTR-GOV-04 will delay.
    function test_attack_revokedRateAdminsProposalOutlivesIt() public {
        MockERC20 usd = new MockERC20("USD", "USD", 6);
        address admin = address(usd); // anything with code
        IFactoryToken.TokenConfig memory c = _config(0, OWNER);
        c.decimals = 6;
        c.features = (1 << 0) | (1 << GovernanceBits.RATE_ADJUSTABLE);
        c.roles.rateAdmin = nid(admin);
        c.rate = IFactoryToken.RateConfig(2 days, 1000);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        WrappedToken w = WrappedToken(payable(f.createToken(IOpenFactory.TokenKind.WRAPPED, 1, abi.encode(c), "w")));
        vm.prank(admin);
        w.proposeRate(address(usd), 101, 100);
        vm.prank(OWNER);
        w.revokeRole(GovernanceBits.RATE_ADJUSTABLE, nid(admin));
        vm.prank(OWNER);
        vm.expectRevert(IWrappedToken.NotRateAdmin.selector);
        w.cancelRate();
        vm.expectRevert(abi.encodeWithSelector(IWrappedToken.WrapPausedForRateChange.selector, address(usd)));
        w.wrap(address(usd), 1);
    }

    /// B-17, fixed (spec §1.5): under a parent with a window, a leaf's `window` equals the parent's, `GrantNotNarrower(8)`.
    function test_fixed_aLeafsWindowIsNotNarrowed() public {
        IGovernance.GrantTerms memory g = _open();
        (g.total, g.perWindow, g.window, g.delegable) = (1000, 100, 1 days, true);
        vm.prank(OWNER);
        t.setGrant(MINT, nid(MANAGER), g);
        IGovernance.GrantTerms memory l = _open();
        (l.total, l.perWindow, l.window) = (1000, 100, 1);
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantNotNarrower.selector, uint8(8)));
        t.setGrant(MINT, nid(OFFICER), l); // 8,640,000 a day against the parent's 100
        l.window = 1 days + 1;
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantNotNarrower.selector, uint8(8)));
        t.setGrant(MINT, nid(OFFICER), l);
        l.window = 1 days; // positive control: the parent's window
        vm.prank(MANAGER);
        t.setGrant(MINT, nid(OFFICER), l);
        _mint(OFFICER, 100);
        _refused(OFFICER, 1, _ex(3));
    }

    /// B-18, fixed (spec §1.5): `total` narrows by comparison, never a subtraction: an owner's edit below `spent` leaves the
    /// leaf path a named refusal.
    function test_fixed_narrowingBelowSpentPanicsTheLeafPath() public {
        _manager(100);
        _mint(MANAGER, 60);
        IGovernance.GrantTerms memory g = _open();
        (g.total, g.delegable) = (50, true);
        vm.prank(OWNER);
        t.setGrant(MINT, nid(MANAGER), g);
        IGovernance.GrantTerms memory l = _open();
        l.total = 1;
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantNotNarrower.selector, uint8(2)));
        t.setGrant(MINT, nid(OFFICER), l);
        (g.total, g.delegable) = (61, true); // positive control: one unit left, one unit granted
        vm.prank(OWNER);
        t.setGrant(MINT, nid(MANAGER), g);
        vm.prank(MANAGER);
        t.setGrant(MINT, nid(OFFICER), l);
    }

    /// B-18, fixed (spec §1.5): `_grant` over a `LIMITED` holder bumps its epoch: the leaves stay dead when it is narrowed again.
    function test_fixed_wholeThenLimitedRevivesLeaves() public {
        _manager(100);
        _leaf(50);
        _mint(OFFICER, 1); // positive control
        vm.prank(OWNER);
        t.grantRole(MINT, nid(MANAGER));
        _refused(OFFICER, 1, _ex(7));
        _manager(100);
        _refused(OFFICER, 1, _ex(7));
    }

    /// B-19, fixed (spec §1.4, G15): `init` and `transferAdmin` refuse `UA_POOL` and `SHIELD_POOL` as owner.
    function test_fixed_aPoolCanBeOwner() public {
        bytes memory cfg = abi.encode(_config(0, MetaTxLib.UA_POOL));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.AdminAccountPool.selector, MetaTxLib.UA_POOL));
        f.createToken(IOpenFactory.TokenKind.NORMAL, 1, cfg, "p");
        cfg = abi.encode(_config(0, MetaTxLib.SHIELD_POOL));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.AdminAccountPool.selector, MetaTxLib.SHIELD_POOL));
        f.createToken(IOpenFactory.TokenKind.NORMAL, 1, cfg, "p");
        vm.startPrank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.AdminAccountPool.selector, MetaTxLib.UA_POOL));
        t.transferAdmin(nid(MetaTxLib.UA_POOL), EnvKit.codeUidOf(address(t)));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.AdminAccountPool.selector, MetaTxLib.SHIELD_POOL));
        t.transferAdmin(nid(MetaTxLib.SHIELD_POOL), EnvKit.codeUidOf(address(t)));
        t.transferAdmin(nid(OFFICER), EnvKit.codeUidOf(address(t))); // positive control
        vm.stopPrank();
        assertEq(t.pendingAdmin(), nid(OFFICER));
    }

    // ------------------------------------------------------------------ refuted (R-*)

    /// R-01: a leaf cannot reach its parent's budget by a re-grant: spent sits on the holder, across a revoke and another parent.
    function test_refuted_reGrantThroughAnotherParentRefreshes() public {
        _manager(100);
        _leaf(50);
        _mint(OFFICER, 50);
        vm.prank(MANAGER);
        t.revokeRole(MINT, nid(OFFICER));
        IGovernance.GrantTerms memory g = _open();
        (g.total, g.delegable) = (100, true);
        vm.prank(OWNER);
        t.setGrant(MINT, nid(OFFICER2), g);
        (g.total, g.delegable) = (50, false);
        vm.prank(OFFICER2);
        t.setGrant(MINT, nid(OFFICER), g);
        assertEq(t.grantOf(MINT, nid(OFFICER)).spentTotal, 50);
        _refused(OFFICER, 1, _ex(2));
    }

    /// R-01: a holder cannot widen itself: not by `setGrant` on itself, not through a leaf above its terms or one that delegates.
    function test_refuted_holderWidensItself() public {
        _manager(100);
        IGovernance.GrantTerms memory g = _open();
        g.total = 50;
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IAdmin.NotAdmin.selector, MANAGER));
        t.setGrant(MINT, nid(MANAGER), g); // inside its terms and still not its own leaf
        g.total = 101;
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantNotNarrower.selector, 2));
        t.setGrant(MINT, nid(OFFICER), g);
        (g.total, g.delegable) = (50, true);
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantNotNarrower.selector, 6));
        t.setGrant(MINT, nid(OFFICER), g);
        _leaf(50); // positive control
    }

    /// R-05: a lock has no path out: `disableFeature` refuses, and a renounced owner cannot call it anyway.
    function test_refuted_lockBypass() public {
        NormalToken l = _token("l", 1 << MINT, OWNER);
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.FeatureLocked.selector, MINT));
        l.disableFeature(MINT);
        vm.prank(OWNER);
        t.disableFeature(MINT); // positive control: unlocked
    }
}
