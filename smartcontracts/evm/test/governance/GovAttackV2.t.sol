// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";
import {OpenFactory} from "../../src/factory/OpenFactory.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {NormalToken} from "../../src/metatx/NormalToken.sol";
import {WrappedToken} from "../../src/metatx/WrappedToken.sol";
import {IWrappedToken} from "../../src/metatx/IWrappedToken.sol";
import {UAMetaTxBase} from "../../src/metatx/UAMetaTxBase.sol";
import {IMetaTx} from "../../src/metatx/IMetaTx.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {SCaaSDex} from "../../src/dex/SCaaSDex.sol";
import {ISCaaSDex} from "../../src/dex/ISCaaSDex.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {GovernanceBase, GovernanceUse} from "../../src/governance/GovernanceBase.sol";
import {GovernanceBits} from "../../src/governance/GovernanceBits.sol";
import {GovernanceLib} from "../../src/governance/GovernanceLib.sol";
import {MockERC20} from "../helpers/Mocks.sol";
import {Catalogue} from "../helpers/Catalogue.sol";

/// A third-party application on the base, v2 §1.6 shape: bit 128, the scope is a branch, the contract applies the predicate.
contract BranchApp is GovernanceBase {
    uint8 internal constant APPROVE = 128;
    mapping(bytes32 => uint256) public approved;

    constructor(address owner_) {
        GovernanceLib.Roles memory none;
        GovernanceLib.init(uint256(1) << APPROVE, 0, owner_, 0, address(0), none, uint256(1) << APPROVE, uint256(1) << APPROVE, 0);
    }

    function _guardIn() internal pure override returns (bool) { return false; }
    function _guardOut(bool) internal pure override {}
    function _caller() internal view override returns (address) { return msg.sender; }
    function _validBits() internal pure override returns (uint256) { return uint256(1) << APPROVE; }
    function _roleBits() internal pure override returns (uint256) { return uint256(1) << APPROVE; }
    function _contractOnlyBits() internal pure override returns (uint256) { return 0; }
    function _scalarBits() internal pure override returns (uint256) { return uint256(1) << APPROVE; }
    function _scopeBits() internal pure override returns (uint256) { return uint256(1) << APPROVE; }

    function approve(bytes32 branch, uint128 principal) external {
        require(GovernanceUse.use(APPROVE, msg.sender, principal) == branch, "branch");
        approved[branch] += principal;
    }
}

/// The smallest `GovernanceHolder` of permission-model-gaps.md §1.2-§1.3: one op, its direct entry, its named twin, on the real
/// `UAMetaTxBase`. A sketch for the attack round, not a design.
contract HolderSketch is UAMetaTxBase {
    error NotOperator(bytes32 subject);

    bytes32 internal constant MINT_TYPEHASH = keccak256(
        "HolderMint(address from,address target,address to,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"
    );

    bytes32 public operator;

    constructor(bytes32 uid) UAMetaTxBase("SCaaS Holder", uid, address(0), address(0), false) {}

    function setOperator(bytes32 next) external {
        require(operator == 0 || _subject() == operator, "operator");
        operator = next;
    }

    function mint(address target, address to, uint256 amount) external nonReentrant {
        if (_subject() != operator) revert NotOperator(_subject());
        NormalToken(target).mint(to, amount);
    }

    function mtxMint(MetaTxLib.Envelope calldata e, address target, address to, uint256 amount, bytes calldata sig)
        external nonReentrant returns (bytes memory)
    {
        return _named(MINT_TYPEHASH, this.mint.selector, e, abi.encode(target, to, amount), sig);
    }

    function _mtxRule(bytes4 sel) internal view override returns (MtxRule memory) {
        if (sel == this.mint.selector) return MtxRule(FEE_CLASS_ABSOLUTE, 0, 100);
        return super._mtxRule(sel);
    }
}

/// A target named in a signed op that calls the holder back while the holder runs.
contract EvilTarget {
    HolderSketch public holder;
    address public good;
    address public to;
    bytes4 public failure;

    constructor(HolderSketch h, address good_, address to_) {
        (holder, good, to) = (h, good_, to_);
    }

    function mint(address, uint256) external {
        try holder.mint(good, to, 1) {} catch (bytes memory e) { failure = bytes4(e); }
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
    function initialize(address, uint64, bytes calldata) external {}
    function underlyings() external pure returns (address[] memory) {}
    function features() external pure returns (uint256) { return 1; } // PAYABLE only: no bit 6, no bit 9
    function lockedFeatures() external pure returns (uint256) { return 1; }
    function owner() external pure returns (address) {}
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
        f = new OpenFactory(address(this), UID, 0);
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
        c.owner = owner_;
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
        t.setGrant(MINT, MANAGER, g);
    }

    function _leaf(uint128 total) internal {
        IGovernance.GrantTerms memory g = _open();
        g.total = total;
        vm.prank(MANAGER);
        t.setGrant(MINT, OFFICER, g);
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
        return SCaaSDex(f.createDex(1, abi.encode(ISCaaSDex.DexConfig(OWNER, 0, address(0xAA), false, 0, address(0))), salt));
    }

    // ------------------------------------------------------------------ delay (B-01, B-02)

    /// B-01, fixed (spec §1.6, CTR-GOV-04's Change): with a `grantDelay`, `setGrant` that makes a holder takes the owner's
    /// two calls, as `grantRole` does; the first proposes, the confirm in the window applies.
    function test_fixed_setGrantMakesAnUnboundedHolderInOneCall() public {
        IFactoryToken.TokenConfig memory c = _config(0, OWNER);
        c.grantDelay = 2 days;
        NormalToken d = NormalToken(f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), "d"));
        vm.prank(OWNER);
        d.setGrant(MINT, OFFICER, _open());
        assertFalse(d.hasRole(MINT, OFFICER));
        vm.prank(OFFICER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, MINT, OFFICER));
        d.mint(TO, 1);
        vm.warp(block.timestamp + 2 days);
        vm.prank(OWNER); // positive control: the confirm
        d.setGrant(MINT, OFFICER, _open());
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
        t.setGrant(MINT, MANAGER, g);
        g.maxUses = 5; // a use count is no budget on a scalar bit
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantBudgetRequired.selector, MINT));
        t.setGrant(MINT, MANAGER, g);
        SCaaSDex d = _dex("d");
        g.maxUses = 0;
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantBudgetRequired.selector, LISTING));
        d.setGrant(LISTING, MANAGER, g);
        g.maxUses = 2; // positive control on a scalarless bit
        vm.prank(OWNER);
        d.setGrant(LISTING, MANAGER, g);

        _manager(100); // positive control: a leaf with no owner call, spending the parent's 100 only
        _leaf(100);
        _mint(MANAGER, 50);
        _refused(OFFICER, 51, _ex(2));
        _mint(OFFICER, 50);
        assertEq(t.grantOf(MINT, MANAGER).spentTotal, 100);
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
        (ok,) = address(f).call(abi.encodeWithSelector(f.setKindEnabled.selector, uint8(8), true));
        assertTrue(ok);
        assertTrue(f.kindEnabled(IOpenFactory.TokenKind.NORMAL_REGULATED));
    }

    /// B-03, stated: a token of a second factory stays an outside leg to the first's `isToken`, whatever its bits.
    function test_stated_aSecondFactorysTokenIsOutsideToTheFirst() public {
        OpenFactory f2 = new OpenFactory(address(this), UID, 0);
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
        t.grantRole(MINT, OFFICER); // the owner takes the officer over: whole shape
        t.revokeRole(MINT, MANAGER); // and removes the manager
        vm.stopPrank();
        assertFalse(t.hasRole(MINT, MANAGER));
        assertEq(t.grantOf(MINT, OFFICER).grantor, address(0));

        vm.prank(OFFICER2); // a stranger is refused
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotOwner.selector, OFFICER2));
        t.revokeRole(MINT, OFFICER);
        vm.prank(MANAGER); // a holder of nothing, and the officer is no longer its leaf
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotOwner.selector, MANAGER));
        t.revokeRole(MINT, OFFICER);
        assertTrue(t.hasRole(MINT, OFFICER));

        _manager(100); // a revoked grantor and its own leaf: refused while it holds nothing
        vm.prank(MANAGER);
        t.setGrant(MINT, OFFICER2, _leafTerms(50));
        vm.prank(OWNER);
        t.revokeRole(MINT, MANAGER);
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotOwner.selector, MANAGER));
        t.revokeRole(MINT, OFFICER2);
        _manager(100); // positive control: a grantor that holds revokes its leaf
        vm.prank(MANAGER);
        t.revokeRole(MINT, OFFICER2);
        assertFalse(t.hasRole(MINT, OFFICER2));
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
        t.revokeRole(MINT, OFFICER);
        _refused(OFFICER, 1, abi.encodeWithSelector(IGovernance.MissingRole.selector, MINT, OFFICER));
        assertTrue(t.grantOf(MINT, OFFICER).barred);
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantBarred.selector, MINT, OFFICER));
        t.setGrant(MINT, OFFICER, _leafTerms(50));
        vm.prank(MANAGER); // positive control: another account is added
        t.setGrant(MINT, OFFICER2, _leafTerms(50));
        _mint(OFFICER2, 1);
    }

    // ------------------------------------------------------------------ the renounce rule (B-06, B-07, B-08)

    /// B-06, fixed (spec §1.7): `init` runs the renounce rule when `owner == 0`, so no token is born with an unlocked holder
    /// and no owner. A locked bit's holder survives, as at a renounce.
    function test_fixed_createdWithoutOwnerKeepsAnUnlockedMinter() public {
        IFactoryToken.TokenConfig memory c = _config(0, address(0));
        c.roles.minter = MANAGER;
        vm.expectRevert(abi.encodeWithSelector(IGovernance.OwnerHasHolders.selector, MINT));
        f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), "n");

        c.lockedFeatures = 1 << MINT; // positive control: the lock promises the power
        NormalToken n = NormalToken(f.createToken(IOpenFactory.TokenKind.NORMAL, 1, abi.encode(c), "n"));
        assertEq(n.owner(), address(0));
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
        vm.expectRevert(abi.encodeWithSelector(IGovernance.OwnerHasHolders.selector, MINT));
        t.renounceOwnership();
        vm.prank(OWNER);
        t.revokeRole(MINT, MANAGER);
        _refused(OFFICER, 1, _ex(7)); // dead
        assertTrue(t.hasRole(MINT, OFFICER)); // and reported as a holder
        assertEq(t.holderCount(MINT), 1);
        vm.prank(OWNER);
        t.renounceOwnership();
        assertEq(t.owner(), address(0));
    }

    /// B-08, fixed (spec §1.5): once the owner is 0 nothing above changes, the holder list included: a locked bit's delegable
    /// holder survives the renounce and adds nobody.
    function test_fixed_afterRenounceALockedBitsHolderAddsHolders() public {
        t = _token("l", 1 << MINT, OWNER);
        _manager(100);
        vm.prank(MANAGER); // positive control: with an owner, the leaf is added
        t.setGrant(MINT, OFFICER2, _leafTerms(10));
        vm.prank(OWNER);
        t.renounceOwnership();
        assertEq(t.owner(), address(0));
        assertEq(t.holderCount(MINT), 2);
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotOwner.selector, MANAGER));
        t.setGrant(MINT, OFFICER, _leafTerms(50));
        assertEq(t.holderCount(MINT), 2);
        _mint(MANAGER, 50); // the locked power itself survives
    }

    // ------------------------------------------------------------------ the grant record (B-09 to B-12)

    function _wordRefused(SCaaSDex d, uint8 bit, IGovernance.GrantTerms memory g, uint8 field) internal {
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantWordRefused.selector, bit, field));
        d.setGrant(bit, MANAGER, g);
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
        assertFalse(d.hasRole(LISTING, MANAGER));

        g = _open();
        g.maxUses = 1; // positive control: `maxUses` does bind (`GovGrant` shows it for `validUntil`)
        vm.prank(OWNER);
        d.setGrant(FEE_ROUTING, MANAGER, g);
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
        d.setGrant(LISTING, MANAGER, _open());
        vm.prank(MANAGER);
        d.setListedOnly(true);
    }

    /// B-10, fixed (spec §1.5): a `scope` on a power that does not read it is refused; a scoped power refuses scope 0.
    function test_fixed_aScopeOnABuiltPowerBindsNothing() public {
        IGovernance.GrantTerms memory g = _open();
        g.scope = bytes32(uint256(uint160(TO)));
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantWordRefused.selector, MINT, uint8(7)));
        t.setGrant(MINT, MANAGER, g);
        BranchApp a = new BranchApp(OWNER);
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantWordRefused.selector, uint8(128), uint8(7)));
        a.setGrant(128, MANAGER, _open());
        vm.prank(OWNER); // positive control: a scope where the power reads it
        a.setGrant(128, MANAGER, g);
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
        a.setGrant(128, MANAGER, g);
        IGovernance.GrantTerms memory l = _open();
        (l.scope, l.total) = (b7, 50);
        vm.prank(MANAGER);
        a.setGrant(128, OFFICER, l);
        vm.prank(OFFICER); // positive control: the leaf acts in branch 7 while its parent is there
        a.approve(b7, 2);

        g.scope = b8; // the owner moves the manager; the edit is not a revoke
        vm.prank(OWNER);
        a.setGrant(128, MANAGER, g);
        vm.prank(MANAGER); // positive control: the parent is out of branch 7
        vm.expectRevert(bytes("branch"));
        a.approve(b7, 1);
        vm.prank(OFFICER);
        vm.expectRevert(_ex(7));
        a.approve(b7, 5);
        assertEq(a.approved(b7), 2);
        assertEq(a.grantOf(128, MANAGER).spentTotal, 2);
    }

    /// B-11, fixed: the same for `delegable`: the owner ends the delegation, the leaves die.
    function test_fixed_endingDelegationLeavesTheLeaves() public {
        _manager(100);
        _leaf(50);
        _mint(OFFICER, 1); // positive control: alive under a delegating parent
        IGovernance.GrantTerms memory g = _open();
        g.total = 100;
        vm.prank(OWNER);
        t.setGrant(MINT, MANAGER, g);
        assertFalse(t.grantOf(MINT, MANAGER).delegable);
        _refused(OFFICER, 1, _ex(7));
    }

    /// B-12, fixed (spec §1.5): changing `window` while the spent period still runs on the new grid is refused.
    function test_fixed_changingTheWindowRefreshesTheBudget() public {
        IGovernance.GrantTerms memory g = _open();
        (g.perWindow, g.window) = (50, 1 days);
        vm.startPrank(OWNER);
        t.setGrant(MINT, MANAGER, g);
        vm.stopPrank();
        _mint(MANAGER, 50);
        _refused(MANAGER, 1, _ex(3)); // positive control: exhausted
        vm.prank(OWNER);
        t.setGrant(MINT, MANAGER, g); // the same terms: carried, as `GovGrant` pins
        _refused(MANAGER, 1, _ex(3));
        g.window = 1 days + 1; // one second longer, narrower by any reading
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantWindowInUse.selector, MINT, MANAGER));
        t.setGrant(MINT, MANAGER, g);
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
        d.transferOwnership(next);
        vm.prank(next);
        d.acceptOwnership();
        assertEq(d.owner(), next);
        vm.prank(next);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.MissingRole.selector, FEE_ROUTING, next));
        d.setFeeSplit(0, next);
        vm.prank(OWNER);
        d.setFeeSplit(0, evil);
        assertEq(d.treasury(), evil);
    }

    // ------------------------------------------------------------------ the holder sketch (B-14, refuted R-*)

    function _holder(address operator_) internal returns (HolderSketch h) {
        h = HolderSketch(payable(Clones.clone(address(new HolderSketch(UID)))));
        h.setOperator(MetaTxLib.pad(operator_));
    }

    function _meta(address from, bytes memory data, uint256 nonce) internal view returns (MetaTxLib.MetaTransaction memory m) {
        m = MetaTxLib.MetaTransaction(from, data, 0, nonce, block.timestamp + 1 hours, 0, address(0), 0, address(0));
    }

    function _env(address from, uint256 nonce) internal view returns (MetaTxLib.Envelope memory) {
        return MetaTxLib.Envelope(from, 0, nonce, block.timestamp + 1 hours, 0, address(0), 0, address(0));
    }

    function _domain(HolderSketch h) internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address verifying, bytes32 salt,) = h.eip712Domain();
        return keccak256(abi.encode(
            keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifying, salt));
    }

    function _namedSig(HolderSketch h, uint256 pk, MetaTxLib.Envelope memory e, address target, address to, uint256 v)
        internal view returns (bytes memory)
    {
        bytes32 structHash = keccak256(bytes.concat(
            abi.encode(
                keccak256("HolderMint(address from,address target,address to,uint256 amount,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)"),
                MetaTxLib.pad(e.from), target, to, v),
            abi.encode(e.batch, e.nonce, e.validUntil, e.mode, address(0), e.fee, address(0))));
        (uint8 r, bytes32 a, bytes32 b) = vm.sign(pk, keccak256(abi.encodePacked("\x19\x01", _domain(h), structHash)));
        return abi.encodePacked(a, b, r);
    }

    function _signMeta(HolderSketch h, uint256 pk, MetaTxLib.MetaTransaction memory m) internal view returns (bytes memory) {
        (uint8 r, bytes32 a, bytes32 b) = vm.sign(pk, h.mtxDigest(m));
        return abi.encodePacked(a, b, r);
    }

    /// B-14: a named entry passes `_checkCall`, so its op must be on `_mtxRule`, so the generic `mtxExecute` reaches the same op
    /// under a `bytes data` signature: the path §2 of the gaps note refuses for "the most dangerous signature an owner makes".
    function test_attack_theHoldersOpIsReachableAsABytesBlob() public {
        (address op, uint256 pk) = makeAddrAndKey("operator");
        HolderSketch h = _holder(op);
        vm.prank(OWNER);
        t.grantRole(MINT, address(h));

        MetaTxLib.Envelope memory e = _env(op, 0); // positive control: the named path
        h.mtxMint(e, address(t), TO, 1, _namedSig(h, pk, e, address(t), TO, 1));
        assertEq(t.balanceOf(TO), 1);

        MetaTxLib.MetaTransaction memory m = _meta(op, abi.encodeCall(HolderSketch.mint, (address(t), TO, 2)), 1);
        h.mtxExecute(m, _signMeta(h, pk, m)); // no named field in what the wallet signed
        assertEq(t.balanceOf(TO), 3);
    }

    /// R-02: the same signature on a second clone of the same operator fails: `verifyingContract` is the clone.
    function test_refuted_replayAcrossHolders() public {
        (address op, uint256 pk) = makeAddrAndKey("operator");
        (HolderSketch h1, HolderSketch h2) = (_holder(op), _holder(op));
        vm.startPrank(OWNER);
        t.grantRole(MINT, address(h1));
        t.grantRole(MINT, address(h2));
        vm.stopPrank();
        MetaTxLib.Envelope memory e = _env(op, 0);
        bytes memory sig = _namedSig(h1, pk, e, address(t), TO, 1);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        h2.mtxMint(e, address(t), TO, 1, sig);
        h1.mtxMint(e, address(t), TO, 1, sig); // positive control
        vm.expectRevert(abi.encodeWithSelector(IMetaTx.MetaTxBadNonce.selector, 1, 0));
        h1.mtxMint(e, address(t), TO, 1, sig); // and once only
    }

    /// R-02: `target` is signed: a relayer cannot move a signed op to another token.
    function test_refuted_relayerAltersTheTarget() public {
        (address op, uint256 pk) = makeAddrAndKey("operator");
        HolderSketch h = _holder(op);
        NormalToken other = _token("o", 0, OWNER);
        vm.startPrank(OWNER);
        t.grantRole(MINT, address(h));
        other.grantRole(MINT, address(h));
        vm.stopPrank();
        MetaTxLib.Envelope memory e = _env(op, 0);
        bytes memory sig = _namedSig(h, pk, e, address(t), TO, 1);
        vm.expectRevert(IMetaTx.MetaTxBadSignature.selector);
        h.mtxMint(e, address(other), TO, 1, sig);
        h.mtxMint(e, address(t), TO, 1, sig); // positive control
    }

    /// R-03: an envelope of the replaced operator dies with the rotation, and a stranger's fails the operator check.
    function test_refuted_replacedOperatorsEnvelope() public {
        (address op, uint256 pk) = makeAddrAndKey("operator");
        (address stranger, uint256 spk) = makeAddrAndKey("stranger");
        HolderSketch h = _holder(op);
        vm.prank(OWNER);
        t.grantRole(MINT, address(h));

        MetaTxLib.Envelope memory s = _env(stranger, 0);
        bytes memory bad = _namedSig(h, spk, s, address(t), TO, 1);
        vm.expectRevert(abi.encodeWithSelector(HolderSketch.NotOperator.selector, MetaTxLib.pad(stranger)));
        h.mtxMint(s, address(t), TO, 1, bad);

        MetaTxLib.Envelope memory e = _env(op, 0);
        bytes memory sig = _namedSig(h, pk, e, address(t), TO, 1);
        vm.prank(op);
        h.setOperator(MetaTxLib.pad(OWNER));
        vm.expectRevert(abi.encodeWithSelector(HolderSketch.NotOperator.selector, MetaTxLib.pad(op)));
        h.mtxMint(e, address(t), TO, 1, sig);
    }

    /// R-04: a malicious `target` cannot re-enter the holder, direct or under a ticket. The one guard of `MetaTxBase` holds.
    function test_refuted_targetReentersTheHolder() public {
        (address op, uint256 pk) = makeAddrAndKey("operator");
        HolderSketch h = _holder(op);
        vm.prank(OWNER);
        t.grantRole(MINT, address(h));
        EvilTarget evil = new EvilTarget(h, address(t), address(0xBAD));

        vm.prank(op);
        h.mint(address(evil), TO, 1);
        assertEq(evil.failure(), IMetaTx.Reentrancy.selector);
        assertEq(t.balanceOf(address(0xBAD)), 0);

        MetaTxLib.Envelope memory e = _env(op, 0);
        h.mtxMint(e, address(evil), TO, 1, _namedSig(h, pk, e, address(evil), TO, 1));
        assertEq(evil.failure(), IMetaTx.Reentrancy.selector);
        assertEq(t.balanceOf(address(0xBAD)), 0);
    }

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
        c.roles.rateAdmin = admin;
        c.rate = IFactoryToken.RateConfig(2 days, 1000);
        c.legs = new IFactoryToken.Leg[](1);
        c.legs[0] = IFactoryToken.Leg(address(usd), 1, 1);
        WrappedToken w = WrappedToken(payable(f.createToken(IOpenFactory.TokenKind.WRAPPED, 1, abi.encode(c), "w")));
        vm.prank(admin);
        w.proposeRate(address(usd), 101, 100);
        vm.prank(OWNER);
        w.revokeRole(GovernanceBits.RATE_ADJUSTABLE, admin);
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
        t.setGrant(MINT, MANAGER, g);
        IGovernance.GrantTerms memory l = _open();
        (l.total, l.perWindow, l.window) = (1000, 100, 1);
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantNotNarrower.selector, uint8(8)));
        t.setGrant(MINT, OFFICER, l); // 8,640,000 a day against the parent's 100
        l.window = 1 days + 1;
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantNotNarrower.selector, uint8(8)));
        t.setGrant(MINT, OFFICER, l);
        l.window = 1 days; // positive control: the parent's window
        vm.prank(MANAGER);
        t.setGrant(MINT, OFFICER, l);
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
        t.setGrant(MINT, MANAGER, g);
        IGovernance.GrantTerms memory l = _open();
        l.total = 1;
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantNotNarrower.selector, uint8(2)));
        t.setGrant(MINT, OFFICER, l);
        (g.total, g.delegable) = (61, true); // positive control: one unit left, one unit granted
        vm.prank(OWNER);
        t.setGrant(MINT, MANAGER, g);
        vm.prank(MANAGER);
        t.setGrant(MINT, OFFICER, l);
    }

    /// B-18, fixed (spec §1.5): `_grant` over a `LIMITED` holder bumps its epoch: the leaves stay dead when it is narrowed again.
    function test_fixed_wholeThenLimitedRevivesLeaves() public {
        _manager(100);
        _leaf(50);
        _mint(OFFICER, 1); // positive control
        vm.prank(OWNER);
        t.grantRole(MINT, MANAGER);
        _refused(OFFICER, 1, _ex(7));
        _manager(100);
        _refused(OFFICER, 1, _ex(7));
    }

    /// B-19, fixed (spec §1.4, G15): `init` and `transferOwnership` refuse `UA_POOL` and `SHIELD_POOL` as owner.
    function test_fixed_aPoolCanBeOwner() public {
        bytes memory cfg = abi.encode(_config(0, MetaTxLib.UA_POOL));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.OwnerAccountPool.selector, MetaTxLib.UA_POOL));
        f.createToken(IOpenFactory.TokenKind.NORMAL, 1, cfg, "p");
        cfg = abi.encode(_config(0, MetaTxLib.SHIELD_POOL));
        vm.expectRevert(abi.encodeWithSelector(IGovernance.OwnerAccountPool.selector, MetaTxLib.SHIELD_POOL));
        f.createToken(IOpenFactory.TokenKind.NORMAL, 1, cfg, "p");
        vm.startPrank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.OwnerAccountPool.selector, MetaTxLib.UA_POOL));
        t.transferOwnership(MetaTxLib.UA_POOL);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.OwnerAccountPool.selector, MetaTxLib.SHIELD_POOL));
        t.transferOwnership(MetaTxLib.SHIELD_POOL);
        t.transferOwnership(OFFICER); // positive control
        vm.stopPrank();
        assertEq(t.pendingOwner(), OFFICER);
    }

    // ------------------------------------------------------------------ refuted (R-*)

    /// R-01: a leaf cannot reach its parent's budget by a re-grant: spent sits on the holder, across a revoke and another parent.
    function test_refuted_reGrantThroughAnotherParentRefreshes() public {
        _manager(100);
        _leaf(50);
        _mint(OFFICER, 50);
        vm.prank(MANAGER);
        t.revokeRole(MINT, OFFICER);
        IGovernance.GrantTerms memory g = _open();
        (g.total, g.delegable) = (100, true);
        vm.prank(OWNER);
        t.setGrant(MINT, OFFICER2, g);
        (g.total, g.delegable) = (50, false);
        vm.prank(OFFICER2);
        t.setGrant(MINT, OFFICER, g);
        assertEq(t.grantOf(MINT, OFFICER).spentTotal, 50);
        _refused(OFFICER, 1, _ex(2));
    }

    /// R-01: a holder cannot widen itself: not by `setGrant` on itself, not through a leaf above its terms or one that delegates.
    function test_refuted_holderWidensItself() public {
        _manager(100);
        IGovernance.GrantTerms memory g = _open();
        g.total = 50;
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.NotOwner.selector, MANAGER));
        t.setGrant(MINT, MANAGER, g); // inside its terms and still not its own leaf
        g.total = 101;
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantNotNarrower.selector, 2));
        t.setGrant(MINT, OFFICER, g);
        (g.total, g.delegable) = (50, true);
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantNotNarrower.selector, 6));
        t.setGrant(MINT, OFFICER, g);
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
