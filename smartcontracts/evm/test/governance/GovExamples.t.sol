// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IGovernance} from "../../src/governance/IGovernance.sol";
import {GovernanceBase, GovernanceUse} from "../../src/governance/GovernanceBase.sol";
import {GovernanceLib} from "../../src/governance/GovernanceLib.sol";
import {nid} from "../helpers/Ids.sol";

/// The part every example shares: an application on the base with a `grantDelay`, no guard of its own, the caller as is.
abstract contract ExampleApp is GovernanceBase {
    constructor() GovernanceBase(address(0)) {}

    function _initApp(address owner_, uint64 delay, uint256 bits) internal {
        GovernanceLib.Roles memory none;
        GovernanceLib.init(bits, 0, nid(owner_), delay, address(0), none, bits, bits, 0, address(0));
    }

    function _guardIn() internal pure override returns (bool) { return false; }
    function _guardOut(bool) internal pure override {}
    function _caller() internal view override returns (address) { return msg.sender; }
    function _contractOnlyBits() internal pure override returns (uint256) { return 0; }
}

/// Spec §1.9, first example: a loan approval bounded on a named argument. Bit 128, scalar and scoped: `approveLoan` passes the
/// principal it pays and compares the returned scope with the loan's branch.
contract LoanBook is ExampleApp {
    uint8 internal constant APPROVE_LOAN = 128;
    uint256 internal constant BITS = uint256(1) << APPROVE_LOAN;

    error WrongBranch(bytes32 scope, bytes32 branch);

    struct Loan { uint128 principal; bytes32 branch; bool approved; }
    mapping(uint256 => Loan) public loans;

    constructor(address committee, uint64 delay) { _initApp(committee, delay, BITS); }

    function _validBits() internal pure override returns (uint256) { return BITS; }
    function _roleBits() internal pure override returns (uint256) { return BITS; }
    function _scalarBits() internal pure override returns (uint256) { return BITS; }
    function _scopeBits() internal pure override returns (uint256) { return BITS; }

    function bitLabel(uint8 bit) external pure override returns (BitType, bytes4, string memory) {
        if (bit != APPROVE_LOAN) revert FeatureInvalidForKind(bit);
        return (BitType.POWER, this.approveLoan.selector, "approve a loan");
    }

    function addLoan(uint256 id, uint128 principal, bytes32 branch) external {
        loans[id] = Loan(principal, branch, false);
    }

    function approveLoan(uint256 loanId) external {
        Loan storage l = loans[loanId];
        require(!l.approved && l.principal != 0, "loan");
        bytes32 scope = GovernanceUse.use(APPROVE_LOAN, _govSubject(), l.principal);
        if (scope != 0 && scope != l.branch) revert WrongBranch(scope, l.branch);
        l.approved = true;
    }
}

/// Spec §1.9, second example: adding or removing members only in one's own subtree. Bits 128 and 129, scoped, no scalar:
/// the scope is a member id, and a scope narrows to any of its descendants.
contract FamilyTree is ExampleApp {
    uint8 internal constant ADD_MEMBER = 128;
    uint8 internal constant REMOVE_MEMBER = 129;
    uint256 internal constant BITS = (uint256(1) << ADD_MEMBER) | (uint256(1) << REMOVE_MEMBER);
    uint256 internal constant MAX_DEPTH = 32;

    error OutsideSubtree(bytes32 scope, uint256 id);

    mapping(uint256 id => uint256 parent) public parentOf; // the root is 1, its own parent
    mapping(uint256 id => bool) public removed;

    constructor(address clan, uint64 delay) {
        _initApp(clan, delay, BITS);
        parentOf[1] = 1;
    }

    function _validBits() internal pure override returns (uint256) { return BITS; }
    function _roleBits() internal pure override returns (uint256) { return BITS; }
    function _scalarBits() internal pure override returns (uint256) { return 0; }
    function _scopeBits() internal pure override returns (uint256) { return BITS; }

    /// `id` is `head` or below it, within `MAX_DEPTH` steps.
    function isDescendant(uint256 head, uint256 id) public view returns (bool) {
        for (uint256 i; i <= MAX_DEPTH; ++i) {
            if (id == head) return true;
            uint256 p = parentOf[id];
            if (p == 0 || p == id) return false;
            id = p;
        }
        return false;
    }

    function _scopeNarrows(uint8, bytes32 parent, bytes32 child) internal view override returns (bool) {
        return isDescendant(uint256(parent), uint256(child));
    }

    function _inScope(uint8 bit, uint256 id) private {
        bytes32 scope = GovernanceUse.use(bit, _govSubject(), 0);
        if (scope != 0 && !isDescendant(uint256(scope), id)) revert OutsideSubtree(scope, id);
    }

    function addMember(uint256 parent, uint256 id) external {
        _inScope(ADD_MEMBER, parent);
        require(parentOf[parent] != 0 && parentOf[id] == 0, "member");
        parentOf[id] = parent;
    }

    /// A tombstone that references the record.
    function removeMember(uint256 id) external {
        _inScope(REMOVE_MEMBER, id);
        removed[id] = true;
    }
}

/// Spec §1.9, third example, form (i): circulation only within a group, custody. Bit 128, scalar and scoped: `moveWithin`
/// passes the amount, the scope is the group, both ends must be members of it. Balances are this ledger's.
contract GroupLedger is ExampleApp {
    uint8 internal constant MOVE_WITHIN = 128;
    uint256 internal constant BITS = uint256(1) << MOVE_WITHIN;

    error OutsideGroup(bytes32 group, uint64 member);

    mapping(uint64 member => bytes32) public groupOf;
    mapping(uint64 member => uint256) public balanceOf;

    constructor(address owner_, uint64 delay) { _initApp(owner_, delay, BITS); }

    function _validBits() internal pure override returns (uint256) { return BITS; }
    function _roleBits() internal pure override returns (uint256) { return BITS; }
    function _scalarBits() internal pure override returns (uint256) { return BITS; }
    function _scopeBits() internal pure override returns (uint256) { return BITS; }

    function join(uint64 member, bytes32 group, uint256 balance) external {
        (groupOf[member], balanceOf[member]) = (group, balance);
    }

    function moveWithin(uint64 from, uint64 to, uint256 amount) external {
        bytes32 g = GovernanceUse.use(MOVE_WITHIN, _govSubject(), amount);
        if (g != 0) {
            if (groupOf[from] != g) revert OutsideGroup(g, from);
            if (groupOf[to] != g) revert OutsideGroup(g, to);
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}

/// @notice The three examples of CTR-GOV-10 on the final rules (spec §1.9): each owner grants in two calls, each delegable
///         holder at once, and the leaf debits its parent on the same scalar.
contract GovExamplesTest is Test {
    address constant OWNER = address(0x0A);
    address constant MANAGER = address(0x0B);
    address constant OFFICER = address(0x0C);
    uint64 constant D = 2 days;
    bytes32 constant BRANCH = bytes32(uint256(0xB1));

    function setUp() public {
        vm.warp(1_800_000_000);
    }

    function _twice(IGovernance app, uint8 bit, address holder, IGovernance.GrantTerms memory g) internal {
        vm.prank(OWNER);
        app.setGrant(bit, nid(holder), g);
        assertFalse(app.hasRole(bit, nid(holder)), "proposed");
        vm.warp(block.timestamp + D);
        vm.prank(OWNER);
        app.setGrant(bit, nid(holder), g);
        assertTrue(app.hasRole(bit, nid(holder)), "confirmed");
    }

    function _ex(uint8 field) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(IGovernance.GrantExhausted.selector, field);
    }

    // ------------------------------------------------------------------ LoanBook

    function _book() internal returns (LoanBook b) {
        b = new LoanBook(OWNER, D);
        IGovernance.GrantTerms memory g;
        (g.min, g.max, g.total, g.validUntil, g.scope, g.delegable) =
            (1e6, 1e8, 5e8, uint64(block.timestamp + 365 days), BRANCH, true);
        _twice(b, 128, MANAGER, g);
        b.addLoan(1, 5e5, BRANCH);
        b.addLoan(2, 2e8, BRANCH);
        b.addLoan(3, 5e6, BRANCH);
        b.addLoan(4, 5e6, bytes32(uint256(0xB2)));
        b.addLoan(5, 1e7, BRANCH);
        b.addLoan(6, 3e7, BRANCH);
    }

    function test_loanApprovalInABand() public {
        LoanBook b = _book();
        (, bytes4 sel, string memory name) = b.bitLabel(128);
        assertEq(sel, LoanBook.approveLoan.selector);
        assertEq(name, "approve a loan");
        vm.startPrank(MANAGER);
        vm.expectRevert(_ex(0));
        b.approveLoan(1);
        vm.expectRevert(_ex(1));
        b.approveLoan(2);
        vm.expectRevert(abi.encodeWithSelector(LoanBook.WrongBranch.selector, BRANCH, bytes32(uint256(0xB2))));
        b.approveLoan(4);
        b.approveLoan(3);
        vm.stopPrank();
        assertEq(b.grantOf(128, nid(MANAGER)).spentTotal, 5e6);
    }

    function test_loanLeafDebitsItsManager() public {
        LoanBook b = _book();
        IGovernance.GrantTerms memory l;
        (l.min, l.max, l.total, l.validUntil, l.scope) = (1e6, 2e7, 1e8, uint64(block.timestamp + 30 days), BRANCH);
        vm.prank(MANAGER); // at once: the leaf path takes no delay
        b.setGrant(128, nid(OFFICER), l);
        vm.startPrank(OFFICER);
        b.approveLoan(5);
        vm.expectRevert(_ex(1));
        b.approveLoan(6);
        vm.stopPrank();
        assertEq(b.grantOf(128, nid(OFFICER)).spentTotal, 1e7);
        assertEq(b.grantOf(128, nid(MANAGER)).spentTotal, 1e7, "the manager is debited on the same principal");
    }

    // ------------------------------------------------------------------ FamilyTree

    /// 1 ── 2 (head) ── 3 (son) ── 5
    ///  └── 4
    function _tree() internal returns (FamilyTree tr) {
        tr = new FamilyTree(OWNER, D);
        vm.prank(OWNER);
        tr.grantRole(128, nid(OWNER));
        vm.warp(block.timestamp + D);
        vm.startPrank(OWNER);
        tr.grantRole(128, nid(OWNER));
        tr.addMember(1, 2);
        tr.addMember(2, 3);
        tr.addMember(1, 4);
        vm.stopPrank();
        IGovernance.GrantTerms memory g;
        (g.max, g.maxUses, g.delegable, g.scope) = (type(uint128).max, 3, true, bytes32(uint256(2)));
        _twice(tr, 128, MANAGER, g);
        _twice(tr, 129, MANAGER, g);
    }

    function _leafOn(FamilyTree tr, uint8 bit, uint256 son, uint32 uses) internal {
        IGovernance.GrantTerms memory l;
        (l.max, l.maxUses, l.scope) = (type(uint128).max, uses, bytes32(son));
        vm.prank(MANAGER);
        tr.setGrant(bit, nid(OFFICER), l);
    }

    function test_subtreeAddAndRemove() public {
        FamilyTree tr = _tree();
        _leafOn(tr, 128, 3, 2);
        _leafOn(tr, 129, 3, 1);
        vm.prank(OFFICER);
        tr.addMember(3, 5);
        assertEq(tr.parentOf(5), 3);
        vm.prank(MANAGER);
        tr.addMember(2, 6);
        assertEq(tr.grantOf(128, nid(MANAGER)).uses, 2, "every add in the subtree debits the head");
        vm.prank(OFFICER);
        tr.addMember(5, 7);
        vm.prank(OFFICER); // the head's 3 adds are spent
        vm.expectRevert(_ex(5));
        tr.addMember(5, 8);
        vm.prank(OFFICER);
        tr.removeMember(5);
        assertTrue(tr.removed(5));
    }

    function test_subtreeOutsideTheScopeRefused() public {
        FamilyTree tr = _tree();
        IGovernance.GrantTerms memory l;
        (l.max, l.maxUses, l.scope) = (type(uint128).max, 1, bytes32(uint256(4)));
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantNotNarrower.selector, uint8(7)));
        tr.setGrant(128, nid(OFFICER), l); // 4 is outside the head's subtree
        _leafOn(tr, 128, 3, 1);
        vm.prank(OFFICER);
        vm.expectRevert(abi.encodeWithSelector(FamilyTree.OutsideSubtree.selector, bytes32(uint256(3)), uint256(2)));
        tr.addMember(2, 9); // the son's scope is 3, not its parent 2
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(FamilyTree.OutsideSubtree.selector, bytes32(uint256(2)), uint256(4)));
        tr.addMember(4, 9);
    }

    /// B-02: `{scope = headId, delegable}` without `maxUses` is refused; with it, the clan's grant runs.
    function test_subtreeHeadWithNoBudgetRefused() public {
        FamilyTree tr = new FamilyTree(OWNER, D);
        IGovernance.GrantTerms memory g;
        (g.max, g.delegable, g.scope) = (type(uint128).max, true, bytes32(uint256(1)));
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantBudgetRequired.selector, uint8(128)));
        tr.setGrant(128, nid(MANAGER), g);
        g.maxUses = 10;
        _twice(tr, 128, MANAGER, g);
    }

    // ------------------------------------------------------------------ GroupLedger

    bytes32 constant GA = bytes32(uint256(0xA));
    bytes32 constant GB = bytes32(uint256(0xB));

    function _ledger() internal returns (GroupLedger gl) {
        gl = new GroupLedger(OWNER, D);
        gl.join(1, GA, 1000);
        gl.join(2, GA, 0);
        gl.join(3, GB, 0);
        IGovernance.GrantTerms memory g;
        (g.max, g.total, g.scope, g.delegable) = (type(uint128).max, 500, GA, true);
        _twice(gl, 128, MANAGER, g);
    }

    function test_moveWithinAGroup() public {
        GroupLedger gl = _ledger();
        vm.prank(MANAGER);
        gl.moveWithin(1, 2, 100);
        assertEq(gl.balanceOf(2), 100);
        IGovernance.GrantTerms memory l;
        (l.max, l.total, l.scope) = (type(uint128).max, 50, GA);
        vm.prank(MANAGER);
        gl.setGrant(128, nid(OFFICER), l);
        vm.prank(OFFICER);
        gl.moveWithin(2, 1, 50);
        assertEq(gl.grantOf(128, nid(MANAGER)).spentTotal, 150);
    }

    function test_moveOutOfTheGroupRefused() public {
        GroupLedger gl = _ledger();
        vm.prank(MANAGER);
        vm.expectRevert(abi.encodeWithSelector(GroupLedger.OutsideGroup.selector, GA, uint64(3)));
        gl.moveWithin(1, 3, 1);
        IGovernance.GrantTerms memory g; // a delegable holder needs a `total`
        (g.max, g.scope, g.delegable) = (type(uint128).max, GA, true);
        vm.prank(OWNER);
        vm.expectRevert(abi.encodeWithSelector(IGovernance.GrantBudgetRequired.selector, uint8(128)));
        gl.setGrant(128, nid(OFFICER), g);
    }
}
