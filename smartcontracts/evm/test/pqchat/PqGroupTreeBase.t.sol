// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {PqGroupTree} from "../../src/pqgroup/PqGroupTree.sol";
import {IPqGroupTree} from "../../src/pqgroup/IPqGroupTree.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";

/// The registry's two views the base reads: every UA's key version 0 is one admitted scheme-1 key (`ek` all zero, `pk_X`
/// 9), every UA registered.
contract KemStub {
    function kemKeyAt(bytes32, uint64) external pure returns (IUARegistry.KemKey memory k, bytes memory sig) {
        (k.scheme, k.mlkemEk, k.x25519) = (1, new bytes(1568), bytes32(uint256(9) << 248));
        sig = "";
    }

    function isRegistered(bytes32) external pure returns (bool) {
        return true;
    }
}

/// `PqGroupTree` alone, under bounds above the base's own (1,024 leaf positions): a group `GID` of `used` positions with leaf
/// 0 set, and the base's commit check.
contract TreeHarness is PqGroupTree {
    bytes32 internal constant GID = keccak256("harness group");

    error Fail(uint8 code, uint256 a, uint256 b);

    function _treeSlot() internal pure override returns (bytes32) {
        return keccak256("harness.tree");
    }

    function _treeTypehashes() internal pure override returns (bytes32, bytes32) {
        return (keccak256("HarnessLeaf"), keccak256("HarnessParent"));
    }

    function _treeBounds() internal pure override returns (uint256, uint256, uint256, uint256) {
        return (1024, 32, 32, 8);
    }

    function _treeListedNew(bytes32, bytes32) internal override {}

    function _treeFail(uint8 code, uint256 a, uint256 b) internal pure override {
        revert Fail(code, a, b);
    }

    function open(IUARegistry reg, uint256 used, bytes32 ua, bytes32[] calldata admins) external {
        _treeOpen(GID, keccak256("tree"), used, admins, 0);
        _treeSetLeaf(reg, GID, 0, ua, 0, 0, 0);
    }

    function hashOf(IUARegistry reg) external view returns (bytes32) {
        return _treeHash(reg, _tree(GID));
    }

    function check(IUARegistry reg, Delta memory d) external view returns (bytes32) {
        return _treeCheck(reg, GID, d, false).root;
    }
}

/// The base layer's own rules (review A-6, F-5), apart from PqChat: at most 512 leaf positions whatever the inheritor's
/// bounds (owner R8 2026-11-25, was 256: a group of 513 refused at opening, an Add at position 512 refused), and a one-leaf tree's commit root is its
/// leaf's `th`, as `_treeHash` gives it (was 0). Each with its positive control. **UNAUDITED.**
contract PqGroupTreeBaseTest is Test {
    bytes32 constant U = bytes32(uint256(0xA11CE));
    TreeHarness h;
    IUARegistry reg;
    bytes32[] admins;

    function setUp() public {
        h = new TreeHarness();
        reg = IUARegistry(address(new KemStub()));
        admins.push(U);
    }

    /// A commit of `U` from leaf 0 that changes nothing but the signed `treeHash`, on a tree of `leaves`.
    function _plain(uint32 leaves, bytes32 treeHash) internal view returns (PqGroupTree.Delta memory d) {
        (d.author, d.leaf, d.keyId, d.leaves, d.epoch, d.admins, d.treeHash) = (U, 0, 0, leaves, 1, admins, treeHash);
    }

    function _fail(uint8 code, uint256 a, uint256 b) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(TreeHarness.Fail.selector, code, a, b);
    }

    /// F-5: one leaf, no growth: the honest root (the leaf's `th`) is accepted and a signed 0 is `T_HASH`.
    function test_f5_oneLeafRootIsTheLeafHash() public {
        h.open(reg, 1, U, admins);
        bytes32 root = h.hashOf(reg);
        assertTrue(root != bytes32(0), "a live leaf's th");
        assertEq(h.check(reg, _plain(1, root)), root, "the walk's root");
        vm.expectRevert(_fail(10, uint256(root), 0)); // T_HASH(computed): the walk's root is the leaf's th, not the signed 0
        h.check(reg, _plain(1, bytes32(0)));
    }

    /// A-6: `_treeOpen` refuses 513 positions under an inheritor bound of 1,024; 512 opens (the control).
    function test_a6_openAbove512Refused() public {
        vm.expectRevert(_fail(0, 0, 0)); // T_SHAPE
        h.open(reg, 513, U, admins);
        h.open(reg, 512, U, admins);
    }

    /// A-6: an Add at position 512 of a tree of 512 is `T_LEAF(512)` under an inheritor bound of 1,024; the same commit
    /// without it is accepted (the control).
    function test_a6_addAtPosition512Refused() public {
        h.open(reg, 512, U, admins);
        PqGroupTree.Delta memory d = _plain(512, h.hashOf(reg));
        assertEq(h.check(reg, d), d.treeHash, "control: no Add");
        d.adds = new IPqGroupTree.TreeAdd[](1);
        d.adds[0] = IPqGroupTree.TreeAdd(512, bytes32(uint256(0xB0B)), 0, bytes32(0), bytes32(0));
        vm.expectRevert(_fail(3, 512, 0)); // T_LEAF
        h.check(reg, d);
    }
}
