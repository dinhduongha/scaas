// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IPqChat} from "./IPqChat.sol";

/// @title The tree views of `PqChat`'s TreeKEM mode (spec 2026-11-23-pqchat-treekem §6, CTR-CHAT-27).
/// @notice Served by the read-only body module `PqChatTreeViews` (owner 2026-11-24): `PqChat` sends every selector it does not
///         have to it by `DELEGATECALL`, so a client calls them on the instance (`IPqChatTreeViews(instance)`); the instance
///         reports this interface id beside `IPqChat`'s in `supportsInterface`. Every view reads state only. A page caps its
///         count at `TREE_RANGE_MAX`, `treeLeaves` at `TREE_LEAF_PAGE_MAX` (C36); a page past the end is empty, never a
///         revert. A session that is flat: `PqChatModeEntry(0)`; none: `PqChatUnknown`. **UNAUDITED.**
interface IPqChatTreeViews {
    /// @notice A leaf of the live tree; a blank leaf is all zero. `kemHash` is read from the registry at the call.
    struct TreeLeafView {
        bytes32 ua;
        uint64 keyId;
        uint64 joinEpoch;
        uint32 wrapIndex;
        bytes32 kemHash;
    }

    /// @notice A node of the live tree by its index: a parent's `th`, the hash of its live key (0 blank) and the number of the
    ///         commit that set it; a leaf's (an even index) `th`, its `kemHash` and its `joinEpoch`.
    struct TreeNodeView {
        bytes32 hash;
        bytes32 keyHash;
        uint64 epoch;
    }

    /// @notice 256: the most entries a page view returns.
    function TREE_RANGE_MAX() external view returns (uint256);
    /// @notice 64 (C36): the most leaves one `treeLeaves` call returns.
    function TREE_LEAF_PAGE_MAX() external view returns (uint256);

    /// @notice The live tree; `owed`: the leaves owed to removals at the head (C21); `sincePath`: the leaves path-less commits
    ///         added since the last path commit (the path-less delta §5.3; the bound is `sessionOf`'s `pathRefreshBound`).
    function treeOf(bytes32 sessionId)
        external
        view
        returns (
            bytes32 treeId,
            uint32 leaves,
            uint32 used,
            bytes32 treeHash,
            bytes32 genesisTreeHash,
            bytes32 headEpochId,
            uint32 owed,
            uint32 sincePath
        );
    /// @notice Leaves `first..` below `used`, at most `TREE_LEAF_PAGE_MAX`.
    function treeLeaves(bytes32 sessionId, uint256 first, uint256 count) external view returns (TreeLeafView[] memory);
    /// @notice Nodes `first..` below `2 * leaves - 1`, at most `TREE_RANGE_MAX` (fable-16).
    function treeNodes(bytes32 sessionId, uint256 first, uint256 count) external view returns (TreeNodeView[] memory);
    /// @notice The live key of parent `node` (1,601 B); empty for a leaf or a blank parent.
    function treeNodeKey(bytes32 sessionId, uint256 node) external view returns (bytes memory);
    /// @notice A tree epoch's record and its `sigHash`; epoch 0 or a flat epoch: `PqChatModeEntry(0)`.
    function commitOf(bytes32 epochId) external view returns (IPqChat.PqChatCommit memory c, bytes32 sigHash);
    /// @notice A commit's landed list; two empty arrays before it lands or for `ctCount` 0.
    function pathListOf(bytes32 epochId) external view returns (uint32[] memory ctTargets, bytes32[] memory ctHashes);
    /// @notice A commit's landed node keys, in path order; empty before they land.
    function pathKeys(bytes32 epochId) external view returns (bytes[] memory);
    /// @notice A commit's landed ciphertext `i`; all empty before it lands.
    function pathCtAt(bytes32 epochId, uint256 i) external view returns (IPqChat.PathCt memory);
    /// @notice 0 a member or never one, 1 left, 2 removed; `epoch` the number of the head the exit was applied at (C9, C28).
    function goneOf(bytes32 sessionId, bytes32 ua) external view returns (uint8 kind, uint64 epoch);
    /// @notice The session-wide set: the period of a key taken out of a UA that went (C28).
    function goneKeyOf(bytes32 sessionId, bytes32 kemHash)
        external
        view
        returns (bool gone, uint64 joinEpoch, uint64 endEpoch);
    /// @notice The pair set: the period of a key taken out of a UA that stayed (R16).
    function goneOwnKeyOf(bytes32 sessionId, bytes32 ua, bytes32 kemHash)
        external
        view
        returns (bool gone, uint64 joinEpoch, uint64 endEpoch);
}
