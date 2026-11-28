// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IPqChat} from "./IPqChat.sol";
import {IPqChatTreeViews} from "./IPqChatTreeViews.sol";
import {PqChatCore} from "./PqChatCore.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {SSTORE2} from "../common/SSTORE2.sol";

/// @title `PqChatTreeViews`: the read-only body module of `PqChat`'s tree views (spec §6; owner 2026-11-24, option A).
/// @notice `PqChat` declares each view of `IPqChatTreeViews` and forwards it here by `DELEGATECALL` in the clone's context
///         (CTR-CHAT-32: no `fallback`), so it reads `PqChat`'s state and env through the same hooks as `PqChatTree`. It
///         writes nothing: its runtime holds no `SSTORE`, `TSTORE`, `LOG`, `CREATE`, `CREATE2`, `CALL`, `CALLCODE`,
///         `DELEGATECALL` or `SELFDESTRUCT` (`test/pqchat/PqChatTreeViews.t.sol` scans it); an unknown selector reverts with empty data (no `fallback`);
///         called directly it has no env and no tree. **UNAUDITED.**
contract PqChatTreeViews is IPqChatTreeViews, PqChatCore {
    /// @inheritdoc IPqChatTreeViews
    uint256 public constant TREE_RANGE_MAX = 256;
    /// @inheritdoc IPqChatTreeViews
    uint256 public constant TREE_LEAF_PAGE_MAX = 64; // C36

    /// @notice The factory whose `PqChat` releases name this module (checked by the release's constructor).
    address public immutable FACTORY;

    constructor(address factory_) {
        FACTORY = factory_;
    }

    /// @inheritdoc IPqChatTreeViews
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
        )
    {
        Tree storage t = _treeOf(sessionId);
        (IUARegistry reg,,) = _env();
        return (t.treeId, t.leaves, t.used, _treeHash(reg, t), t.genesisTreeHash, t.head, t.owed, t.sincePath);
    }

    /// @dev The length of the page `first..first + count` of `total`, `count` capped at `cap`.
    function _page(uint256 first, uint256 count, uint256 total, uint256 cap) private pure returns (uint256) {
        if (first >= total) return 0;
        if (count > cap) count = cap;
        return count < total - first ? count : total - first;
    }

    /// @inheritdoc IPqChatTreeViews
    function treeLeaves(bytes32 sessionId, uint256 first, uint256 count)
        external
        view
        returns (TreeLeafView[] memory v)
    {
        Tree storage t = _treeOf(sessionId);
        (IUARegistry reg,,) = _env();
        v = new TreeLeafView[](_page(first, count, t.used, TREE_LEAF_PAGE_MAX));
        for (uint256 i; i < v.length; ++i) {
            Leaf storage l = t.leafAt[first + i];
            if (!l.live) continue;
            v[i] = TreeLeafView(l.ua, l.keyId, l.joinEpoch, l.wrapIndex, keccak256(_kemPk(reg, l.ua, l.keyId)));
        }
    }

    /// @inheritdoc IPqChatTreeViews
    function treeNodes(bytes32 sessionId, uint256 first, uint256 count)
        external
        view
        returns (TreeNodeView[] memory v)
    {
        Tree storage t = _treeOf(sessionId);
        (IUARegistry reg,,) = _env();
        v = new TreeNodeView[](_page(first, count, 2 * uint256(t.leaves) - 1, TREE_RANGE_MAX));
        for (uint256 i; i < v.length; ++i) {
            uint256 x = first + i;
            if (x % 2 == 0) {
                Leaf storage l = t.leafAt[x / 2];
                if (l.live) {
                    v[i] = TreeNodeView(_thLeaf(reg, t, x / 2), keccak256(_kemPk(reg, l.ua, l.keyId)), l.joinEpoch);
                }
            } else {
                Node storage n = t.nodeAt[x];
                v[i] = TreeNodeView(n.hash, _keyHashOf(n.keyAt), uint64(n.keyAt >> 176));
            }
        }
    }

    /// @inheritdoc IPqChatTreeViews
    function treeNodeKey(bytes32 sessionId, uint256 node) external view returns (bytes memory) {
        uint256 k = _treeOf(sessionId).nodeAt[node].keyAt;
        if (node % 2 == 0 || k == 0) return "";
        return SSTORE2.read(address(uint160(k)), (k >> 160) & 0xffff, KEM_PK);
    }

    /// @inheritdoc IPqChatTreeViews
    function commitOf(bytes32 epochId) external view returns (IPqChat.PqChatCommit memory c, bytes32 sigHash) {
        Epoch storage ep = _known(epochId);
        if (ep.sessionId == epochId || !_isTree(ep.sessionId)) revert IPqChat.PqChatModeEntry(0);
        (c, sigHash) = abi.decode(_get(ep.record), (IPqChat.PqChatCommit, bytes32));
    }

    /// @inheritdoc IPqChatTreeViews
    function pathListOf(bytes32 epochId) external view returns (uint32[] memory ctTargets, bytes32[] memory ctHashes) {
        address list = _staged(epochId).list;
        if (list == address(0)) return (ctTargets, ctHashes);
        bytes memory b = SSTORE2.read(list);
        uint256 n = b.length / 36;
        (ctTargets, ctHashes) = (new uint32[](n), new bytes32[](n));
        for (uint256 j; j < n; ++j) {
            ctTargets[j] = uint32(bytes4(_slice(b, 4 * j, 4)));
            ctHashes[j] = bytes32(_slice(b, 4 * n + 32 * j, 32));
        }
    }

    /// @inheritdoc IPqChatTreeViews
    function pathKeys(bytes32 epochId) external view returns (bytes[] memory k) {
        address keys = _staged(epochId).keys;
        if (keys == address(0)) return k;
        uint256 m = (keys.code.length - 1) / KEM_PK;
        k = new bytes[](m);
        for (uint256 j; j < m; ++j) {
            k[j] = SSTORE2.read(keys, KEM_PK * j, KEM_PK);
        }
    }

    /// @inheritdoc IPqChatTreeViews
    function pathCtAt(bytes32 epochId, uint256 i) external view returns (IPqChat.PathCt memory ct) {
        uint256 s = _staged(epochId).ctAt[i];
        if (s == 0) return ct;
        bytes memory b = SSTORE2.read(address(uint160(s)), s >> 160, PATH_CT);
        (ct.mlkemCt, ct.x25519Eph, ct.sealedSecret) =
        (_slice(b, 0, 1568), bytes32(_slice(b, 1568, 32)), _slice(b, 1600, 48));
    }

    /// @inheritdoc IPqChatTreeViews
    function goneOf(bytes32 sessionId, bytes32 ua) external view returns (uint8 kind, uint64 epoch) {
        Gone storage g = _treeOf(sessionId).gone[ua];
        return (g.kind, g.epoch);
    }

    /// @inheritdoc IPqChatTreeViews
    function goneKeyOf(bytes32 sessionId, bytes32 kemHash)
        external
        view
        returns (bool gone, uint64 joinEpoch, uint64 endEpoch)
    {
        GoneKey storage g = _treeOf(sessionId).goneKey[kemHash];
        return (g.set, g.joinEpoch, g.endEpoch);
    }

    /// @inheritdoc IPqChatTreeViews
    function goneOwnKeyOf(bytes32 sessionId, bytes32 ua, bytes32 kemHash)
        external
        view
        returns (bool gone, uint64 joinEpoch, uint64 endEpoch)
    {
        GoneKey storage g = _treeOf(sessionId).goneOwnKey[ua][kemHash];
        return (g.set, g.joinEpoch, g.endEpoch);
    }

    function _slice(bytes memory b, uint256 off, uint256 n) private pure returns (bytes memory out) {
        out = new bytes(n);
        for (uint256 j; j < n; ++j) {
            out[j] = b[off + j];
        }
    }

    function _fail(uint8 code, uint256 a, uint256 b) internal pure override {
        _chatFail(code, a, b);
    }
}
