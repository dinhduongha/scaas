// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {PqChatTree} from "../../src/pqchat/PqChatTree.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {SSTORE2} from "../../src/common/SSTORE2.sol";

/// A harness, not a release (plan T3c): `PqChatTree` with the tree views of spec §6 drafted in, built only to measure what
/// they add to the module's runtime against the T-1 deploy line (35,286 B). The module has 19 B left at 198ade5bf, so the
/// views wait for the owner's call on where they live (AGENTS.md: no module split without the owner). Drafted readings
/// that the spec leaves open: `treeNodes` over every node index (an even index is a leaf: its `th`, its `kemHash`, its
/// `joinEpoch`); a page past the end is empty, never a revert.
contract PqChatTreeViewsProbe is PqChatTree {
    struct TreeLeafView {
        bytes32 ua;
        uint64 keyId;
        uint64 joinEpoch;
        uint32 wrapIndex;
        bytes32 kemHash;
    }

    struct TreeNodeView {
        bytes32 hash;
        bytes32 keyHash;
        uint64 epoch;
    }

    uint256 internal constant TREE_RANGE_MAX = 256;
    uint256 internal constant TREE_LEAF_PAGE_MAX = 64; // C36

    constructor(address factory_) PqChatTree(factory_) {}

    function treeOf(bytes32 sid)
        external
        view
        returns (
            bytes32 treeId,
            uint32 leaves,
            uint32 used,
            bytes32 treeHash,
            bytes32 genesisTreeHash,
            bytes32 headEpochId,
            uint32 owed
        )
    {
        Tree storage t = _treeOf(sid);
        (IUARegistry reg,,) = _env();
        return (t.treeId, t.leaves, t.used, _treeHash(reg, t), t.genesisTreeHash, t.head, t.owed);
    }

    function _page(uint256 first, uint256 count, uint256 total, uint256 cap) private pure returns (uint256) {
        if (first >= total) return 0;
        if (count > cap) count = cap;
        return count < total - first ? count : total - first;
    }

    function treeLeaves(bytes32 sid, uint256 first, uint256 count) external view returns (TreeLeafView[] memory v) {
        Tree storage t = _treeOf(sid);
        (IUARegistry reg,,) = _env();
        v = new TreeLeafView[](_page(first, count, t.used, TREE_LEAF_PAGE_MAX));
        for (uint256 i; i < v.length; ++i) {
            Leaf storage l = t.leafAt[first + i];
            if (!l.live) continue;
            v[i] = TreeLeafView(l.ua, l.keyId, l.joinEpoch, l.wrapIndex, keccak256(_kemPk(reg, l.ua, l.keyId)));
        }
    }

    function treeNodes(bytes32 sid, uint256 first, uint256 count) external view returns (TreeNodeView[] memory v) {
        Tree storage t = _treeOf(sid);
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

    function treeNodeKey(bytes32 sid, uint256 node) external view returns (bytes memory) {
        uint256 k = _treeOf(sid).nodeAt[node].keyAt;
        if (node % 2 == 0 || k == 0) return "";
        return SSTORE2.read(address(uint160(k)), (k >> 160) & 0xffff, KEM_PK);
    }

    function commitOf(bytes32 epochId) external view returns (IPqChat.PqChatCommit memory c, bytes32 sigHash) {
        Epoch storage ep = _known(epochId);
        if (ep.sessionId == epochId || !_isTree(ep.sessionId)) revert IPqChat.PqChatModeEntry(0);
        (c, sigHash) = abi.decode(_get(ep.record), (IPqChat.PqChatCommit, bytes32));
    }

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

    function pathKeys(bytes32 epochId) external view returns (bytes[] memory k) {
        address keys = _staged(epochId).keys;
        if (keys == address(0)) return k;
        uint256 m = (keys.code.length - 1) / KEM_PK;
        k = new bytes[](m);
        for (uint256 j; j < m; ++j) {
            k[j] = SSTORE2.read(keys, KEM_PK * j, KEM_PK);
        }
    }

    function pathCtAt(bytes32 epochId, uint256 i) external view returns (IPqChat.PathCt memory ct) {
        uint256 s = _staged(epochId).ctAt[i];
        if (s == 0) return ct;
        bytes memory b = SSTORE2.read(address(uint160(s)), s >> 160, PATH_CT);
        (ct.mlkemCt, ct.x25519Eph, ct.sealedSecret) =
        (_slice(b, 0, 1568), bytes32(_slice(b, 1568, 32)), _slice(b, 1600, 48));
    }

    function goneOf(bytes32 sid, bytes32 ua) external view returns (uint8 kind, uint64 epoch) {
        Gone storage g = _treeOf(sid).gone[ua];
        return (g.kind, g.epoch);
    }

    function goneKeyOf(bytes32 sid, bytes32 kemHash)
        external
        view
        returns (bool gone, uint64 joinEpoch, uint64 endEpoch)
    {
        GoneKey storage g = _treeOf(sid).goneKey[kemHash];
        return (g.set, g.joinEpoch, g.endEpoch);
    }

    function goneOwnKeyOf(bytes32 sid, bytes32 ua, bytes32 kemHash)
        external
        view
        returns (bool gone, uint64 joinEpoch, uint64 endEpoch)
    {
        GoneKey storage g = _treeOf(sid).goneOwnKey[ua][kemHash];
        return (g.set, g.joinEpoch, g.endEpoch);
    }

    function _slice(bytes memory b, uint256 off, uint256 n) private pure returns (bytes memory out) {
        out = new bytes(n);
        for (uint256 j; j < n; ++j) {
            out[j] = b[off + j];
        }
    }
}
