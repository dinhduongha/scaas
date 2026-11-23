// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../ua/IUARegistry.sol";
import {SSTORE2} from "../common/SSTORE2.sol";

/// @title A group's ratchet tree, for any contract that keeps one (owner 2026-11-23, CTR-CHAT-26: the two layers; and "or other
///        systems that use a tree"): RFC 9420's array layout and tree hash over registry KEM keys, the key admission check of
///        scheme 1, the live tree and the no-return sets (R16) of each group, in an ERC-7201 namespace of the inheritor.
/// @notice App-agnostic: no record type, no domain, no error of its own. The inheritor fixes, by the hooks below, the namespace
///         slot (`_treeSlot`: ERC-7201 of its own namespace id followed by `.tree`, so two apps whose ids differ never share
///         one, also behind one `DELEGATECALL`), the leaf and parent typehashes of the tree hash (`_treeTypehashes`: its own type
///         strings are its label, so two apps' trees never share a hash space), its bounds (`_treeBounds`) and its named errors
///         (`_treeFail`). A group is a `bytes32` id of the inheritor's. A leaf is a `(ua, keyId)` KEM key of the registry, by
///         reference; its `kemHash` is never stored, it is the registry's (write-once) wherever a hash needs it. Rights, records,
///         signatures and commits are the inheritor's. Interface for inheritors: `docs/contracts/pqchat.md` §17.
///         **UNAUDITED.**
abstract contract PqGroupTree {
    /// @dev What `_treeFail` raises, each inheritor by its own named error: `a`, `b` its arguments as words.
    uint8 internal constant T_SHAPE = 0; // ()
    uint8 internal constant T_KEM_KEY = 1; // (ua, keyId): no scheme-1 key of 1,601 B, or one that fails the admission check
    uint8 internal constant T_KEY_LIVE = 2; // (kemHash): a live leaf already holds that key

    uint256 internal constant KEM_PK = 1601; // 0x01 ‖ ek (1,568) ‖ pk_X (32)
    uint256 internal constant P25519 = 2 ** 255 - 19;

    /// @dev A leaf, two slots: `ua`; `keyId`, `joinEpoch`, `wrapIndex` (the wrap that brought it), `live`.
    struct Leaf {
        bytes32 ua;
        uint64 keyId;
        uint64 joinEpoch;
        uint32 wrapIndex;
        bool live;
    }

    /// @dev A parent, two slots: its `th` and its key (`pointer | offset << 160 | epoch << 176`, 0 = blank).
    struct Node {
        bytes32 hash;
        uint256 keyAt;
    }

    /// @dev Per UA: its live leaves, and whether the inheritor listed it (`listed`, stays set).
    struct Keys {
        uint32 live;
        bool listed;
    }

    /// @dev A UA that left (kind 1) or was removed (kind 2), at the head's epoch number; never cleared (C28).
    struct Gone {
        uint8 kind;
        uint64 epoch;
    }

    /// @dev A key taken out of a leaf: its period; never cleared (C28, R16).
    struct GoneKey {
        uint64 joinEpoch;
        uint64 endEpoch;
        bool set;
    }

    struct Tree {
        bytes32 treeId; // 0 = no tree
        bytes32 genesisTreeHash;
        bytes32 head; // the head epoch's id, from the completion of epoch 0
        uint32 used;
        uint32 leaves;
        uint32 owed;
        mapping(uint256 => Leaf) leafAt; // by leaf index
        mapping(uint256 => Node) nodeAt; // by node index (odd: parents)
        mapping(bytes32 => Keys) keysOf; // by UA
        mapping(bytes32 => uint256) liveKey; // by kemHash: leaf + 1
        mapping(bytes32 => Gone) gone; // by UA
        mapping(bytes32 => mapping(bytes32 => GoneKey)) goneOwnKey; // the pair set, by UA then kemHash (R16)
        mapping(bytes32 => GoneKey) goneKey; // the group-wide set, by kemHash (R16)
        bytes32[] admins; // the live admin list
    }

    /// @custom:storage-location erc7201:<the inheritor's namespace id>.tree
    struct TreeStore {
        mapping(bytes32 => Tree) trees; // by group id
    }

    // ------------------------------------------------------------------ the hooks

    /// @dev ERC-7201 slot of the inheritor's namespace id followed by `.tree` (`scaas.pqchat` -> `scaas.pqchat.tree`).
    function _treeSlot() internal pure virtual returns (bytes32);
    /// @dev The typehashes of `th(leaf)` (fields `uint32 leaf, bytes32 ua, uint64 keyId, bytes32 kemHash`) and `th(parent)`
    ///      (`bytes32 keyHash, bytes32 left, bytes32 right`): the inheritor's type strings are the tree hash's label.
    function _treeTypehashes() internal pure virtual returns (bytes32 leaf, bytes32 parent);
    /// @dev The most leaf positions and admins a group may have.
    function _treeBounds() internal pure virtual returns (uint256 leavesMax, uint256 adminsMax);
    /// @dev Reverts with the inheritor's named error for `code` (`T_*`); never returns.
    function _treeFail(uint8 code, uint256 a, uint256 b) internal pure virtual;

    function _tree(bytes32 gid) internal view returns (Tree storage t) {
        TreeStore storage s;
        bytes32 slot = _treeSlot();
        assembly ("memory-safe") {
            s.slot := slot
        }
        t = s.trees[gid];
    }

    // ------------------------------------------------------------------ RFC 9420 Appendix C (`leaves` a power of two)

    /// @dev The count of trailing one bits of `x`.
    function _level(uint256 x) internal pure returns (uint256 k) {
        while ((x >> k) & 1 == 1) ++k;
    }

    function _parentOf(uint256 x) internal pure returns (uint256) {
        uint256 k = _level(x);
        return (x | (1 << k)) ^ (((x >> (k + 1)) & 1) << (k + 1));
    }

    function _siblingOf(uint256 x) internal pure returns (uint256) {
        uint256 p = _parentOf(x);
        uint256 h = 1 << (_level(p) - 1);
        return x < p ? p + h : p - h;
    }

    // ------------------------------------------------------------------ the group

    /// @dev A new group's tree, cold: `used` leaf positions (`leaves` the smallest power of two not below it), every node
    ///      blank, the admin list. Leaves come by `_treeSetLeaf`.
    function _treeOpen(bytes32 gid, bytes32 treeId, uint256 used, bytes32[] calldata admins) internal {
        (uint256 leavesMax, uint256 adminsMax) = _treeBounds();
        if (used == 0 || used > leavesMax || admins.length > adminsMax) _treeFail(T_SHAPE, 0, 0);
        uint256 leaves = 1;
        while (leaves < used) leaves <<= 1;
        Tree storage t = _tree(gid);
        (t.treeId, t.used, t.leaves) = (treeId, uint32(used), uint32(leaves));
        t.admins = admins;
    }

    /// @dev Leaf `i` set to `(ua, keyId)` (its key admitted, `kemHash` not live), `liveKey`, `keysOf` and the `th` of each
    ///      ancestor written. Returns whether the UA was not listed yet (it is from now on).
    function _treeSetLeaf(
        IUARegistry reg,
        bytes32 gid,
        uint256 i,
        bytes32 ua,
        uint64 keyId,
        uint64 joinEpoch,
        uint32 wrapIndex
    ) internal returns (bool newlyListed) {
        Tree storage t = _tree(gid);
        bytes32 kemHash = _admittedKey(reg, ua, keyId);
        if (t.liveKey[kemHash] != 0) _treeFail(T_KEY_LIVE, uint256(kemHash), 0);
        t.liveKey[kemHash] = i + 1;
        t.leafAt[i] = Leaf(ua, keyId, joinEpoch, wrapIndex, true);
        Keys storage k = t.keysOf[ua];
        newlyListed = !k.listed;
        (k.live, k.listed) = (k.live + 1, true);
        _treeRehash(reg, t, 2 * i, _leafHash(i, ua, keyId, kemHash));
    }

    /// @dev Marks `ua` listed (the inheritor listed it by other means).
    function _treeListed(bytes32 gid, bytes32 ua) internal {
        _tree(gid).keysOf[ua].listed = true;
    }

    /// @dev The group's first epoch completed: its head and the genesis tree hash.
    function _treeGenesis(IUARegistry reg, bytes32 gid, bytes32 head) internal {
        Tree storage t = _tree(gid);
        (t.head, t.genesisTreeHash) = (head, _treeHash(reg, t));
    }

    /// @dev `th(root)`.
    function _treeHash(IUARegistry reg, Tree storage t) internal view returns (bytes32) {
        return t.leaves == 1 ? _thLeaf(reg, t, 0) : t.nodeAt[t.leaves - 1].hash;
    }

    // ------------------------------------------------------------------ th (RFC 9420 §7.8, typed)

    /// @dev The `th` of every ancestor of node `x`, whose `th` is `h`, bottom-up from the stored hashes; a sibling leaf's
    ///      `kemHash` from the registry.
    function _treeRehash(IUARegistry reg, Tree storage t, uint256 x, bytes32 h) internal {
        uint256 root = t.leaves - 1;
        while (x != root) {
            uint256 s = _siblingOf(x);
            bytes32 hs = s & 1 == 0 ? _thLeaf(reg, t, s / 2) : t.nodeAt[s].hash;
            uint256 p = _parentOf(x);
            Node storage n = t.nodeAt[p];
            h = x < s ? _thParent(_keyHashOf(n.keyAt), h, hs) : _thParent(_keyHashOf(n.keyAt), hs, h);
            n.hash = h;
            x = p;
        }
    }

    function _thLeaf(IUARegistry reg, Tree storage t, uint256 i) internal view returns (bytes32) {
        Leaf storage l = t.leafAt[i];
        if (!l.live) return 0;
        (bytes32 ua, uint64 keyId) = (l.ua, l.keyId);
        return _leafHash(i, ua, keyId, keccak256(_kemPk(reg, ua, keyId)));
    }

    function _leafHash(uint256 i, bytes32 ua, uint64 keyId, bytes32 kemHash) internal pure returns (bytes32) {
        (bytes32 leafTypehash,) = _treeTypehashes();
        return keccak256(abi.encode(leafTypehash, uint32(i), ua, keyId, kemHash));
    }

    /// @dev 0 for a blank parent over two empty subtrees.
    function _thParent(bytes32 keyHash, bytes32 l, bytes32 r) internal pure returns (bytes32) {
        if (keyHash == 0 && l == 0 && r == 0) return 0;
        (, bytes32 parentTypehash) = _treeTypehashes();
        return keccak256(abi.encode(parentTypehash, keyHash, l, r));
    }

    /// @dev `keccak256` of a parent's stored key, 0 when blank.
    function _keyHashOf(uint256 keyAt) internal view returns (bytes32) {
        if (keyAt == 0) return 0;
        return keccak256(SSTORE2.read(address(uint160(keyAt)), (keyAt >> 160) & 0xffff, KEM_PK));
    }

    // ------------------------------------------------------------------ keys and the admission check (C19, C32)

    /// @dev The registry's `kemPk` of `(ua, keyId)`, `scheme ‖ ek ‖ pk_X` (`UAKinds`' form); empty `ek` when none.
    function _kemPk(IUARegistry reg, bytes32 ua, uint64 keyId) internal view returns (bytes memory) {
        (IUARegistry.KemKey memory k,) = reg.kemKeyAt(ua, keyId);
        return abi.encodePacked(k.scheme, k.mlkemEk, k.x25519);
    }

    /// @dev The `kemHash` of `(ua, keyId)`'s registry key when it passes the admission check, else `T_KEM_KEY`.
    function _admittedKey(IUARegistry reg, bytes32 ua, uint64 keyId) internal view returns (bytes32) {
        bytes memory pk = _kemPk(reg, ua, keyId);
        if (!_admissible(pk)) _treeFail(T_KEM_KEY, uint256(ua), keyId);
        return keccak256(pk);
    }

    /// @notice The public admission check of a scheme-1 `kemPk` (spec §8, C19, C32), as clientkeys' `admitKemKey` and
    ///         `ua-rs`: 1,601 B, scheme byte 1; every 12-bit coefficient of the first 1,536 B of `ek` below 3,329 (FIPS 203
    ///         §7.2); `pk_X` (little-endian) canonical, bit 255 clear and below `p`, and none of the five small-order values
    ///         (0, 1, the two of order 8, `p − 1`). A rule on bytes: it does not make a key the only one its secret opens
    ///         (R15).
    function _admissible(bytes memory pk) internal pure returns (bool ok) {
        if (pk.length != KEM_PK || pk[0] != 0x01) return false;
        assembly ("memory-safe") {
            ok := 1
            let p := add(pk, 33) // ek
            for { let e := add(p, 1536) } lt(p, e) { p := add(p, 3) } {
                let w := shr(232, mload(p)) // b0 b1 b2, big-endian
                let b0 := shr(16, w)
                let b1 := and(shr(8, w), 0xff)
                let b2 := and(w, 0xff)
                if or(iszero(lt(or(b0, shl(8, and(b1, 15))), 3329)), iszero(lt(or(shr(4, b1), shl(4, b2)), 3329))) {
                    ok := 0
                    break
                }
            }
        }
        if (!ok) return false;
        uint256 u;
        for (uint256 j; j < 32; ++j) {
            u |= uint256(uint8(pk[1569 + j])) << (8 * j);
        }
        return u < P25519 && u > 1 && u != P25519 - 1
            && u != 325606250916557431795983626356110631294008115727848805560023387167927233504
            && u != 39382357235489614581723060781553021112529911719440698176882885853963445705823;
    }
}
