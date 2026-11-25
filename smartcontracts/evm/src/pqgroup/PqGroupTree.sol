// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IPqGroupTree} from "./IPqGroupTree.sol";
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
    uint8 internal constant T_LEAF = 3; // (leaf): not live with the named key, not blank for an Add, the author's, out of range
    uint8 internal constant T_RETURN = 4; // (ua): an Add of a UA that is gone (R14, C28)
    uint8 internal constant T_KEY_RETURN = 5; // (kemHash): an Add of a key of the group-wide set (R16)
    uint8 internal constant T_OWN_KEY_RETURN = 6; // (ua, kemHash): an Add under `ua` of a key of its pair set (R16)
    uint8 internal constant T_ADMINS = 7; // (): no admin with a live leaf would remain (C24)
    uint8 internal constant T_BACKLOG = 8; // (owed): more leaves owed at the head than a commit may change (C21)
    uint8 internal constant T_TARGETS = 9; // (count): the path length or the target count differs from the walk
    uint8 internal constant T_HASH = 10; // (computed): the signed tree hash differs from the walk's root (R12)
    uint8 internal constant T_REMOVED_KEPT = 11; // (head, ua): a gone UA keeps a leaf, is an admin or the author
    uint8 internal constant T_NOT_MEMBER = 12; // (ua): no live leaf, or gone
    uint8 internal constant T_NOT_ADMIN = 13; // (ua): not a live admin of the head

    uint256 internal constant KEM_PK = 1601; // 0x01 ‖ ek (1,568) ‖ pk_X (32)
    /// @dev The base's own bound on leaf positions, whatever `_treeBounds()` says (review A-6; owner R8 2026-11-25: 256 ->
    ///      512): a direct path is at most 9 parents (`_walkPath`'s array of 10) and a path key's offset in its blob fits
    ///      16 bits (`keyAt`: 9 x 1,601 B).
    uint256 internal constant TREE_LEAVES_LIMIT = 512;
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

    /// @dev A staged commit's landed pieces (CTR-CHAT-27 §7): the hash of the targets the walk expects (4 B each, packed),
    ///      the list's blob, the node keys' blob, each ciphertext's slot (`pointer | offset << 160`); 0 = not landed.
    struct Staged {
        bytes32 targetsHash;
        address list;
        address keys;
        mapping(uint256 => uint256) ctAt;
    }

    /// @custom:storage-location erc7201:<the inheritor's namespace id>.tree
    struct TreeStore {
        mapping(bytes32 => Tree) trees; // by group id
        mapping(bytes32 => Staged) staged; // by epoch id (appended: no pinned slot moves)
    }

    /// @dev A commit's change, as the walk reads it from the inheritor's record.
    struct Delta {
        bytes32 author;
        uint32 leaf;
        uint64 keyId;
        uint32 leaves; // the tree's size after the commit
        uint64 epoch; // the commit's epoch number
        bytes32[] admins; // the new epoch's, sorted
        IPqGroupTree.TreeRemove[] removes;
        IPqGroupTree.TreeAdd[] adds;
        bytes32[] nodeKeyHashes;
        uint32 ctCount;
        bytes32 treeHash;
    }

    /// @dev The tree of a commit, in memory (nothing written): per node `st` (0 as stored, 1 blank, 2 set), its `th` when
    ///      `st != 0`, a set parent's key hash; the UAs the changes name with their live leaves after the Adds; each Remove's
    ///      `kemHash`; the author's filtered path and its targets, in order.
    struct Walk {
        uint8[] st;
        bytes32[] th;
        bytes32[] kh;
        bytes32[] uas;
        uint256[] live;
        uint256 nUas;
        bytes32[] rmKem;
        uint256[] path;
        uint32[] targets;
        uint256 used;
        uint256 leaves;
        bytes32 root;
    }

    // ------------------------------------------------------------------ the hooks

    /// @dev ERC-7201 slot of the inheritor's namespace id followed by `.tree` (`scaas.pqchat` -> `scaas.pqchat.tree`).
    function _treeSlot() internal pure virtual returns (bytes32);
    /// @dev The typehashes of `th(leaf)` (fields `uint32 leaf, bytes32 ua, uint64 keyId, bytes32 kemHash`) and `th(parent)`
    ///      (`bytes32 keyHash, bytes32 left, bytes32 right`): the inheritor's type strings are the tree hash's label.
    function _treeTypehashes() internal pure virtual returns (bytes32 leaf, bytes32 parent);
    /// @dev The most leaf positions and admins a group may have, changes per commit (also leaves owed at a head, C21) and
    ///      live leaves per UA. Leaf positions stop at `TREE_LEAVES_LIMIT` (512) whatever this returns.
    function _treeBounds()
        internal
        pure
        virtual
        returns (uint256 leavesMax, uint256 adminsMax, uint256 changesMax, uint256 keysMax);
    /// @dev A commit's completion gave `ua` its first leaf in group `gid` (the inheritor's index, e.g. `sessionsOf`).
    function _treeListedNew(bytes32 gid, bytes32 ua) internal virtual;
    /// @dev Reverts with the inheritor's named error for `code` (`T_*`); never returns.
    function _treeFail(uint8 code, uint256 a, uint256 b) internal pure virtual;

    function _treeStore() internal pure returns (TreeStore storage s) {
        bytes32 slot = _treeSlot();
        assembly ("memory-safe") {
            s.slot := slot
        }
    }

    function _tree(bytes32 gid) internal view returns (Tree storage) {
        return _treeStore().trees[gid];
    }

    function _staged(bytes32 epochId) internal view returns (Staged storage) {
        return _treeStore().staged[epochId];
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
        (uint256 leavesMax, uint256 adminsMax,,) = _treeBounds();
        if (used == 0 || used > leavesMax || used > TREE_LEAVES_LIMIT || admins.length > adminsMax) {
            _treeFail(T_SHAPE, 0, 0);
        }
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

    // ------------------------------------------------------------------ leave, removal (C9, C21, C28)

    /// @dev `ua` gone (kind 1 left, 2 removed) at the head's epoch number `epoch`, never cleared; its live leaves owed by the
    ///      next commit, at most `changesMax` at a head (`T_BACKLOG`). A UA already gone is left as it is.
    function _treeGo(bytes32 gid, bytes32 ua, uint8 kind, uint64 epoch) internal {
        Tree storage t = _tree(gid);
        if (t.gone[ua].kind != 0) return;
        t.gone[ua] = Gone(kind, epoch);
        (,, uint256 changesMax,) = _treeBounds();
        uint256 owed = t.owed + t.keysOf[ua].live;
        if (owed > changesMax) _treeFail(T_BACKLOG, owed, 0);
        t.owed = uint32(owed);
    }

    /// @dev A live member: a UA with a live leaf that is not gone.
    function _treeMember(Tree storage t, bytes32 ua) internal view returns (bool) {
        return t.keysOf[ua].live != 0 && t.gone[ua].kind == 0;
    }

    /// @dev A live admin of the head: in its list and not gone.
    function _treeAdmin(Tree storage t, bytes32 ua) internal view returns (bool) {
        return t.gone[ua].kind == 0 && _in(t.admins, ua);
    }

    /// @dev C24: an admin of the head's list that is a live member remains.
    function _treeLeafyAdmin(Tree storage t) internal view returns (bool) {
        for (uint256 i; i < t.admins.length; ++i) {
            if (_treeMember(t, t.admins[i])) return true;
        }
        return false;
    }

    /// @dev C38: some UA that is not gone holds a live leaf (else the group is closed). A scan of the leaf positions, read
    ///      only on the path where no admin with a leaf remains.
    function _treeHasMember(Tree storage t) internal view returns (bool) {
        for (uint256 i; i < t.used; ++i) {
            Leaf storage l = t.leafAt[i];
            if (l.live && t.gone[l.ua].kind == 0) return true;
        }
        return false;
    }

    function _in(bytes32[] storage a, bytes32 x) internal view returns (bool) {
        for (uint256 i; i < a.length; ++i) {
            if (a[i] == x) return true;
        }
        return false;
    }

    // ------------------------------------------------------------------ a commit (spec §8, §9)

    /// @dev Everything public about a commit `d` on the head, in memory (R12, C7): the author's leaf, the Removes and the
    ///      Adds (R14, R16, C18, C19, the level judged after the Adds, fable-r3-4), the bounds, the gone UAs (`owed`), the
    ///      admin list against the prospective gone set (codex-r3-10, C24), the rights of §9, the shapes, the walk of the
    ///      filtered path and the root. `completing`: the completion's step 1, where a gone author is `T_REMOVED_KEPT`.
    function _treeCheck(IUARegistry reg, bytes32 gid, Delta memory d, bool completing)
        internal
        view
        returns (Walk memory w)
    {
        Tree storage t = _tree(gid);
        {
            Leaf storage al = t.leafAt[d.leaf];
            if (d.leaf >= t.used || !al.live || al.ua != d.author || al.keyId != d.keyId) _treeFail(T_LEAF, d.leaf, 0);
        }
        if (t.gone[d.author].kind != 0) {
            _treeFail(
                completing ? T_REMOVED_KEPT : T_NOT_MEMBER,
                completing ? uint256(t.head) : uint256(d.author),
                uint256(d.author)
            );
        }
        w = _walkInit(t, d);
        _walkRemoves(reg, t, d, w);
        _walkAdds(reg, t, d, w);
        _walkJudge(reg, t, d, w);
        _walkPath(t, d, w);
        _walkHash(reg, t, w);
        if (w.leaves != d.leaves) _treeFail(T_SHAPE, 0, 0);
        if (w.root != d.treeHash) _treeFail(T_HASH, uint256(w.root), 0);
    }

    /// @dev The size after the Adds (each at a leaf below `used`, or at `used`, in order) and the memory tree.
    function _walkInit(Tree storage t, Delta memory d) private view returns (Walk memory w) {
        (uint256 leavesMax,, uint256 changesMax,) = _treeBounds();
        uint256 nr = d.removes.length;
        if (nr + d.adds.length > changesMax) _treeFail(T_SHAPE, 0, 0);
        uint256 used = t.used;
        for (uint256 i; i < d.adds.length; ++i) {
            uint256 l = d.adds[i].leaf;
            if (l > used || l >= leavesMax || l >= TREE_LEAVES_LIMIT) _treeFail(T_LEAF, l, 0);
            if (l == used) ++used;
        }
        uint256 leaves = t.leaves;
        while (leaves < used) leaves <<= 1;
        uint256 n = 2 * leaves - 1;
        (w.used, w.leaves) = (used, leaves);
        (w.st, w.th, w.kh) = (new uint8[](n), new bytes32[](n), new bytes32[](n));
        (w.uas, w.live, w.rmKem) =
        (new bytes32[](nr + d.adds.length), new uint256[](nr + d.adds.length), new bytes32[](nr));
        // depth(leaves) bounds the path; `ctCount < leaves`; no path exactly when no ciphertext (C24)
        uint256 depth;
        while ((1 << depth) < d.leaves) ++depth;
        if (
            d.nodeKeyHashes.length > depth || d.ctCount >= d.leaves || (d.ctCount == 0) != (d.nodeKeyHashes.length == 0)
        ) _treeFail(T_SHAPE, 0, 0);
    }

    function _walkRemoves(IUARegistry reg, Tree storage t, Delta memory d, Walk memory w) private view {
        for (uint256 i; i < d.removes.length; ++i) {
            IPqGroupTree.TreeRemove memory r = d.removes[i];
            Leaf storage l = t.leafAt[r.leaf];
            if (
                r.leaf >= t.used || r.leaf == d.leaf || !l.live || l.ua != r.ua || l.keyId != r.keyId
                    || w.st[2 * r.leaf] != 0
            ) _treeFail(T_LEAF, r.leaf, 0);
            w.st[2 * r.leaf] = 1;
            _blankPath(w, 2 * r.leaf);
            w.live[_uaAt(t, w, r.ua)] -= 1;
            w.rmKem[i] = keccak256(_kemPk(reg, r.ua, r.keyId));
        }
    }

    function _walkAdds(IUARegistry reg, Tree storage t, Delta memory d, Walk memory w) private view {
        for (uint256 i; i < d.adds.length; ++i) {
            IPqGroupTree.TreeAdd memory a = d.adds[i];
            uint256 x = 2 * a.leaf;
            if (w.st[x] == 2 || (w.st[x] == 0 && t.leafAt[a.leaf].live)) _treeFail(T_LEAF, a.leaf, 0);
            if (t.gone[a.ua].kind != 0) _treeFail(T_RETURN, uint256(a.ua), 0);
            bytes32 k = _admittedKey(reg, a.ua, a.keyId);
            if (k != a.kemHash) _treeFail(T_KEM_KEY, uint256(a.ua), a.keyId);
            uint256 lk = t.liveKey[k];
            // C39: live while this commit has not removed its leaf (0); removed (1) or removed and refilled (2) frees it
            if (lk != 0 && w.st[2 * (lk - 1)] == 0) _treeFail(T_KEY_LIVE, uint256(k), 0);
            for (uint256 j; j < i; ++j) {
                if (d.adds[j].kemHash == k) _treeFail(T_KEY_LIVE, uint256(k), 0);
            }
            if (t.goneKey[k].set) _treeFail(T_KEY_RETURN, uint256(k), 0);
            if (t.goneOwnKey[a.ua][k].set) _treeFail(T_OWN_KEY_RETURN, uint256(a.ua), uint256(k));
            w.st[x] = 2;
            w.th[x] = _leafHash(a.leaf, a.ua, a.keyId, k);
            _blankPath(w, x);
            w.live[_uaAt(t, w, a.ua)] += 1;
        }
    }

    /// @dev On the tree after the Adds: the keys per UA; a Remove's bytes added again in the same commit at their level
    ///      (R16); no gone UA keeps a leaf (every leaf owed is removed); the admin list (sorted, registered, none gone now or
    ///      by this commit: codex-r3-10; C24 with fable-r2-6's exemption); the rights of §9 (C8).
    function _walkJudge(IUARegistry reg, Tree storage t, Delta memory d, Walk memory w) private view {
        (,,, uint256 keysMax) = _treeBounds();
        for (uint256 i; i < w.nUas; ++i) {
            if (w.live[i] > keysMax) _treeFail(T_SHAPE, 0, 0);
        }
        uint256 owed;
        bool plain = true;
        for (uint256 j; j < d.removes.length; ++j) {
            IPqGroupTree.TreeRemove memory r = d.removes[j];
            bool gone = t.gone[r.ua].kind != 0;
            if (gone) ++owed;
            else if (r.ua != d.author) plain = false;
            for (uint256 i; i < d.adds.length; ++i) {
                if (d.adds[i].kemHash != w.rmKem[j]) continue;
                if (d.adds[i].ua == r.ua) _treeFail(T_OWN_KEY_RETURN, uint256(r.ua), uint256(w.rmKem[j]));
                if (w.live[_uaAt(t, w, r.ua)] == 0) _treeFail(T_KEY_RETURN, uint256(w.rmKem[j]), 0);
            }
        }
        if (owed != t.owed) _keptFail(t, w);
        for (uint256 i; i < d.adds.length; ++i) {
            if (d.adds[i].ua != d.author) plain = false;
        }
        bytes32[] memory a = d.admins;
        (, uint256 adminsMax,,) = _treeBounds();
        if (a.length > adminsMax) _treeFail(T_SHAPE, 0, 0);
        bool leafy;
        for (uint256 i; i < a.length; ++i) {
            if ((i > 0 && a[i] <= a[i - 1]) || !reg.isRegistered(a[i])) _treeFail(T_SHAPE, 0, 0);
            if (t.gone[a[i]].kind != 0 || _goes(t, w, a[i])) _treeFail(T_REMOVED_KEPT, uint256(t.head), uint256(a[i]));
            if (_liveAfter(t, w, a[i]) != 0) leafy = true;
        }
        if (!_keepsAdmins(t, w, a)) {
            plain = false;
            if (!leafy) _treeFail(T_ADMINS, 0, 0);
        }
        if (!plain && !_treeAdmin(t, d.author)) _treeFail(T_NOT_ADMIN, uint256(d.author), 0);
    }

    /// @dev `a` is the head's list less UAs that are gone or that this commit leaves with no leaf (both sorted).
    function _keepsAdmins(Tree storage t, Walk memory w, bytes32[] memory a) private view returns (bool) {
        bytes32[] storage h = t.admins;
        uint256 j;
        for (uint256 i; i < h.length; ++i) {
            bytes32 x = h[i];
            if (j < a.length && a[j] == x) ++j;
            else if (j < a.length && a[j] < x) return false;
            else if (t.gone[x].kind == 0 && !_goes(t, w, x)) return false;
        }
        return j == a.length;
    }

    /// @dev `ua` holds a leaf on the head and none after the commit's Adds: gone by this commit (fable-r3-4).
    function _goes(Tree storage t, Walk memory w, bytes32 ua) private view returns (bool) {
        return t.keysOf[ua].live != 0 && _liveAfter(t, w, ua) == 0;
    }

    function _liveAfter(Tree storage t, Walk memory w, bytes32 ua) private view returns (uint256) {
        for (uint256 i; i < w.nUas; ++i) {
            if (w.uas[i] == ua) return w.live[i];
        }
        return t.keysOf[ua].live;
    }

    /// @dev Names a gone UA that keeps a leaf on the commit's tree.
    function _keptFail(Tree storage t, Walk memory w) private view {
        for (uint256 i; i < t.used; ++i) {
            bytes32 ua = t.leafAt[i].ua;
            if (w.st[2 * i] == 0 && t.leafAt[i].live && t.gone[ua].kind != 0) {
                _treeFail(T_REMOVED_KEPT, uint256(t.head), uint256(ua));
            }
        }
        _treeFail(T_REMOVED_KEPT, uint256(t.head), 0);
    }

    /// @dev The index of `ua` among the UAs the changes name, added with its live leaves on the head.
    function _uaAt(Tree storage t, Walk memory w, bytes32 ua) private view returns (uint256 i) {
        for (; i < w.nUas; ++i) {
            if (w.uas[i] == ua) return i;
        }
        (w.uas[i], w.live[i]) = (ua, t.keysOf[ua].live);
        ++w.nUas;
    }

    /// @dev The parents above node `x` blanked (a changed leaf's direct path, C6), unless already marked.
    function _blankPath(Walk memory w, uint256 x) private pure {
        uint256 root = w.leaves - 1;
        while (x != root) {
            x = _parentOf(x);
            if (w.st[x] == 0) w.st[x] = 1;
        }
    }

    /// @dev The author's filtered path on the commit's tree and the resolution of each copath child (RFC 9420 §4.1.2, §7.5),
    ///      upward, each in ascending node order; the path takes `nodeKeyHashes` in order, the rest of the direct path blank.
    function _walkPath(Tree storage t, Delta memory d, Walk memory w) private view {
        uint256 x = 2 * uint256(d.leaf);
        uint256 root = w.leaves - 1;
        uint32[] memory tg = new uint32[](w.leaves);
        uint256[] memory path = new uint256[](10);
        (uint256 n, uint256 k) = (0, 0);
        while (x != root) {
            uint256 p = _parentOf(x);
            uint256 before = n;
            n = _resolve(t, w, _siblingOf(x), tg, n);
            if (n != before) path[k++] = p;
            w.st[p] = 1;
            x = p;
        }
        if (k != d.nodeKeyHashes.length) _treeFail(T_TARGETS, k, 0);
        if (n != d.ctCount) _treeFail(T_TARGETS, n, 0);
        for (uint256 i; i < k; ++i) {
            (w.st[path[i]], w.kh[path[i]]) = (2, d.nodeKeyHashes[i]);
        }
        assembly ("memory-safe") {
            mstore(tg, n)
            mstore(path, k)
        }
        (w.targets, w.path) = (tg, path);
    }

    /// @dev Appends the resolution of node `x` on the commit's tree to `tg` from `n`.
    function _resolve(Tree storage t, Walk memory w, uint256 x, uint32[] memory tg, uint256 n)
        private
        view
        returns (uint256)
    {
        uint8 s = w.st[x];
        if (x & 1 == 0) {
            if (s == 2 || (s == 0 && t.leafAt[x / 2].live)) tg[n++] = uint32(x);
            return n;
        }
        if (s == 0) {
            Node storage nd = t.nodeAt[x];
            if (nd.keyAt != 0) {
                tg[n++] = uint32(x);
                return n;
            }
            if (nd.hash == 0) return n; // no member below, nothing changed below
        }
        uint256 h = 1 << (_level(x) - 1);
        return _resolve(t, w, x + h, tg, _resolve(t, w, x - h, tg, n));
    }

    /// @dev `th` of every marked parent, level by level; an unmarked child's from storage (a leaf's `kemHash` from the
    ///      registry), so every hash is of the commit's tree (fable-9, codex-19).
    function _walkHash(IUARegistry reg, Tree storage t, Walk memory w) private view {
        uint256 n = 2 * w.leaves - 1;
        for (uint256 lv = 1; (1 << lv) <= w.leaves; ++lv) {
            uint256 h = 1 << (lv - 1);
            for (uint256 x = (1 << lv) - 1; x < n; x += 1 << (lv + 1)) {
                if (w.st[x] == 0) continue;
                w.th[x] = _thParent(w.kh[x], _thOf(reg, t, w, x - h), _thOf(reg, t, w, x + h));
            }
        }
        w.root = w.leaves == 1 ? _thOf(reg, t, w, 0) : w.th[w.leaves - 1]; // one leaf: its own th (F-5), as `_treeHash`
    }

    function _thOf(IUARegistry reg, Tree storage t, Walk memory w, uint256 x) private view returns (bytes32) {
        if (w.st[x] != 0) return w.th[x];
        return x & 1 == 0 ? _thLeaf(reg, t, x / 2) : t.nodeAt[x].hash;
    }

    /// @dev Completion steps 2-5's tree writes (spec §8) from the walk `w` of `d` (checked again in this transaction): the
    ///      Removes blank their leaves and free `liveKey`; each removed key into the set of its level judged after the Adds
    ///      (R16, C28: the group-wide set when its UA holds no leaf, else the pair set); a UA left with no leaf `gone` (kind
    ///      2, this epoch); the Adds; the path keys (`keys` the node keys' blob, 1,601 B each); every marked parent's `th`;
    ///      the size, the head, the admin list, `owed` 0; `_treeListedNew` for each UA listed for the first time.
    function _treeApply(bytes32 gid, Delta memory d, Walk memory w, bytes32 head, address keys) internal {
        Tree storage t = _tree(gid);
        for (uint256 i; i < d.removes.length; ++i) {
            IPqGroupTree.TreeRemove memory r = d.removes[i];
            bytes32 k = w.rmKem[i];
            GoneKey memory g = GoneKey(t.leafAt[r.leaf].joinEpoch, d.epoch, true);
            delete t.leafAt[r.leaf];
            t.liveKey[k] = 0;
            t.keysOf[r.ua].live -= 1;
            if (_liveAfter(t, w, r.ua) == 0) {
                t.goneKey[k] = g;
                if (t.gone[r.ua].kind == 0) t.gone[r.ua] = Gone(2, d.epoch);
            } else {
                t.goneOwnKey[r.ua][k] = g;
            }
        }
        for (uint256 i; i < d.adds.length; ++i) {
            IPqGroupTree.TreeAdd memory a = d.adds[i];
            t.leafAt[a.leaf] = Leaf(a.ua, a.keyId, d.epoch, uint32(i), true);
            t.liveKey[a.kemHash] = a.leaf + 1;
            Keys storage ks = t.keysOf[a.ua];
            if (!ks.listed) _treeListedNew(gid, a.ua);
            (ks.live, ks.listed) = (ks.live + 1, true);
        }
        for (uint256 x = 1; x < w.st.length; x += 2) {
            if (w.st[x] != 0) t.nodeAt[x] = Node(w.th[x], 0);
        }
        for (uint256 i; i < w.path.length; ++i) {
            t.nodeAt[w.path[i]].keyAt = uint160(keys) | (i * KEM_PK) << 160 | uint256(d.epoch) << 176;
        }
        (t.used, t.leaves, t.head, t.owed) = (uint32(w.used), uint32(w.leaves), head, 0);
        t.admins = d.admins;
    }

    /// @dev `ctTargets` packed, 4 B each, big-endian (the expected targets' hash, the list's blob).
    function _pack4(uint32[] memory a) internal pure returns (bytes memory b) {
        b = new bytes(4 * a.length);
        for (uint256 i; i < a.length; ++i) {
            uint32 v = a[i];
            assembly ("memory-safe") {
                let q := add(add(b, 32), mul(i, 4))
                mstore(
                    q,
                    or(shl(224, v), and(mload(q), 0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff))
                )
            }
        }
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
