// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IPqChat} from "./IPqChat.sol";
import {PqChatTypes} from "./PqChatTypes.sol";
import {PqChatCore} from "./PqChatCore.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {SSTORE2} from "../common/SSTORE2.sol";

/// @title `PqChatTree`: the body module of `PqChat`'s TreeKEM mode (`groupMode = 1`, CTR-CHAT-26, owner 2026-11-23: a new
///        DELEGATECALL body module), PqChat's entries over the shared tree of `PqGroupTree` (reached through `PqChatCore`).
/// @notice `PqChat` runs the mode-0 part of `createSession` (lists, keys, creator, signature, nonce, the record) and then
///         `treeCreate` here with its calldata; it forwards `addWraps` of a tree session. In the clone's context, so it reads
///         PqChat's state and env through the hooks; called directly it has no env (`PqChatEnv`). No `this`, `msg.sender`
///         unused, no guard of its own (`PqChat` holds none), its return and revert data forwarded verbatim. Plan
///         2026-11-23-pqchat-treekem T3a (the cold tree written with the wraps) and T3b (`commit`, its pieces, completion,
///         `treeLeave`, `treeRemove`, `postMessage`); the checks and the tree writes are `PqGroupTree`'s. **UNAUDITED.**
contract PqChatTree is PqChatCore {
    /// @notice The factory whose `PqChat` releases name this module (checked by the release's constructor).
    address public immutable FACTORY;

    constructor(address factory_) {
        FACTORY = factory_;
    }

    /// @notice The creation step of a tree session (spec §8), after `PqChat.createSession` checked and stored the record
    ///         under the same arguments: an `sstore2` home (C1), this instance the home (C4), the caps (C10, C24); `treeId`,
    ///         `used`, `leaves` and the admin list written; the creator alone joins `sessionsOf` (C34); then the wraps.
    function treeCreate(IPqChat.PqChatSession calldata s, IPqChat.Wrap[] calldata wraps, IUARegistry.UASig calldata)
        external
        returns (bytes32 sid)
    {
        (IUARegistry reg, uint256 limit,) = _env();
        if (_s().sigStore != SIG_SSTORE2) revert IPqChat.PqChatTreeSigStore();
        sid = PqChatTypes.sessionId(s.creator, s.nonce);
        Epoch storage ep = _s().epochs[sid];
        if (!ep.home) revert IPqChat.PqChatTreeHome();
        if (s.sealedInfo.length > TREE_INFO_MAX) revert IPqChat.PqChatShape();
        _treeOpen(sid, PqChatTypes.hashSession(s), s.members.length, s.admins);
        _s().sessions[s.creator].push(sid);
        _treeListed(sid, s.creator);
        _landTree(reg, sid, ep, 0, wraps, s.members, s.wrapHashes, limit);
    }

    /// @notice `PqChat.addWraps` of a tree session: the wraps of epoch 0 with their leaves (C15), or a commit's Welcome wraps
    ///         (`wraps[i]` names `adds[i]`).
    function addWraps(bytes32 epochId, uint32 first, IPqChat.Wrap[] calldata wraps) external {
        (IUARegistry reg, uint256 limit,) = _env();
        Epoch storage ep = _known(epochId);
        if (ep.epoch == 0) {
            (IPqChat.PqChatSession memory s,) = abi.decode(_get(ep.record), (IPqChat.PqChatSession, bytes32));
            _landTree(reg, epochId, ep, first, wraps, s.members, s.wrapHashes, limit);
            return;
        }
        IPqChat.PqChatCommit memory c = _staging(epochId, ep);
        _landWelcome(epochId, ep, c, first, wraps, limit);
        _done(reg, epochId, ep, c);
    }

    // ------------------------------------------------------------------ commit (spec §8)

    /// @notice A tree epoch (spec §6, §8): accepted when everything public about it holds on the head (R12), then the pieces
    ///         it carries; it completes here when it carries all, or has none.
    function commit(
        IPqChat.PqChatCommit calldata c,
        uint32[] calldata ctTargets,
        bytes32[] calldata ctHashes,
        bytes[] calldata nodeKeys,
        IPqChat.PathCt[] calldata cts,
        IPqChat.Wrap[] calldata wraps,
        IUARegistry.UASig calldata sig
    ) external returns (bytes32 eid) {
        eid = _accept(c, sig);
        _landFirst(eid, c, ctTargets, ctHashes, nodeKeys);
        _landRest(eid, c, cts, wraps);
    }

    /// @dev `commit`'s list and node keys, each whole or absent.
    function _landFirst(
        bytes32 eid,
        IPqChat.PqChatCommit calldata c,
        uint32[] calldata ctTargets,
        bytes32[] calldata ctHashes,
        bytes[] calldata nodeKeys
    ) internal {
        Epoch storage ep = _s().epochs[eid];
        if (ctTargets.length != 0 || ctHashes.length != 0) {
            _landList(eid, ep, c.ctCount, c.ctListHash, ctTargets, ctHashes);
        }
        if (nodeKeys.length != 0) _landKeys(eid, ep, c.nodeKeyHashes, nodeKeys);
    }

    /// @dev `commit`'s first chunks of ciphertexts and wraps, then the completion when nothing is missing.
    function _landRest(
        bytes32 eid,
        IPqChat.PqChatCommit calldata c,
        IPqChat.PathCt[] calldata cts,
        IPqChat.Wrap[] calldata wraps
    ) internal {
        (IUARegistry reg, uint256 limit,) = _env();
        Epoch storage ep = _s().epochs[eid];
        (IPqChat.PqChatCommit memory m,) = abi.decode(_get(ep.record), (IPqChat.PqChatCommit, bytes32));
        if (cts.length != 0) _landCts(eid, ep, 0, cts, limit);
        if (wraps.length != 0) _landWelcome(eid, ep, m, 0, wraps, limit);
        _done(reg, eid, ep, m);
    }

    /// @notice The list of a staged commit, whole, once (C14).
    function addPathList(bytes32 epochId, uint32[] calldata ctTargets, bytes32[] calldata ctHashes) external {
        (IUARegistry reg,,) = _env();
        Epoch storage ep = _known(epochId);
        IPqChat.PqChatCommit memory c = _staging(epochId, ep);
        _landList(epochId, ep, c.ctCount, c.ctListHash, ctTargets, ctHashes);
        _done(reg, epochId, ep, c);
    }

    /// @notice The node keys of a staged commit, whole, once.
    function addPathKeys(bytes32 epochId, bytes[] calldata nodeKeys) external {
        (IUARegistry reg,,) = _env();
        Epoch storage ep = _known(epochId);
        IPqChat.PqChatCommit memory c = _staging(epochId, ep);
        _landKeys(epochId, ep, c.nodeKeyHashes, nodeKeys);
        _done(reg, epochId, ep, c);
    }

    /// @notice Ciphertexts `firstCt..` of a staged commit, after its list.
    function addPath(bytes32 epochId, uint32 firstCt, IPqChat.PathCt[] calldata cts) external {
        (IUARegistry reg, uint256 limit,) = _env();
        Epoch storage ep = _known(epochId);
        IPqChat.PqChatCommit memory c = _staging(epochId, ep);
        _landCts(epochId, ep, firstCt, cts, limit);
        _done(reg, epochId, ep, c);
    }

    /// @dev The acceptance of spec §8: the session's tree and home (C16), the head (`_parentOf`, its tree hash: C31), the
    ///      signature and the nonce, the record's shapes (C24), the tree of the commit in memory (`_treeCheck`); then the
    ///      record with its signature in state, `wraps` = pieces + 1 (C20), the expected targets' hash.
    function _accept(IPqChat.PqChatCommit calldata c, IUARegistry.UASig calldata sig) internal returns (bytes32 eid) {
        (IUARegistry reg, uint256 limit,) = _env();
        Tree storage t = _treeOf(c.sessionId);
        if (c.treeId != t.treeId) revert IPqChat.PqChatTreeHome();
        _parentOf(c.parentEpochId, c.sessionId, c.epoch);
        bytes32 stored = _treeHash(reg, t);
        if (c.parentTreeHash != stored) revert IPqChat.PqChatTreeParent(stored);
        _auth(reg, c.author, PqChatTypes.hashCommit(c), sig);
        _useNonce(PqChatTypes.scopeEpoch(c.sessionId, c.author), c.nonce);
        if (
            c.wrapHashes.length != c.adds.length || c.sealedInfo.length == 0 || c.sealedInfo.length > TREE_INFO_MAX
                || (c.ctCount == 0 && c.ctListHash != EMPTY_PATH_LIST)
        ) revert IPqChat.PqChatShape();
        bytes memory b = _blob(abi.encode(c), sig);
        (IPqChat.PqChatCommit memory m,) = abi.decode(b, (IPqChat.PqChatCommit, bytes32));
        Walk memory w = _treeCheck(reg, c.sessionId, _delta(m), false);
        eid = PqChatTypes.epochId(c.sessionId, c.author, c.nonce);
        Epoch storage ep = _s().epochs[eid];
        (ep.sessionId, ep.parent, ep.epoch) = (c.sessionId, c.parentEpochId, c.epoch);
        ep.record = _put(b, limit);
        ep.wraps = uint32((c.ctCount == 0 ? 0 : 2 + uint256(c.ctCount)) + c.adds.length + 1);
        _staged(eid).targetsHash = keccak256(_pack4(w.targets));
        emit IPqChat.PqChatEpochAdded(c.sessionId, eid, c.parentEpochId, c.epoch, c.author);
    }

    /// @dev `hashStruct(PathList)` of two empty arrays (codex-r2-14): `keccak256(abi.encode(PATH_LIST_TYPEHASH,
    ///      keccak256(""), keccak256("")))`, pinned against the vectors' `digests.emptyPathList`.
    bytes32 internal constant EMPTY_PATH_LIST = 0x314f8c453563644126ee2ba7f65398ffecccac5e0b863019a52ec0f677f605da;

    function _delta(IPqChat.PqChatCommit memory c) internal pure returns (Delta memory d) {
        (d.author, d.leaf, d.keyId, d.leaves, d.epoch) = (c.author, c.leaf, c.keyId, c.leaves, c.epoch);
        (d.admins, d.removes, d.adds) = (c.admins, c.removes, c.adds);
        (d.nodeKeyHashes, d.ctCount, d.treeHash) = (c.nodeKeyHashes, c.ctCount, c.treeHash);
    }

    /// @dev The record of a staged tree epoch whose slot is still free (`PqChatEpochTaken`).
    function _staging(bytes32 epochId, Epoch storage ep) internal view returns (IPqChat.PqChatCommit memory c) {
        if (!_isTree(ep.sessionId)) revert IPqChat.PqChatModeEntry(0);
        _slotFree(ep, epochId);
        (c,) = abi.decode(_get(ep.record), (IPqChat.PqChatCommit, bytes32));
    }

    // ------------------------------------------------------------------ the pieces (§7, §8)

    /// @dev The list: `ctCount` entries each, its `hashStruct` the signed `ctListHash`, its targets the walk's; one blob of
    ///      `ctTargets` (4 B each) then `ctHashes`.
    function _landList(
        bytes32 eid,
        Epoch storage ep,
        uint256 n,
        bytes32 ctListHash,
        uint32[] calldata ctTargets,
        bytes32[] calldata ctHashes
    ) internal {
        Staged storage g = _staged(eid);
        if (
            n == 0 || g.list != address(0) || ctTargets.length != n || ctHashes.length != n
                || PqChatTypes.hashPathList(ctTargets, ctHashes) != ctListHash
        ) revert IPqChat.PqChatPathList(eid);
        bytes memory tb = _pack4(ctTargets);
        if (keccak256(tb) != g.targetsHash) revert IPqChat.PqChatTreeTargets(n);
        g.list = SSTORE2.write(bytes.concat(tb, abi.encodePacked(ctHashes)));
        ++ep.landed;
        emit IPqChat.PqChatPath(eid, 1, 0, uint32(n));
    }

    /// @dev The node keys: one per signed hash, 1,601 B, admitted (C19); one blob.
    function _landKeys(bytes32 eid, Epoch storage ep, bytes32[] memory nodeKeyHashes, bytes[] calldata nodeKeys)
        internal
    {
        Staged storage g = _staged(eid);
        uint256 m = nodeKeyHashes.length;
        if (m == 0 || nodeKeys.length != m) revert IPqChat.PqChatShape();
        if (g.keys != address(0)) revert IPqChat.PqChatPathStored(eid, 0);
        bytes memory buf;
        for (uint256 k; k < m; ++k) {
            bytes calldata nk = nodeKeys[k];
            if (nk.length != KEM_PK || keccak256(nk) != nodeKeyHashes[k]) revert IPqChat.PqChatPathHash(eid, k);
            if (!_admissible(nk)) revert IPqChat.PqChatKemKey(eid, uint64(k));
            buf = bytes.concat(buf, nk);
        }
        g.keys = SSTORE2.write(buf);
        ++ep.landed;
        emit IPqChat.PqChatPath(eid, 2, 0, uint32(m));
    }

    /// @dev Ciphertexts `first..`, each against `ctHashes` of the landed list, once; packed 1,648 B each, as many per blob
    ///      as the chain's limit holds, one slot each.
    function _landCts(bytes32 eid, Epoch storage ep, uint256 first, IPqChat.PathCt[] calldata cts, uint256 limit)
        internal
    {
        address list = _staged(eid).list;
        if (list == address(0)) revert IPqChat.PqChatPathList(eid);
        uint256 n = cts.length;
        if (first + n > (list.code.length - 1) / 36) revert IPqChat.PqChatShape();
        uint256 per = (_codeCap(limit) - 1) / PATH_CT;
        for (uint256 j; j < n; j += per) {
            _ctBlob(eid, list, first, cts, j, n - j < per ? n : j + per);
        }
        ep.landed += uint32(n);
        emit IPqChat.PqChatPath(eid, 3, uint32(first), uint32(n));
    }

    /// @dev One blob of `cts[from..to)`, indices `first + from..`, each against its hash in `list`, once.
    function _ctBlob(bytes32 eid, address list, uint256 first, IPqChat.PathCt[] calldata cts, uint256 from, uint256 to)
        private
    {
        Staged storage g = _staged(eid);
        uint256 total = (list.code.length - 1) / 36;
        bytes memory buf = new bytes((to - from) * PATH_CT);
        for (uint256 q = from; q < to; ++q) {
            uint256 i = first + q;
            IPqChat.PathCt calldata ct = cts[q];
            if (
                ct.mlkemCt.length != MLKEM_CT || ct.sealedSecret.length != SEALED_KEY
                    || PqChatTypes.hashPathCt(ct) != bytes32(SSTORE2.read(list, 4 * total + 32 * i, 32))
            ) revert IPqChat.PqChatPathHash(eid, i);
            if (g.ctAt[i] != 0) revert IPqChat.PqChatPathStored(eid, i);
            _packCt(buf, (q - from) * PATH_CT, ct);
        }
        uint256 ptr = uint160(SSTORE2.write(buf));
        for (uint256 q = from; q < to; ++q) {
            g.ctAt[first + q] = ptr | ((q - from) * PATH_CT) << 160;
        }
    }

    function _packCt(bytes memory buf, uint256 off, IPqChat.PathCt calldata ct) private pure {
        bytes calldata a = ct.mlkemCt;
        bytes calldata b = ct.sealedSecret;
        bytes32 x = ct.x25519Eph;
        assembly ("memory-safe") {
            let q := add(add(buf, 32), off)
            calldatacopy(q, a.offset, 1568)
            mstore(add(q, 1568), x)
            calldatacopy(add(q, 1600), b.offset, 48)
        }
    }

    /// @dev Welcome wraps `first..` as mode 0's against `adds[i]` and `wrapHashes[i]`.
    function _landWelcome(
        bytes32 eid,
        Epoch storage ep,
        IPqChat.PqChatCommit memory c,
        uint256 first,
        IPqChat.Wrap[] calldata wraps,
        uint256 limit
    ) internal {
        IPqChat.MemberKey[] memory mk = new IPqChat.MemberKey[](c.adds.length);
        for (uint256 i; i < mk.length; ++i) {
            mk[i] = IPqChat.MemberKey(c.adds[i].ua, c.adds[i].keyId, c.adds[i].via);
        }
        _storeWraps(eid, ep, first, wraps, mk, c.wrapHashes, limit);
        ep.landed += uint32(wraps.length);
        emit IPqChat.PqChatWraps(eid, uint32(first), uint32(wraps.length));
    }

    /// @dev Completion (spec §8 steps 1-5), when every piece has landed: step 1 (a gone UA keeps no leaf, sits in no admin
    ///      list and authored nothing: `PqChatRemovedKept`) and the walk again on the same head, the tree writes, the new
    ///      UAs in `sessionsOf`, the slot, `epochsOf`, `landed == wraps`.
    function _done(IUARegistry reg, bytes32 eid, Epoch storage ep, IPqChat.PqChatCommit memory c) internal {
        if (ep.landed + 1 != ep.wraps) return;
        Delta memory d = _delta(c);
        Walk memory w = _treeCheck(reg, c.sessionId, d, true);
        _treeApply(c.sessionId, d, w, eid, _staged(eid).keys);
        ep.landed = ep.wraps;
        _s().childOf[ep.parent] = eid; // the slot (a tree session is at its home, C4)
        _s().chain[c.sessionId].push(eid); // `epochsOf`
        emit IPqChat.PqChatEpochComplete(eid);
    }

    // ------------------------------------------------------------------ leave, removal, messages (§9)

    /// @dev The head of a tree session named by `epochId`: stored, of `sid`, complete, no child (C9, C20).
    function _head(bytes32 sid, bytes32 epochId) internal view returns (Epoch storage ep) {
        ep = _known(epochId);
        if (ep.sessionId != sid) revert IPqChat.PqChatUnknown(epochId);
        if (ep.landed != ep.wraps) revert IPqChat.PqChatIncomplete(epochId);
        bytes32 child = _s().childOf[epochId];
        if (child != 0) revert IPqChat.PqChatEpochTaken(epochId, child);
    }

    /// @notice C9, C21, C28, C38: a live member leaves at the head; it is `gone` (kind 1) and its leaves are owed. The record
    ///         that closes a session is accepted.
    function treeLeave(IPqChat.PqChatTreeLeave calldata l, IUARegistry.UASig calldata sig) external {
        (IUARegistry reg, uint256 limit,) = _env();
        Tree storage t = _treeOf(l.sessionId);
        if (l.treeId != t.treeId) revert IPqChat.PqChatTreeHome();
        Epoch storage ep = _head(l.sessionId, l.epochId);
        if (!_treeMember(t, l.member)) revert IPqChat.PqChatNotMember(l.member);
        _auth(reg, l.member, PqChatTypes.hashTreeLeave(l), sig);
        _useNonce(PqChatTypes.scopeEpoch(l.sessionId, l.member), l.nonce);
        _treeGo(l.sessionId, l.member, 1, ep.epoch);
        ep.left[l.member] = true;
        _s().leaves[l.epochId].push(_put(abi.encode(l, keccak256(abi.encode(sig)), sig), limit));
        emit IPqChat.PqChatLeft(l.sessionId, l.epochId, l.member);
    }

    /// @notice C9, C21, C24, C28, C38: a live admin of the head removes members or admins (strictly sorted); they are
    ///         `gone` (kind 2) and their leaves are owed; an admin with a live leaf remains while any member keeps a leaf.
    ///         The record that closes a session is accepted.
    function treeRemove(IPqChat.PqChatTreeRemove calldata r, IUARegistry.UASig calldata sig) external {
        (IUARegistry reg, uint256 limit,) = _env();
        Tree storage t = _treeOf(r.sessionId);
        if (r.treeId != t.treeId) revert IPqChat.PqChatTreeHome();
        Epoch storage ep = _head(r.sessionId, r.epochId);
        if (r.nextEpoch != ep.epoch + 1) revert IPqChat.PqChatEpochNumber(ep.epoch + 1, r.nextEpoch);
        if (!_treeAdmin(t, r.admin)) revert IPqChat.PqChatNotAdmin(r.admin);
        uint256 n = r.members.length;
        if (n == 0) revert IPqChat.PqChatShape();
        for (uint256 i; i < n; ++i) {
            bytes32 u = r.members[i];
            if (i > 0 && u <= r.members[i - 1]) revert IPqChat.PqChatShape();
            if (t.keysOf[u].live == 0 && !_in(t.admins, u)) revert IPqChat.PqChatNotMember(u);
        }
        _auth(reg, r.admin, PqChatTypes.hashTreeRemove(r), sig);
        _useNonce(PqChatTypes.scopeEpoch(r.sessionId, r.admin), r.nonce);
        bool leafy = _treeLeafyAdmin(t);
        for (uint256 i; i < n; ++i) {
            _treeGo(r.sessionId, r.members[i], 2, ep.epoch);
            ep.removedOf[r.members[i]] = true;
        }
        // C24 read with C38 (CTR-CHAT-27 Change 2026-11-24): refused only while a member that is not gone keeps a leaf
        if (leafy && !_treeLeafyAdmin(t) && _treeHasMember(t)) revert IPqChat.PqChatTreeAdmins();
        _s().removals[r.epochId].push(_put(_blob(abi.encode(r), sig), limit));
        emit IPqChat.PqChatRemoved(r.sessionId, r.epochId, r.admin, r.members);
    }

    /// @notice `PqChat.postMessage` of a tree session: the sender a live member at the head.
    function postMessage(IPqChat.PqChatMessage calldata m, IUARegistry.UASig calldata sig)
        external
        returns (uint256 index)
    {
        (IUARegistry reg, uint256 limit,) = _env();
        _head(m.sessionId, m.epochId);
        if (!_treeMember(_tree(m.sessionId), m.sender)) revert IPqChat.PqChatNotMember(m.sender);
        index = _post(reg, limit, m, sig);
    }

    /// @dev Wraps `first..` of epoch 0 as mode 0's (`_land`); then leaf `i` = `members[i]` for each, its key admitted and not
    ///      live, and the UA in `sessionsOf` at its first key (C15, C34); at completion the genesis tree hash.
    function _landTree(
        IUARegistry reg,
        bytes32 sid,
        Epoch storage ep,
        uint256 first,
        IPqChat.Wrap[] calldata wraps,
        IPqChat.MemberKey[] memory members,
        bytes32[] memory hashes,
        uint256 limit
    ) internal {
        _storeWraps(sid, ep, first, wraps, members, hashes, limit); // `_land` without the flat completion (P48)
        uint32 landed = ep.landed + uint32(wraps.length);
        ep.landed = landed;
        bool complete = landed == ep.wraps && wraps.length != 0;
        for (uint256 j; j < wraps.length; ++j) {
            uint256 i = first + j;
            if (_treeSetLeaf(reg, sid, i, members[i].ua, members[i].keyId, 0, uint32(i))) {
                _s().sessions[members[i].ua].push(sid);
            }
        }
        emit IPqChat.PqChatWraps(sid, uint32(first), uint32(wraps.length));
        if (complete) {
            _treeGenesis(reg, sid, sid);
            emit IPqChat.PqChatEpochComplete(sid);
        }
    }

    function _fail(uint8 code, uint256 a, uint256 b) internal pure override {
        _chatFail(code, a, b);
    }
}
