// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IPqChat} from "./IPqChat.sol";
import {PqChatTypes} from "./PqChatTypes.sol";
import {PqChatCore} from "./PqChatCore.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {UAKinds} from "../ua/UAKinds.sol";

/// @title `PqChatTopics`: the body module of `PqChat` (CTR-TOK-30; plan 3c 3C-D2: the release passed the 33,594 B line at
///        34,223 B): the public topics and votes (topics spec, D18-D22), each entry with `IPqChat`'s signature. `PqChat`
///        forwards these entries' calldata to it by `DELEGATECALL`, so it runs in the clone's state and env; called directly
///        it has no env (`PqChatEnv`) and an empty state. One module per release, pinned in the class env's `libs` (its
///        code hash checked by the factory at `deployImplementation`) and named in the release's `implArgs`. **UNAUDITED.**
contract PqChatTopics is PqChatCore {
    /// @notice The factory whose `PqChat` releases name this module (checked by the release's constructor).
    address public immutable FACTORY;

    /// @notice The largest topic `name`, in bytes, of `createTopic` and `updateTopic` (owner 2026-11-10: 128 -> 512).
    uint256 internal constant NAME_MAX = 512;

    constructor(address factory_) {
        FACTORY = factory_;
    }

    // ------------------------------------------------------------------ public topics

    /// @notice P41: any UA the registry verifies; `homeChain`, `homeChatContract` not zero; `name` 1-512 B (owner 2026-11-10;
    ///         was 1-128 B).
    function createTopic(IPqChat.PqTopic calldata t, IUARegistry.UASig calldata sig) external returns (bytes32 tid) {
        (IUARegistry reg, uint256 limit,) = _env();
        uint256 nl = bytes(t.name).length;
        if (nl == 0 || nl > NAME_MAX || t.homeChain == 0 || t.homeChatContract == address(0)) revert IPqChat.PqTopicShape();
        _auth(reg, t.admin, PqChatTypes.hashTopic(t), sig);
        _useNonce(PqChatTypes.scopeTopic(t.admin), t.nonce);
        tid = PqChatTypes.topicId(t.admin, t.nonce);
        S storage s = _s();
        Topic storage tp = s.topics[tid];
        (tp.admin, tp.openReplies) = (t.admin, t.openReplies);
        tp.record = _put(abi.encode(t, keccak256(abi.encode(sig))), limit);
        s.allTopics.push(tid);
        s.topicsByAdmin[t.admin].push(tid);
        emit IPqChat.PqTopicCreated(tid, t.admin);
    }

    /// @notice P41: by the topic's admin, `seq == stored + 1` (P36); `name` 1-512 B.
    function updateTopic(IPqChat.PqTopicUpdate calldata u, IUARegistry.UASig calldata sig) external {
        (IUARegistry reg, uint256 limit,) = _env();
        Topic storage tp = _topic(u.topicId);
        if (u.seq != tp.seq + 1) revert IPqChat.PqTopicSeq(tp.seq + 1, u.seq);
        uint256 nl = bytes(u.name).length;
        if (nl == 0 || nl > NAME_MAX) revert IPqChat.PqTopicShape();
        _adminAuth(reg, tp.admin, PqChatTypes.hashTopicUpdate(u), sig);
        (tp.seq, tp.openReplies) = (u.seq, u.openReplies);
        tp.latest = _put(abi.encode(u, keccak256(abi.encode(sig))), limit);
        emit IPqChat.PqTopicUpdated(u.topicId, u.seq);
    }

    /// @notice P41: by the topic's admin, `seq == stored + 1` per `(topicId, writer)`, the writer not the admin.
    function setTopicWriter(IPqChat.PqTopicWriter calldata w, IUARegistry.UASig calldata sig) external {
        (IUARegistry reg,,) = _env();
        Topic storage tp = _topic(w.topicId);
        if (w.writer == tp.admin || w.writer == 0) revert IPqChat.PqTopicShape();
        Writer storage wr = _s().writers[w.topicId][w.writer];
        if (w.seq != wr.seq + 1) revert IPqChat.PqTopicSeq(wr.seq + 1, w.seq);
        _adminAuth(reg, tp.admin, PqChatTypes.hashTopicWriter(w), sig);
        if (wr.seq == 0) _s().writersOf[w.topicId].push(w.writer); // its first record only
        (wr.granted, wr.seq) = (w.granted, w.seq);
        emit IPqChat.PqTopicWriterSet(w.topicId, w.writer, w.granted, w.seq);
    }

    /// @notice P37, P41: a post by the admin or a writer; a reply to an entry of the same topic here, by anyone while
    ///         `openReplies`, else by the admin or a writer; `ref` all zero or `chainUid`, `pqchat`, `entryId` set.
    function postEntry(IPqChat.PqTopicEntry calldata e, IUARegistry.UASig calldata sig) external returns (bytes32 eid) {
        (IUARegistry reg, uint256 limit,) = _env();
        uint32 depth = _entryRights(e);
        _entryShape(e.ref, e.mediaType, e.body);
        _auth(reg, e.author, PqChatTypes.hashEntry(e), sig);
        _useNonce(PqChatTypes.scopeEntry(e.topicId, e.author), e.nonce);
        eid = PqChatTypes.entryId(e.topicId, e.author, e.nonce);
        S storage s = _s();
        s.entries[eid] = Entry(_put(abi.encode(e, keccak256(abi.encode(sig))), limit), depth);
        if (e.parentId == 0) s.posts[e.topicId].push(eid);
        else s.replies[e.parentId].push(eid);
        s.byAuthor[e.author].push(eid);
        emit IPqChat.PqTopicEntryPosted(e.topicId, eid, e.parentId, e.author, sig);
    }

    function _entryRights(IPqChat.PqTopicEntry calldata e) internal view returns (uint32 depth) {
        Topic storage tp = _topic(e.topicId);
        if (e.parentId != 0) {
            Entry storage pe = _s().entries[e.parentId];
            if (pe.record == address(0) || _word(pe.record, 64) != e.topicId) revert IPqChat.PqTopicParent(e.parentId);
            depth = pe.depth + 1;
            if (tp.openReplies) return depth;
        }
        if (e.author != tp.admin && !_s().writers[e.topicId][e.author].granted) revert IPqChat.PqTopicNotWriter(e.author);
    }

    function _entryShape(IPqChat.EntryRef calldata r, string calldata mediaType, bytes calldata body) internal pure {
        uint256 ml = bytes(mediaType).length;
        if (ml == 0 || ml > 64 || body.length == 0) revert IPqChat.PqTopicShape();
        bool none = r.chainUid == 0 && r.pqchat == address(0) && r.entryId == 0 && r.contentHash == 0;
        if (!none && (r.chainUid == 0 || r.pqchat == address(0) || r.entryId == 0)) revert IPqChat.PqTopicRef();
    }

    /// @notice P38: a new version of an existing entry by its author, `version == count + 1`, the nonce in the original's
    ///         topic scope.
    function editEntry(IPqChat.PqTopicEdit calldata d, IUARegistry.UASig calldata sig) external {
        (IUARegistry reg, uint256 limit,) = _env();
        address original = _s().entries[d.entryId].record;
        if (original == address(0)) revert IPqChat.PqTopicUnknown(d.entryId);
        if (_word(original, 96) != d.author) revert IPqChat.PqTopicNotAuthor(d.author);
        address[] storage vs = _s().versions[d.entryId];
        uint32 next = uint32(vs.length) + 2;
        if (d.version != next) revert IPqChat.PqTopicVersion(next, d.version);
        uint256 ml = bytes(d.mediaType).length;
        if (ml == 0 || ml > 64 || d.body.length == 0) revert IPqChat.PqTopicShape();
        _auth(reg, d.author, PqChatTypes.hashEdit(d), sig);
        _useNonce(PqChatTypes.scopeEntry(_word(original, 64), d.author), d.nonce);
        vs.push(_put(abi.encode(d, keccak256(abi.encode(sig))), limit));
        emit IPqChat.PqTopicEntryEdited(d.entryId, d.version, sig);
    }

    /// @notice P40, D21: one slot per (entry, voter UA), `seq == stored + 1`; a new value moves the counts (old - 1, new + 1).
    function voteEntry(IPqChat.PqTopicVote calldata v, IUARegistry.UASig calldata sig) external {
        (IUARegistry reg,,) = _env();
        if (_s().entries[v.entryId].record == address(0)) revert IPqChat.PqTopicUnknown(v.entryId);
        if (v.value < -1 || v.value > 1) revert IPqChat.PqTopicVoteValue(v.value);
        Vote storage vt = _s().votes[v.entryId][v.voter];
        if (v.seq != vt.seq + 1) revert IPqChat.PqTopicSeq(vt.seq + 1, v.seq);
        _auth(reg, v.voter, PqChatTypes.hashVote(v), sig);
        Score storage sc = _s().scores[v.entryId];
        if (vt.value == 1) --sc.up;
        else if (vt.value == -1) --sc.down;
        if (v.value == 1) ++sc.up;
        else if (v.value == -1) ++sc.down;
        (vt.value, vt.seq) = (v.value, v.seq);
        emit IPqChat.PqTopicVoted(v.entryId, v.voter, v.value, v.seq);
    }

    function topicOf(bytes32 topicId) external view returns (IPqChat.PqTopic memory t, uint64 seq) {
        Topic storage tp = _topic(topicId);
        (t,) = abi.decode(_get(tp.record), (IPqChat.PqTopic, bytes32));
        if (tp.latest != address(0)) {
            (IPqChat.PqTopicUpdate memory u,) = abi.decode(_get(tp.latest), (IPqChat.PqTopicUpdate, bytes32));
            (t.name, t.about, t.openReplies) = (u.name, u.about, u.openReplies);
        }
        seq = tp.seq;
    }

    function entryOf(bytes32 entryId) external view returns (IPqChat.EntryView memory v) {
        Entry storage en = _s().entries[entryId];
        if (en.record == address(0)) revert IPqChat.PqTopicUnknown(entryId);
        (IPqChat.PqTopicEntry memory e, bytes32 sh) = abi.decode(_get(en.record), (IPqChat.PqTopicEntry, bytes32));
        address[] storage vs = _s().versions[entryId];
        (v.topicId, v.author, v.parentId, v.depth, v.ref) = (e.topicId, e.author, e.parentId, en.depth, e.ref);
        (v.mediaType, v.body, v.sigHash, v.versionCount) = (e.mediaType, e.body, sh, uint32(vs.length) + 1);
        if (vs.length != 0) {
            (IPqChat.PqTopicEdit memory d, bytes32 dh) = abi.decode(_get(vs[vs.length - 1]), (IPqChat.PqTopicEdit, bytes32));
            (v.mediaType, v.body, v.sigHash) = (d.mediaType, d.body, dh);
        }
    }

    function versionAt(bytes32 entryId, uint32 version)
        external view returns (string memory mediaType, bytes memory body, bytes32 sigHash)
    {
        address original = _s().entries[entryId].record;
        if (original == address(0)) revert IPqChat.PqTopicUnknown(entryId);
        address[] storage vs = _s().versions[entryId];
        if (version == 0 || version > vs.length + 1) revert IPqChat.PqTopicVersion(uint32(vs.length) + 1, version);
        if (version == 1) {
            (IPqChat.PqTopicEntry memory e, bytes32 sh) = abi.decode(_get(original), (IPqChat.PqTopicEntry, bytes32));
            return (e.mediaType, e.body, sh);
        }
        (IPqChat.PqTopicEdit memory d, bytes32 dh) = abi.decode(_get(vs[version - 2]), (IPqChat.PqTopicEdit, bytes32));
        return (d.mediaType, d.body, dh);
    }

    function writerOf(bytes32 topicId, bytes32 ua) external view returns (bool granted, uint64 seq) {
        Writer storage w = _s().writers[topicId][ua];
        return (w.granted, w.seq);
    }

    function scoreOf(bytes32 entryId) external view returns (uint128 up, uint128 down) {
        Score storage sc = _s().scores[entryId];
        return (sc.up, sc.down);
    }

    function voteOf(bytes32 entryId, bytes32 ua) external view returns (int8 value, uint64 seq) {
        Vote storage vt = _s().votes[entryId][ua];
        return (vt.value, vt.seq);
    }

    function topics(uint256 start, uint256 count) external view returns (bytes32[] memory, uint256) {
        return _page(_s().allTopics, start, count);
    }

    function topicsByAdmin(bytes32 admin_, uint256 start, uint256 count) external view returns (bytes32[] memory, uint256) {
        return _page(_s().topicsByAdmin[admin_], start, count);
    }

    function writersOf(bytes32 topicId, uint256 start, uint256 count) external view returns (bytes32[] memory, uint256) {
        return _page(_s().writersOf[topicId], start, count);
    }

    function posts(bytes32 topicId, uint256 start, uint256 count) external view returns (bytes32[] memory, uint256) {
        return _page(_s().posts[topicId], start, count);
    }

    function replies(bytes32 parentId, uint256 start, uint256 count) external view returns (bytes32[] memory, uint256) {
        return _page(_s().replies[parentId], start, count);
    }

    function byAuthor(bytes32 author, uint256 start, uint256 count) external view returns (bytes32[] memory, uint256) {
        return _page(_s().byAuthor[author], start, count);
    }

    function topicNonceUsed(bytes32 admin_, uint64 nonce) external view returns (bool) {
        return _nonceUsed(PqChatTypes.scopeTopic(admin_), nonce);
    }

    function entryNonceUsed(bytes32 topicId, bytes32 author, uint64 nonce) external view returns (bool) {
        return _nonceUsed(PqChatTypes.scopeEntry(topicId, author), nonce);
    }

    /// @dev P42: at most `count` ids from `start`, fewer at the end, empty past it; and the list's length.
    function _page(bytes32[] storage l, uint256 start, uint256 count)
        internal view returns (bytes32[] memory page, uint256 total)
    {
        total = l.length;
        if (start >= total) return (page, total);
        uint256 end = total - start > count ? start + count : total;
        page = new bytes32[](end - start);
        for (uint256 i; i < page.length; ++i) page[i] = l[start + i];
    }

    function _topic(bytes32 topicId) internal view returns (Topic storage tp) {
        tp = _s().topics[topicId];
        if (tp.admin == 0) revert IPqChat.PqTopicUnknown(topicId);
    }

    /// @dev A record a topic's admin signs without naming itself (`PqTopicUpdate`, `PqTopicWriter`): any other signer's
    ///      refusal by the registry is `PqTopicNotAdmin` (P41); every other revert (a starved verifier) bubbles.
    function _adminAuth(IUARegistry reg, bytes32 admin_, bytes32 structHash, IUARegistry.UASig calldata sig) internal view {
        try reg.requirePortable(admin_, UAKinds.PURPOSE_PQCHAT, PqChatTypes.typed(structHash), sig) {}
        catch (bytes memory err) {
            if (bytes4(err) == IUARegistry.UAUnauthorized.selector) revert IPqChat.PqTopicNotAdmin(admin_);
            assembly ("memory-safe") {
                revert(add(err, 32), mload(err))
            }
        }
    }
}
