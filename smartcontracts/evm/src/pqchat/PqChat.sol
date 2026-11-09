// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IPqChat} from "./IPqChat.sol";
import {PqChatTypes} from "./PqChatTypes.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {UAKinds} from "../ua/UAKinds.sol";
import {IOpenFactory} from "../factory/IOpenFactory.sol";
import {IFactoryToken} from "../factory/IFactoryToken.sol";
import {ChainEnvCode} from "../factory/ChainEnvCode.sol";
import {SSTORE2} from "../common/SSTORE2.sol";

/// @title `PqChat` (UA-7, CTR-CHAT-01; D22: class 3, kind 0 on the factory's generic path): sessions, epochs in chunks, the
///        home-instance slot, admins, leave, on-chain and stored messages, public topics and votes.
/// @notice One release, many EIP-1167 clones; each clone reads its chain values from its own code (`ChainEnv`, 3C-D1): the
///         registry, `chain_uid`, the code-size limit `params[0]`. State in the ERC-7201 namespace `scaas.pqchat`.
///         Records are stored in SSTORE2 blobs (3C-D3), never only in an event. **UNAUDITED.**
contract PqChat is IPqChat {
    uint16 internal constant CLASS = 3;
    uint16 internal constant KIND = 0;
    /// @notice EIP-170's limit, the smallest of any EVM chain (3C-D1).
    uint256 internal constant MIN_CODE_LIMIT = 24_576;
    uint256 internal constant MLKEM_CT = 1568;
    uint256 internal constant SEALED_KEY = 48;
    /// @notice A packed wrap: member (32) ‖ keyId (8) ‖ mlkemCt (1,568) ‖ x25519Eph (32) ‖ sealedKey (48).
    uint256 internal constant WRAP_BYTES = 1688;
    /// @inheritdoc IPqChat
    uint256 public constant STORED_RANGE_MAX = 16;
    /// @inheritdoc IPqChat
    uint256 public constant SESSIONS_RANGE_MAX = 128;
    /// @inheritdoc IPqChat
    uint256 public constant EPOCHS_RANGE_MAX = 128;

    address public immutable FACTORY;
    uint64 internal immutable VERSION;

    struct Epoch {
        bytes32 sessionId; // 0 = unknown
        address record; // head blob of abi.encode(record, sigHash)
        uint64 epoch;
        uint32 wraps;
        uint32 landed;
        bool home; // epoch 0 only: this instance is the session's home (P32)
        bytes32 parent;
        mapping(uint256 => uint256) wrapAt; // pointer | offset << 160
        mapping(bytes32 => bool) left;
    }

    struct Topic {
        bytes32 owner; // 0 = unknown
        address record; // the create record's head blob
        uint64 seq;
        bool openReplies;
        address latest; // the latest update's head blob, 0 before one
    }

    struct Entry {
        address record; // the original's head blob; 0 = unknown
        uint32 depth;
    }

    struct Vote {
        int8 value;
        uint64 seq;
    }

    struct Writer {
        bool granted;
        uint64 seq;
    }

    struct Score {
        uint128 up;
        uint128 down;
    }

    /// @custom:storage-location erc7201:scaas.pqchat
    struct S {
        bytes32 ownerUA;
        bool initialized;
        mapping(bytes32 => Epoch) epochs;
        mapping(bytes32 => bytes32) childOf;
        mapping(bytes32 => mapping(uint256 => uint256)) nonces;
        mapping(bytes32 => address[]) messages;
        mapping(bytes8 => address[]) stored;
        mapping(bytes32 => Topic) topics;
        mapping(bytes32 => mapping(bytes32 => Writer)) writers;
        mapping(bytes32 => Entry) entries;
        mapping(bytes32 => address[]) versions;
        mapping(bytes32 => mapping(bytes32 => Vote)) votes;
        mapping(bytes32 => Score) scores;
        bytes32[] allTopics;
        mapping(bytes32 => bytes32[]) topicsByOwner;
        mapping(bytes32 => bytes32[]) writersOf;
        mapping(bytes32 => bytes32[]) posts;
        mapping(bytes32 => bytes32[]) replies;
        mapping(bytes32 => bytes32[]) byAuthor;
        mapping(bytes32 => bytes32[]) sessions; // per UA (owner 2026-11-10)
        mapping(bytes32 => bytes32[]) chain; // per session: its epochs >= 1 in completion order (epoch 0 implied)
    }

    /// @dev `keccak256(abi.encode(uint256(keccak256("scaas.pqchat")) - 1)) & ~bytes32(uint256(0xff))`.
    bytes32 internal constant SLOT = 0xc7b36804b17476e9a19a6ebc690cd7b9326d322c515fd7dc91373f9bc6dc3000;

    function _s() internal pure returns (S storage s) {
        assembly ("memory-safe") {
            s.slot := SLOT
        }
    }

    /// @notice `(ReleaseId, factory_, implArgs)` (topics spec §11); `implArgs` empty. The implementation is locked.
    constructor(IOpenFactory.ReleaseId memory id, address factory_, bytes memory) {
        if (id.contractClass != CLASS || id.kind != KIND || id.version == 0 || factory_ == address(0)) revert PqChatEnv();
        (FACTORY, VERSION) = (factory_, id.version);
        _s().initialized = true;
    }

    // ------------------------------------------------------------------ the instance

    function initialize(bytes32 ownerUA) external {
        if (msg.sender != FACTORY) revert PqChatNotFactory();
        S storage s = _s();
        if (s.initialized) revert PqChatInitialized();
        ChainEnvCode.requirePresent();
        (s.initialized, s.ownerUA) = (true, ownerUA);
    }

    function owner() external view returns (bytes32) {
        return _s().ownerUA;
    }

    function factoryInfo() external view returns (IOpenFactory.FactoryInfo memory) {
        S storage s = _s();
        return IOpenFactory.FactoryInfo(FACTORY, ChainEnvCode.chainUid(), CLASS, KIND, VERSION, s.ownerUA, s.initialized);
    }

    function supportsInterface(bytes4 id) external pure returns (bool) {
        return id == 0x01ffc9a7 || id == type(IPqChat).interfaceId;
    }

    /// @notice 3C-D1: a `chain_uid`, a registry and a code-size limit of at least 24,576 B.
    function validateEnv(IFactoryToken.ChainEnv calldata env) external pure {
        if (env.chainUid == 0 || env.registry == address(0) || env.params.length == 0
            || uint256(env.params[0]) < MIN_CODE_LIMIT) revert PqChatEnv();
    }

    function chainEnv() external view returns (IFactoryToken.ChainEnv memory) {
        return ChainEnvCode.decode();
    }

    // ------------------------------------------------------------------ sessions

    function createSession(PqChatSession calldata s, Wrap[] calldata wraps, IUARegistry.UASig calldata sig)
        external returns (bytes32 sid)
    {
        (IUARegistry reg, uint256 limit, bytes32 uid) = _env();
        _checkSession(reg, s);
        _auth(reg, s.creator, PqChatTypes.hashSession(s), sig);
        _useNonce(PqChatTypes.scopeSession(s.creator), s.nonce);
        sid = PqChatTypes.sessionId(s.creator, s.nonce);
        Epoch storage ep = _s().epochs[sid];
        ep.sessionId = sid;
        ep.record = _put(abi.encode(s, keccak256(abi.encode(sig))), limit);
        ep.wraps = uint32(s.members.length);
        ep.home = s.homeChain == uid && s.homeContract == address(this);
        emit PqChatSessionCreated(sid, s.creator, s.homeChain);
        for (uint256 i; i < s.members.length; ++i) _s().sessions[s.members[i].ua].push(sid);
        _land(sid, ep, 0, wraps, s.members, s.wrapHashes, limit);
    }

    /// @dev P8, 3C-D6: the lists, the creator a member and an admin, the home instance named (P32).
    function _checkSession(IUARegistry reg, PqChatSession calldata s) internal view {
        MemberKey[] memory members = s.members;
        bytes32[] memory admins = s.admins;
        _checkLists(reg, admins, members, s.wrapHashes.length, 2);
        if (!_has(admins, s.creator) || _memberAt(members, s.creator) == type(uint256).max || s.homeChain == 0
            || s.homeContract == address(0)) revert PqChatShape();
    }

    /// @notice P9, P10: the parent stored and complete in this instance, `epoch == parent + 1`, the home slot free; a plain
    ///         rekey by a member of the parent, any other change by an admin of it (3C-D7); every member holds `keyId` here.
    function rekey(PqChatEpoch calldata e, Wrap[] calldata wraps, IUARegistry.UASig calldata sig)
        external returns (bytes32 eid)
    {
        (IUARegistry reg, uint256 limit,) = _env();
        _indexAdded(e, _rights(reg, _parentOf(e), e));
        _auth(reg, e.author, PqChatTypes.hashEpoch(e), sig);
        _useNonce(PqChatTypes.scopeEpoch(e.sessionId, e.author), e.nonce);
        eid = PqChatTypes.epochId(e.sessionId, e.author, e.nonce);
        Epoch storage ep = _s().epochs[eid];
        (ep.sessionId, ep.parent, ep.epoch) = (e.sessionId, e.parentEpochId, e.epoch);
        ep.record = _put(abi.encode(e, keccak256(abi.encode(sig))), limit);
        ep.wraps = uint32(e.members.length);
        emit PqChatEpochAdded(e.sessionId, eid, e.parentEpochId, e.epoch, e.author);
        _land(eid, ep, 0, wraps, e.members, e.wrapHashes, limit);
    }

    function _parentOf(PqChatEpoch calldata e) internal view returns (Epoch storage pe) {
        pe = _known(e.parentEpochId);
        if (pe.sessionId != e.sessionId) revert PqChatUnknown(e.parentEpochId);
        if (pe.landed != pe.wraps) revert PqChatIncomplete(e.parentEpochId);
        if (e.epoch != pe.epoch + 1) revert PqChatEpochNumber(pe.epoch + 1, e.epoch);
        if (_s().epochs[e.sessionId].home) {
            bytes32 c = _s().childOf[e.parentEpochId];
            if (c != 0) revert PqChatEpochTaken(e.parentEpochId, c);
        }
    }

    /// @dev The rights of P10 (3C-D7); returns the parent's member ids.
    function _rights(IUARegistry reg, Epoch storage pe, PqChatEpoch calldata e) internal view returns (bytes32[] memory pu) {
        MemberKey[] memory members = e.members;
        bytes32[] memory admins = e.admins;
        _checkLists(reg, admins, members, e.wrapHashes.length, 1);
        (bytes32[] memory pa, MemberKey[] memory pm,) = _lists(pe);
        pu = _uas(pm);
        if (_keeps(pe, pa, admins) && _keeps(pe, pu, _uas(members))) {
            if (_memberAt(pm, e.author) == type(uint256).max) revert PqChatNotMember(e.author);
        } else if (!_has(pa, e.author)) {
            revert PqChatNotAdmin(e.author);
        }
    }

    /// @dev Owner 2026-11-10: `sessionsOf` gains the session for each member `e` adds to the parent (both sorted). Runs
    ///      before the signature check; a refused record reverts it with the rest.
    function _indexAdded(PqChatEpoch calldata e, bytes32[] memory parent) internal {
        uint256 i;
        for (uint256 j; j < e.members.length; ++j) {
            bytes32 ua = e.members[j].ua;
            while (i < parent.length && parent[i] < ua) ++i;
            if (i == parent.length || parent[i] != ua) _s().sessions[ua].push(e.sessionId);
        }
    }

    /// @dev 3C-D7: `child` (sorted) is `parent` (sorted) minus entries that left the parent epoch.
    function _keeps(Epoch storage pe, bytes32[] memory parent, bytes32[] memory child) internal view returns (bool) {
        uint256 j;
        for (uint256 i; i < parent.length; ++i) {
            if (j < child.length && child[j] == parent[i]) ++j;
            else if (j < child.length && child[j] < parent[i]) return false; // added
            else if (!pe.left[parent[i]]) return false; // dropped without leaving
        }
        return j == child.length;
    }

    function _uas(MemberKey[] memory m) internal pure returns (bytes32[] memory u) {
        u = new bytes32[](m.length);
        for (uint256 i; i < m.length; ++i) u[i] = m[i].ua;
    }

    function addWraps(bytes32 epochId, uint32 first, Wrap[] calldata wraps) external {
        (, uint256 limit,) = _env();
        Epoch storage ep = _known(epochId);
        _slotFree(ep, epochId);
        (, MemberKey[] memory members, bytes32[] memory hashes) = _lists(ep);
        _land(epochId, ep, first, wraps, members, hashes, limit);
    }

    /// @notice P12: a member of `epochId` leaves it; the next epoch may drop it as a plain rekey (3C-D8).
    function leave(PqChatLeave calldata l, IUARegistry.UASig calldata sig) external {
        (IUARegistry reg,,) = _env();
        Epoch storage ep = _known(l.epochId);
        if (ep.sessionId != l.sessionId) revert PqChatUnknown(l.epochId);
        (, MemberKey[] memory m,) = _lists(ep);
        if (_memberAt(m, l.member) == type(uint256).max) revert PqChatNotMember(l.member);
        _auth(reg, l.member, PqChatTypes.hashLeave(l), sig);
        _useNonce(PqChatTypes.scopeEpoch(l.sessionId, l.member), l.nonce);
        ep.left[l.member] = true;
        emit PqChatLeft(l.sessionId, l.epochId, l.member);
    }

    /// @notice P16, D11: a member of the complete epoch `epochId` posts; the record and `keccak256(abi.encode(sig))` in one
    ///         blob appended to the session's list, the signature's bytes in the event.
    function postMessage(PqChatMessage calldata m, IUARegistry.UASig calldata sig) external returns (uint256 index) {
        (IUARegistry reg, uint256 limit,) = _env();
        Epoch storage ep = _known(m.epochId);
        if (ep.sessionId != m.sessionId) revert PqChatUnknown(m.epochId);
        if (ep.landed != ep.wraps) revert PqChatIncomplete(m.epochId);
        (, MemberKey[] memory mk,) = _lists(ep);
        if (_memberAt(mk, m.sender) == type(uint256).max) revert PqChatNotMember(m.sender);
        bytes32 hm = PqChatTypes.hashMessage(m);
        _auth(reg, m.sender, hm, sig);
        _useNonce(PqChatTypes.scopeMessage(m.epochId, m.sender, m.device), m.counter);
        bytes memory blob = abi.encode(m, keccak256(abi.encode(sig)));
        if (blob.length + 2 > _codeCap(limit)) revert PqChatShape(); // one blob (P16)
        address[] storage list = _s().messages[m.sessionId];
        index = list.length;
        list.push(_put(blob, limit));
        emit PqChatMessagePosted(m.sessionId, PqChatTypes.typed(hm), m.sender, index, sig);
    }

    /// @notice P29: no signature, membership or nonce; the payload `abi.encode(v, hint, env)` raw in one blob.
    function storeMessage(uint8 v, bytes8 hint, bytes calldata env) external returns (uint256 index) {
        (, uint256 limit,) = _env();
        bytes memory payload = abi.encode(v, hint, env);
        if (v != 1 || payload.length + 1 > _codeCap(limit)) revert PqChatShape();
        address[] storage list = _s().stored[hint];
        index = list.length;
        list.push(SSTORE2.write(payload));
        emit PqChatStored(hint, index);
    }

    function sessionOf(bytes32 sessionId) external view returns (PqChatSession memory s, bytes32 sigHash) {
        Epoch storage ep = _known(sessionId);
        if (ep.sessionId != sessionId) revert PqChatUnknown(sessionId);
        (s, sigHash) = abi.decode(_get(ep.record), (PqChatSession, bytes32));
    }

    function epochOf(bytes32 epochId) external view returns (PqChatEpoch memory e, bytes32 sigHash) {
        Epoch storage ep = _known(epochId);
        if (ep.sessionId == epochId) revert PqChatUnknown(epochId);
        (e, sigHash) = abi.decode(_get(ep.record), (PqChatEpoch, bytes32));
    }

    function epochComplete(bytes32 epochId) public view returns (bool) {
        Epoch storage ep = _s().epochs[epochId];
        return ep.sessionId != 0 && ep.landed == ep.wraps;
    }

    function childOf(bytes32 parentEpochId) external view returns (bytes32) {
        return _s().childOf[parentEpochId];
    }

    function wrapAt(bytes32 epochId, uint256 i) external view returns (Wrap memory w) {
        uint256 at = _s().epochs[epochId].wrapAt[i];
        if (at == 0) return w;
        bytes memory b = SSTORE2.read(address(uint160(at)), at >> 160, WRAP_BYTES);
        (w.mlkemCt, w.sealedKey) = (new bytes(MLKEM_CT), new bytes(SEALED_KEY));
        bytes memory ct = w.mlkemCt;
        bytes memory sk = w.sealedKey;
        bytes32 m;
        bytes32 kid;
        bytes32 x;
        assembly ("memory-safe") {
            let q := add(b, 32)
            m := mload(q)
            kid := mload(add(q, 32))
            mcopy(add(ct, 32), add(q, 40), 1568)
            x := mload(add(q, 1608))
            mcopy(add(sk, 32), add(q, 1640), 48)
        }
        (w.member, w.keyId, w.x25519Eph) = (m, uint64(bytes8(kid)), x);
    }

    function leftIn(bytes32 epochId, bytes32 member) external view returns (bool) {
        return _s().epochs[epochId].left[member];
    }

    function nonceUsed(bytes32 scope, uint64 nonce) public view returns (bool) {
        return _s().nonces[scope][nonce >> 8] & (1 << (nonce & 0xff)) != 0;
    }

    function messageCount(bytes32 sessionId) external view returns (uint256) {
        return _s().messages[sessionId].length;
    }

    function messageAt(bytes32 sessionId, uint256 index) external view returns (PqChatMessage memory m, bytes32 sigHash) {
        (m, sigHash) = abi.decode(_get(_s().messages[sessionId][index]), (PqChatMessage, bytes32));
    }

    function storedCount(bytes8 hint) external view returns (uint256) {
        return _s().stored[hint].length;
    }

    function storedAt(bytes8 hint, uint256 index) external view returns (bytes memory) {
        return SSTORE2.read(_s().stored[hint][index]);
    }

    function storedRange(bytes8 hint, uint256 offset, uint256 limit) external view returns (bytes[] memory page) {
        address[] storage l = _s().stored[hint];
        uint256 n = l.length;
        if (offset >= n) return page;
        if (limit > STORED_RANGE_MAX) limit = STORED_RANGE_MAX;
        uint256 end = n - offset > limit ? offset + limit : n;
        page = new bytes[](end - offset);
        for (uint256 i; i < page.length; ++i) page[i] = SSTORE2.read(l[offset + i]);
    }

    function sessionCount(bytes32 ua) external view returns (uint256) {
        return _s().sessions[ua].length;
    }

    function sessionsOf(bytes32 ua, uint256 offset, uint256 limit) external view returns (bytes32[] memory page) {
        bytes32[] storage l = _s().sessions[ua];
        uint256 n = l.length;
        if (offset >= n) return page;
        if (limit > SESSIONS_RANGE_MAX) limit = SESSIONS_RANGE_MAX;
        uint256 end = n - offset > limit ? offset + limit : n;
        page = new bytes32[](end - offset);
        for (uint256 i; i < page.length; ++i) page[i] = l[offset + i];
    }

    /// @dev Epoch 0 implied (no slot) once the session is complete here; then `chain` (owner 2026-11-10).
    function epochCount(bytes32 sessionId) public view returns (uint256) {
        Epoch storage ep = _s().epochs[sessionId];
        if (ep.sessionId != sessionId || sessionId == 0 || ep.landed != ep.wraps) return 0;
        return 1 + _s().chain[sessionId].length;
    }

    function epochsOf(bytes32 sessionId, uint256 offset, uint256 limit) external view returns (bytes32[] memory page) {
        uint256 n = epochCount(sessionId);
        if (offset >= n) return page;
        if (limit > EPOCHS_RANGE_MAX) limit = EPOCHS_RANGE_MAX;
        uint256 end = n - offset > limit ? offset + limit : n;
        page = new bytes32[](end - offset);
        bytes32[] storage c = _s().chain[sessionId];
        for (uint256 i; i < page.length; ++i) page[i] = offset + i == 0 ? sessionId : c[offset + i - 1];
    }

    function latestEpoch(bytes32 sessionId) external view returns (bytes32) {
        uint256 n = epochCount(sessionId);
        return n == 0 ? bytes32(0) : n == 1 ? sessionId : _s().chain[sessionId][n - 2];
    }

    // ------------------------------------------------------------------ public topics

    /// @notice P41: any UA the registry verifies; `homeChain`, `homeContract` not zero; `name` 1-128 B.
    function createTopic(PqTopic calldata t, IUARegistry.UASig calldata sig) external returns (bytes32 tid) {
        (IUARegistry reg, uint256 limit,) = _env();
        uint256 nl = bytes(t.name).length;
        if (nl == 0 || nl > 128 || t.homeChain == 0 || t.homeContract == address(0)) revert PqTopicShape();
        _auth(reg, t.owner, PqChatTypes.hashTopic(t), sig);
        _useNonce(PqChatTypes.scopeTopic(t.owner), t.nonce);
        tid = PqChatTypes.topicId(t.owner, t.nonce);
        S storage s = _s();
        Topic storage tp = s.topics[tid];
        (tp.owner, tp.openReplies) = (t.owner, t.openReplies);
        tp.record = _put(abi.encode(t, keccak256(abi.encode(sig))), limit);
        s.allTopics.push(tid);
        s.topicsByOwner[t.owner].push(tid);
        emit PqTopicCreated(tid, t.owner);
    }

    /// @notice P41: by the topic's owner, `seq == stored + 1` (P36).
    function updateTopic(PqTopicUpdate calldata u, IUARegistry.UASig calldata sig) external {
        (IUARegistry reg, uint256 limit,) = _env();
        Topic storage tp = _topic(u.topicId);
        if (u.seq != tp.seq + 1) revert PqTopicSeq(tp.seq + 1, u.seq);
        uint256 nl = bytes(u.name).length;
        if (nl == 0 || nl > 128) revert PqTopicShape();
        _ownerAuth(reg, tp.owner, PqChatTypes.hashTopicUpdate(u), sig);
        (tp.seq, tp.openReplies) = (u.seq, u.openReplies);
        tp.latest = _put(abi.encode(u, keccak256(abi.encode(sig))), limit);
        emit PqTopicUpdated(u.topicId, u.seq);
    }

    /// @notice P41: by the topic's owner, `seq == stored + 1` per `(topicId, writer)`, the writer not the owner.
    function setTopicWriter(PqTopicWriter calldata w, IUARegistry.UASig calldata sig) external {
        (IUARegistry reg,,) = _env();
        Topic storage tp = _topic(w.topicId);
        if (w.writer == tp.owner || w.writer == 0) revert PqTopicShape();
        Writer storage wr = _s().writers[w.topicId][w.writer];
        if (w.seq != wr.seq + 1) revert PqTopicSeq(wr.seq + 1, w.seq);
        _ownerAuth(reg, tp.owner, PqChatTypes.hashTopicWriter(w), sig);
        if (wr.seq == 0) _s().writersOf[w.topicId].push(w.writer); // its first record only
        (wr.granted, wr.seq) = (w.granted, w.seq);
        emit PqTopicWriterSet(w.topicId, w.writer, w.granted, w.seq);
    }

    /// @notice P37, P41: a post by the owner or a writer; a reply to an entry of the same topic here, by anyone while
    ///         `openReplies`, else by the owner or a writer; `ref` all zero or `chainUid`, `pqchat`, `entryId` set.
    function postEntry(PqTopicEntry calldata e, IUARegistry.UASig calldata sig) external returns (bytes32 eid) {
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
        emit PqTopicEntryPosted(e.topicId, eid, e.parentId, e.author, sig);
    }

    function _entryRights(PqTopicEntry calldata e) internal view returns (uint32 depth) {
        Topic storage tp = _topic(e.topicId);
        if (e.parentId != 0) {
            Entry storage pe = _s().entries[e.parentId];
            if (pe.record == address(0) || _word(pe.record, 64) != e.topicId) revert PqTopicParent(e.parentId);
            depth = pe.depth + 1;
            if (tp.openReplies) return depth;
        }
        if (e.author != tp.owner && !_s().writers[e.topicId][e.author].granted) revert PqTopicNotWriter(e.author);
    }

    function _entryShape(EntryRef calldata r, string calldata mediaType, bytes calldata body) internal pure {
        uint256 ml = bytes(mediaType).length;
        if (ml == 0 || ml > 64 || body.length == 0) revert PqTopicShape();
        bool none = r.chainUid == 0 && r.pqchat == address(0) && r.entryId == 0 && r.contentHash == 0;
        if (!none && (r.chainUid == 0 || r.pqchat == address(0) || r.entryId == 0)) revert PqTopicRef();
    }

    /// @notice P38: a new version of an existing entry by its author, `version == count + 1`, the nonce in the original's
    ///         topic scope.
    function editEntry(PqTopicEdit calldata d, IUARegistry.UASig calldata sig) external {
        (IUARegistry reg, uint256 limit,) = _env();
        address original = _s().entries[d.entryId].record;
        if (original == address(0)) revert PqTopicUnknown(d.entryId);
        if (_word(original, 96) != d.author) revert PqTopicNotAuthor(d.author);
        address[] storage vs = _s().versions[d.entryId];
        uint32 next = uint32(vs.length) + 2;
        if (d.version != next) revert PqTopicVersion(next, d.version);
        uint256 ml = bytes(d.mediaType).length;
        if (ml == 0 || ml > 64 || d.body.length == 0) revert PqTopicShape();
        _auth(reg, d.author, PqChatTypes.hashEdit(d), sig);
        _useNonce(PqChatTypes.scopeEntry(_word(original, 64), d.author), d.nonce);
        vs.push(_put(abi.encode(d, keccak256(abi.encode(sig))), limit));
        emit PqTopicEntryEdited(d.entryId, d.version, sig);
    }

    function voteEntry(PqTopicVote calldata, IUARegistry.UASig calldata) external {
        revert PqTopicShape();
    }

    function topicOf(bytes32 topicId) external view returns (PqTopic memory t, uint64 seq) {
        Topic storage tp = _topic(topicId);
        (t,) = abi.decode(_get(tp.record), (PqTopic, bytes32));
        if (tp.latest != address(0)) {
            (PqTopicUpdate memory u,) = abi.decode(_get(tp.latest), (PqTopicUpdate, bytes32));
            (t.name, t.about, t.openReplies) = (u.name, u.about, u.openReplies);
        }
        seq = tp.seq;
    }

    function entryOf(bytes32 entryId) external view returns (EntryView memory v) {
        Entry storage en = _s().entries[entryId];
        if (en.record == address(0)) revert PqTopicUnknown(entryId);
        (PqTopicEntry memory e, bytes32 sh) = abi.decode(_get(en.record), (PqTopicEntry, bytes32));
        address[] storage vs = _s().versions[entryId];
        (v.topicId, v.author, v.parentId, v.depth, v.ref) = (e.topicId, e.author, e.parentId, en.depth, e.ref);
        (v.mediaType, v.body, v.sigHash, v.versionCount) = (e.mediaType, e.body, sh, uint32(vs.length) + 1);
        if (vs.length != 0) {
            (PqTopicEdit memory d, bytes32 dh) = abi.decode(_get(vs[vs.length - 1]), (PqTopicEdit, bytes32));
            (v.mediaType, v.body, v.sigHash) = (d.mediaType, d.body, dh);
        }
    }

    function versionAt(bytes32 entryId, uint32 version)
        external view returns (string memory mediaType, bytes memory body, bytes32 sigHash)
    {
        address original = _s().entries[entryId].record;
        if (original == address(0)) revert PqTopicUnknown(entryId);
        address[] storage vs = _s().versions[entryId];
        if (version == 0 || version > vs.length + 1) revert PqTopicVersion(uint32(vs.length) + 1, version);
        if (version == 1) {
            (PqTopicEntry memory e, bytes32 sh) = abi.decode(_get(original), (PqTopicEntry, bytes32));
            return (e.mediaType, e.body, sh);
        }
        (PqTopicEdit memory d, bytes32 dh) = abi.decode(_get(vs[version - 2]), (PqTopicEdit, bytes32));
        return (d.mediaType, d.body, dh);
    }

    function writerOf(bytes32 topicId, bytes32 ua) external view returns (bool granted, uint64 seq) {
        Writer storage w = _s().writers[topicId][ua];
        return (w.granted, w.seq);
    }

    function scoreOf(bytes32) external view returns (uint128, uint128) {
        revert PqTopicShape();
    }

    function voteOf(bytes32, bytes32) external view returns (int8, uint64) {
        revert PqTopicShape();
    }

    function topics(uint256 start, uint256 count) external view returns (bytes32[] memory, uint256) {
        return _page(_s().allTopics, start, count);
    }

    function topicsByOwner(bytes32 owner_, uint256 start, uint256 count) external view returns (bytes32[] memory, uint256) {
        return _page(_s().topicsByOwner[owner_], start, count);
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

    function topicNonceUsed(bytes32 owner_, uint64 nonce) external view returns (bool) {
        return nonceUsed(PqChatTypes.scopeTopic(owner_), nonce);
    }

    function entryNonceUsed(bytes32 topicId, bytes32 author, uint64 nonce) external view returns (bool) {
        return nonceUsed(PqChatTypes.scopeEntry(topicId, author), nonce);
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
        if (tp.owner == 0) revert PqTopicUnknown(topicId);
    }

    /// @dev A record a topic's owner signs without naming itself (`PqTopicUpdate`, `PqTopicWriter`): any other signer's
    ///      refusal by the registry is `PqTopicNotOwner` (P41); every other revert (a starved verifier) bubbles.
    function _ownerAuth(IUARegistry reg, bytes32 owner_, bytes32 structHash, IUARegistry.UASig calldata sig) internal view {
        try reg.requirePortable(owner_, UAKinds.PURPOSE_PQCHAT, PqChatTypes.typed(structHash), sig) {}
        catch (bytes memory err) {
            if (bytes4(err) == IUARegistry.UAUnauthorized.selector) revert PqTopicNotOwner(owner_);
            assembly ("memory-safe") {
                revert(add(err, 32), mload(err))
            }
        }
    }

    // ------------------------------------------------------------------ internal: env, signatures, nonces

    /// @dev The registry, the code-size limit and `chain_uid` of this clone (3C-D1); the implementation (no env) refuses.
    function _env() internal view returns (IUARegistry reg, uint256 limit, bytes32 uid) {
        IFactoryToken.ChainEnv memory e = ChainEnvCode.decode();
        limit = e.params.length == 0 ? 0 : uint256(e.params[0]);
        if (limit < MIN_CODE_LIMIT || e.registry == address(0)) revert PqChatEnv();
        (reg, uid) = (IUARegistry(e.registry), e.chainUid);
    }

    /// @dev P7: `ua`'s portable signature over `typed(structHash)` under `PURPOSE_PQCHAT`.
    function _auth(IUARegistry reg, bytes32 ua, bytes32 structHash, IUARegistry.UASig calldata sig) internal view {
        reg.requirePortable(ua, UAKinds.PURPOSE_PQCHAT, PqChatTypes.typed(structHash), sig);
    }

    /// @dev A bitmap per scope, any order, never locked (§4.3); called after the signature.
    function _useNonce(bytes32 scope, uint64 nonce) internal {
        mapping(uint256 => uint256) storage b = _s().nonces[scope];
        uint256 bit = 1 << (nonce & 0xff);
        uint256 word = b[nonce >> 8];
        if (word & bit != 0) revert PqChatNonceUsed(scope, nonce);
        b[nonce >> 8] = word | bit;
    }

    // ------------------------------------------------------------------ internal: epochs and wraps

    function _known(bytes32 epochId) internal view returns (Epoch storage ep) {
        ep = _s().epochs[epochId];
        if (ep.sessionId == 0) revert PqChatUnknown(epochId);
    }

    /// @dev The admins, members and wrap hashes of a stored epoch record (the session for epoch 0).
    function _lists(Epoch storage ep)
        internal view returns (bytes32[] memory admins, MemberKey[] memory members, bytes32[] memory hashes)
    {
        bytes memory b = _get(ep.record);
        if (ep.epoch == 0) {
            (PqChatSession memory s,) = abi.decode(b, (PqChatSession, bytes32));
            return (s.admins, s.members, s.wrapHashes);
        }
        (PqChatEpoch memory e,) = abi.decode(b, (PqChatEpoch, bytes32));
        return (e.admins, e.members, e.wrapHashes);
    }

    /// @dev 3C-D6: members strictly sorted, at least `min`, one hash each, each holding its `keyId` here (P3); admins
    ///      strictly sorted and registered (P8).
    function _checkLists(IUARegistry reg, bytes32[] memory admins, MemberKey[] memory members, uint256 nHashes, uint256 min)
        internal view
    {
        uint256 n = members.length;
        if (n < min || nHashes != n) revert PqChatShape();
        for (uint256 i; i < n; ++i) {
            if (i > 0 && members[i].ua <= members[i - 1].ua) revert PqChatShape();
            (IUARegistry.KemKey memory k,) = reg.kemKeyAt(members[i].ua, members[i].keyId);
            if (k.scheme == 0) revert PqChatKemKey(members[i].ua, members[i].keyId);
        }
        for (uint256 i; i < admins.length; ++i) {
            if ((i > 0 && admins[i] <= admins[i - 1]) || !reg.isRegistered(admins[i])) revert PqChatShape();
        }
    }

    /// @dev P9: in the home instance, a child of a parent whose slot another child holds can no longer land.
    function _slotFree(Epoch storage ep, bytes32 epochId) internal view {
        if (ep.epoch == 0 || !_s().epochs[ep.sessionId].home) return;
        bytes32 c = _s().childOf[ep.parent];
        if (c != 0 && c != epochId) revert PqChatEpochTaken(ep.parent, c);
    }

    /// @dev P11: `wraps` as indices `first..` of `epochId`, each against its signed hash, then its shape and its member's
    ///      `ua` / `keyId` (3C-D6), stored once; packed as many per blob as the limit holds, one slot each (pointer | offset
    ///      << 160). The epoch completes when its last wrap lands.
    function _land(bytes32 epochId, Epoch storage ep, uint256 first, Wrap[] calldata wraps, MemberKey[] memory members,
        bytes32[] memory hashes, uint256 limit) internal
    {
        uint256 n = wraps.length;
        if (first + n > members.length) revert PqChatShape();
        uint256 per = (_codeCap(limit) - 1) / WRAP_BYTES;
        for (uint256 j; j < n; j += per) _blob(epochId, ep, first, wraps, j, n - j < per ? n : j + per, members, hashes);
        uint32 landed = ep.landed + uint32(n);
        ep.landed = landed;
        emit PqChatWraps(epochId, uint32(first), uint32(n));
        if (landed == ep.wraps && n != 0) {
            if (ep.epoch != 0) {
                if (_s().epochs[ep.sessionId].home) _s().childOf[ep.parent] = epochId; // P9: the slot, home only
                _s().chain[ep.sessionId].push(epochId); // owner 2026-11-10: `epochsOf`
            }
            emit PqChatEpochComplete(epochId);
        }
    }

    /// @dev One blob of `wraps[from..to)`, indices `first + from..`.
    function _blob(bytes32 epochId, Epoch storage ep, uint256 first, Wrap[] calldata wraps, uint256 from, uint256 to,
        MemberKey[] memory members, bytes32[] memory hashes) private
    {
        bytes memory buf = new bytes((to - from) * WRAP_BYTES);
        for (uint256 j = from; j < to; ++j) {
            uint256 i = first + j;
            Wrap calldata w = wraps[j];
            if (PqChatTypes.hashWrap(w) != hashes[i]) revert PqChatWrapHash(epochId, i);
            if (w.mlkemCt.length != MLKEM_CT || w.sealedKey.length != SEALED_KEY || w.member != members[i].ua
                || w.keyId != members[i].keyId) revert PqChatShape();
            if (ep.wrapAt[i] != 0) revert PqChatWrapStored(epochId, i);
            _pack(buf, (j - from) * WRAP_BYTES, w);
        }
        uint256 ptr = uint160(SSTORE2.write(buf));
        for (uint256 j = from; j < to; ++j) ep.wrapAt[first + j] = ptr | ((j - from) * WRAP_BYTES) << 160;
    }

    /// @dev One wrap at `off`: member (32) ‖ keyId (8, big-endian) ‖ mlkemCt (1,568) ‖ x25519Eph (32) ‖ sealedKey (48).
    function _pack(bytes memory buf, uint256 off, Wrap calldata w) private pure {
        bytes calldata ct = w.mlkemCt;
        bytes calldata sk = w.sealedKey;
        (bytes32 m, uint64 kid, bytes32 x) = (w.member, w.keyId, w.x25519Eph);
        assembly ("memory-safe") {
            let q := add(add(buf, 32), off)
            mstore(q, m)
            mstore(add(q, 32), shl(192, kid))
            calldatacopy(add(q, 40), ct.offset, 1568)
            mstore(add(q, 1608), x)
            calldatacopy(add(q, 1640), sk.offset, 48)
        }
    }

    // ------------------------------------------------------------------ internal: lists

    /// @dev ponytail: linear scans; a sorted list's binary search if groups grow past a few hundred.
    function _has(bytes32[] memory a, bytes32 x) internal pure returns (bool) {
        for (uint256 i; i < a.length; ++i) if (a[i] == x) return true;
        return false;
    }

    function _memberAt(MemberKey[] memory m, bytes32 ua) internal pure returns (uint256) {
        for (uint256 i; i < m.length; ++i) if (m[i].ua == ua) return i;
        return type(uint256).max;
    }

    // ------------------------------------------------------------------ internal: blobs (3C-D3)

    /// @dev The largest runtime of one blob: the chain's limit, at most 65,535 B (`SSTORE2.write`'s PUSH2).
    function _codeCap(uint256 limit) internal pure returns (uint256) {
        return limit < 0xffff ? limit : 0xffff;
    }

    /// @dev `data` as one blob led by flag 0 when it fits the limit, else a chain: each blob led by flag 1 and the next
    ///      blob's address, the last by flag 0. Returns the head.
    function _put(bytes memory data, uint256 limit) internal returns (address head) {
        uint256 cap = _codeCap(limit) - 1; // the bytes of one blob, flag included
        if (data.length < cap) return SSTORE2.write(bytes.concat(bytes1(0), data));
        uint256 piece = cap - 21;
        for (uint256 i = (data.length + piece - 1) / piece; i > 0; --i) {
            uint256 o = (i - 1) * piece;
            uint256 len = data.length - o < piece ? data.length - o : piece;
            bytes memory part = new bytes(len);
            assembly ("memory-safe") {
                mcopy(add(part, 32), add(add(data, 32), o), len)
            }
            head = SSTORE2.write(head == address(0) ? bytes.concat(bytes1(0), part) : bytes.concat(bytes1(0x01), bytes20(head), part));
        }
    }

    function _get(address head) internal view returns (bytes memory data) {
        for (address q = head; q != address(0);) {
            uint256 len = q.code.length - 1;
            bool more = SSTORE2.read(q, 0, 1)[0] != 0;
            uint256 skip = more ? 21 : 1;
            address next = more ? address(bytes20(SSTORE2.read(q, 1, 20))) : address(0);
            data = bytes.concat(data, SSTORE2.read(q, skip, len - skip));
            q = next;
        }
    }

    /// @dev The 32 bytes at `off` of a record's first piece.
    function _word(address head, uint256 off) internal view returns (bytes32) {
        return bytes32(SSTORE2.read(head, (SSTORE2.read(head, 0, 1)[0] != 0 ? 21 : 1) + off, 32));
    }
}
