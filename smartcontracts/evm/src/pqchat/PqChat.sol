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
        Epoch storage pe = _parentOf(e);
        _rights(reg, pe, e);
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

    function _rights(IUARegistry reg, Epoch storage pe, PqChatEpoch calldata e) internal view {
        MemberKey[] memory members = e.members;
        bytes32[] memory admins = e.admins;
        _checkLists(reg, admins, members, e.wrapHashes.length, 1);
        (bytes32[] memory pa, MemberKey[] memory pm,) = _lists(pe);
        if (_keeps(pe, pa, admins) && _keeps(pe, _uas(pm), _uas(members))) {
            if (_memberAt(pm, e.author) == type(uint256).max) revert PqChatNotMember(e.author);
        } else if (!_has(pa, e.author)) {
            revert PqChatNotAdmin(e.author);
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

    // ------------------------------------------------------------------ public topics

    function createTopic(PqTopic calldata, IUARegistry.UASig calldata) external returns (bytes32) {
        revert PqTopicShape();
    }

    function updateTopic(PqTopicUpdate calldata, IUARegistry.UASig calldata) external {
        revert PqTopicShape();
    }

    function setTopicWriter(PqTopicWriter calldata, IUARegistry.UASig calldata) external {
        revert PqTopicShape();
    }

    function postEntry(PqTopicEntry calldata, IUARegistry.UASig calldata) external returns (bytes32) {
        revert PqTopicShape();
    }

    function editEntry(PqTopicEdit calldata, IUARegistry.UASig calldata) external {
        revert PqTopicShape();
    }

    function voteEntry(PqTopicVote calldata, IUARegistry.UASig calldata) external {
        revert PqTopicShape();
    }

    function topicOf(bytes32) external view returns (PqTopic memory, uint64) {
        revert PqTopicShape();
    }

    function entryOf(bytes32) external view returns (EntryView memory) {
        revert PqTopicShape();
    }

    function versionAt(bytes32, uint32) external view returns (string memory, bytes memory, bytes32) {
        revert PqTopicShape();
    }

    function writerOf(bytes32, bytes32) external view returns (bool, uint64) {
        revert PqTopicShape();
    }

    function scoreOf(bytes32) external view returns (uint128, uint128) {
        revert PqTopicShape();
    }

    function voteOf(bytes32, bytes32) external view returns (int8, uint64) {
        revert PqTopicShape();
    }

    function topics(uint256, uint256) external view returns (bytes32[] memory, uint256) {
        revert PqTopicShape();
    }

    function topicsByOwner(bytes32, uint256, uint256) external view returns (bytes32[] memory, uint256) {
        revert PqTopicShape();
    }

    function writersOf(bytes32, uint256, uint256) external view returns (bytes32[] memory, uint256) {
        revert PqTopicShape();
    }

    function posts(bytes32, uint256, uint256) external view returns (bytes32[] memory, uint256) {
        revert PqTopicShape();
    }

    function replies(bytes32, uint256, uint256) external view returns (bytes32[] memory, uint256) {
        revert PqTopicShape();
    }

    function byAuthor(bytes32, uint256, uint256) external view returns (bytes32[] memory, uint256) {
        revert PqTopicShape();
    }

    function topicNonceUsed(bytes32, uint64) external view returns (bool) {
        revert PqTopicShape();
    }

    function entryNonceUsed(bytes32, bytes32, uint64) external view returns (bool) {
        revert PqTopicShape();
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
            if (ep.epoch != 0 && _s().epochs[ep.sessionId].home) _s().childOf[ep.parent] = epochId;
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
