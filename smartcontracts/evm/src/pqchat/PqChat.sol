// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IPqChat} from "./IPqChat.sol";
import {PqChatTypes} from "./PqChatTypes.sol";
import {PqChatCore} from "./PqChatCore.sol";
import {PqChatTopics} from "./PqChatTopics.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {UAKinds} from "../ua/UAKinds.sol";
import {IOpenFactory} from "../factory/IOpenFactory.sol";
import {IFactoryToken} from "../factory/IFactoryToken.sol";
import {ChainEnvCode} from "../factory/ChainEnvCode.sol";
import {SSTORE2} from "../common/SSTORE2.sol";
import {RescueLib} from "../governance/RescueLib.sol";

/// @title `PqChat` (UA-7, CTR-CHAT-01; D22: class 3, kind 0 on the factory's generic path): sessions, epochs in chunks, the
///        home-instance slot, admins, leave, on-chain and stored messages, public topics and votes.
/// @notice One release, many EIP-1167 clones; each clone reads its chain values from its own code (`ChainEnv`, 3C-D1): the
///         registry, `chain_uid`, the code-size limit `params[0]`. State in the ERC-7201 namespace `scaas.pqchat`.
///         Records are stored in SSTORE2 blobs (3C-D3), never only in an event. The public topics and votes run in the
///         body module `PqChatTopics` by `DELEGATECALL` (CTR-TOK-30, 3C-D2); the sessions, messages and the store, the 1:1
///         path, stay here. **UNAUDITED.**
contract PqChat is IPqChat, PqChatCore {
    uint16 internal constant CLASS = 3;
    uint16 internal constant KIND = 0;
    /// @inheritdoc IPqChat
    uint256 public constant STORED_RANGE_MAX = 16;
    /// @inheritdoc IPqChat
    uint256 public constant SESSIONS_RANGE_MAX = 128;
    /// @inheritdoc IPqChat
    uint256 public constant EPOCHS_RANGE_MAX = 128;
    /// @inheritdoc IPqChat
    uint256 public constant REMOVE_MAX = 16;

    address public immutable FACTORY;
    uint64 internal immutable VERSION;
    /// @notice The body module of the topics (`PqChatTopics`, CTR-TOK-30), named in `implArgs`.
    address internal immutable TOPICS;

    /// @notice `(ReleaseId, factory_, implArgs)` (topics spec §11), `implArgs = abi.encode(topics)`: the body module
    ///         `PqChatTopics` of this factory (CTR-TOK-30, 3C-D2), code present. The implementation is locked.
    constructor(IOpenFactory.ReleaseId memory id, address factory_, bytes memory implArgs) {
        if (id.contractClass != CLASS || id.kind != KIND || id.version == 0 || factory_ == address(0)) {
            revert PqChatEnv();
        }
        address topics_ = abi.decode(implArgs, (address));
        if (topics_.code.length == 0 || PqChatTopics(topics_).FACTORY() != factory_) revert PqChatEnv();
        (FACTORY, VERSION, TOPICS) = (factory_, id.version, topics_);
        _s().initialized = true;
    }

    // ------------------------------------------------------------------ the instance

    /// @notice The factory's only. `ownerUA` is 0 (no owner) or the creator (`IOpenFactory.creating()`, Fable D P3-1): nobody
    ///         names another UA as the owner of an instance it creates.
    function initialize(bytes32 ownerUA) external {
        if (msg.sender != FACTORY) revert PqChatNotFactory();
        S storage s = _s();
        if (s.initialized) revert PqChatInitialized();
        ChainEnvCode.requirePresent();
        if (ownerUA != 0 && ownerUA != IOpenFactory(FACTORY).creating()) revert PqChatOwnerNotCreator(ownerUA);
        (s.initialized, s.ownerUA) = (true, ownerUA);
    }

    function owner() external view returns (bytes32) {
        return _s().ownerUA;
    }

    function factoryInfo() external view returns (IOpenFactory.FactoryInfo memory) {
        S storage s = _s();
        return IOpenFactory.FactoryInfo(FACTORY, ChainEnvCode.chainUid(), CLASS, KIND, VERSION, s.initialized);
    }

    /// @notice CTR-GOV-26 (owner 2026-11-12): anyone; this contract holds nothing by design, so the whole balance of
    ///         `asset` (`address(0)`: the native coin) goes to `RescueLib.SCAAS_DEV_RESCUE`, `IRescuable.Rescued`.
    function rescue(address asset) external {
        RescueLib.all(asset, RescueLib.SCAAS_DEV_RESCUE);
    }

    function supportsInterface(bytes4 id) external pure returns (bool) {
        return id == 0x01ffc9a7 || id == type(IPqChat).interfaceId;
    }

    /// @notice 3C-D1: a `chain_uid`, a registry and a code-size limit of at least 24,576 B.
    function validateEnv(IFactoryToken.ChainEnv calldata env) external pure {
        if (
            env.chainUid == 0 || env.registry == address(0) || env.params.length == 0
                || uint256(env.params[0]) < MIN_CODE_LIMIT
        ) revert PqChatEnv();
    }

    function chainEnv() external view returns (IFactoryToken.ChainEnv memory) {
        return ChainEnvCode.decode();
    }

    // ------------------------------------------------------------------ sessions

    function createSession(PqChatSession calldata s, Wrap[] calldata wraps, IUARegistry.UASig calldata sig)
        external
        returns (bytes32 sid)
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
        ep.home = s.homeChain == uid && s.homeChatContract == address(this);
        emit PqChatSessionCreated(sid, s.creator, s.homeChain);
        for (uint256 i; i < s.members.length; ++i) {
            _s().sessions[s.members[i].ua].push(sid);
        }
        _landWraps(sid, ep, 0, wraps, s.members, s.wrapHashes, limit);
    }

    /// @dev P8, 3C-D6: the lists, the creator a member and an admin, the home instance named (P32).
    function _checkSession(IUARegistry reg, PqChatSession calldata s) internal view {
        MemberKey[] memory members = s.members;
        bytes32[] memory admins = s.admins;
        _checkLists(reg, admins, members, s.wrapHashes.length, 2);
        if (
            !_has(admins, s.creator) || _memberAt(members, s.creator) == type(uint256).max || s.homeChain == 0
                || s.homeChatContract == address(0)
        ) revert PqChatShape();
    }

    /// @notice P9, P10: the parent stored and complete in this instance, `epoch == parent + 1`, the home slot free; a plain
    ///         rekey by a member of the parent, any other change by an admin of it (3C-D7); every member holds `keyId` here.
    function rekey(PqChatEpoch calldata e, Wrap[] calldata wraps, IUARegistry.UASig calldata sig)
        external
        returns (bytes32 eid)
    {
        (IUARegistry reg, uint256 limit,) = _env();
        _indexAdded(e, _rightsOf(reg, _parentOf(e.parentEpochId, e.sessionId, e.epoch), e));
        _auth(reg, e.author, PqChatTypes.hashEpoch(e), sig);
        _useNonce(PqChatTypes.scopeEpoch(e.sessionId, e.author), e.nonce);
        eid = PqChatTypes.epochId(e.sessionId, e.author, e.nonce);
        Epoch storage ep = _s().epochs[eid];
        (ep.sessionId, ep.parent, ep.epoch) = (e.sessionId, e.parentEpochId, e.epoch);
        ep.record = _put(abi.encode(e, keccak256(abi.encode(sig))), limit);
        ep.wraps = uint32(e.members.length);
        emit PqChatEpochAdded(e.sessionId, eid, e.parentEpochId, e.epoch, e.author);
        _landWraps(eid, ep, 0, wraps, e.members, e.wrapHashes, limit);
    }

    /// @dev The rights of P10 (3C-D7) of `e` over its parent `pe` (`PqGroupBase._rights`); returns the parent's member ids.
    function _rightsOf(IUARegistry reg, Epoch storage pe, PqChatEpoch calldata e)
        internal
        view
        returns (bytes32[] memory)
    {
        MemberKey[] memory members = e.members;
        bytes32[] memory admins = e.admins;
        _checkLists(reg, admins, members, e.wrapHashes.length, 1);
        (bytes32[] memory pa, MemberKey[] memory pm,) = _lists(pe);
        return _rights(pe, pa, pm, admins, members, e.author);
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

    function addWraps(bytes32 epochId, uint32 first, Wrap[] calldata wraps) external {
        (, uint256 limit,) = _env();
        Epoch storage ep = _known(epochId);
        _slotFree(ep, epochId);
        (, MemberKey[] memory members, bytes32[] memory hashes) = _lists(ep);
        _landWraps(epochId, ep, first, wraps, members, hashes, limit);
    }

    /// @dev `PqGroupBase._land` and its events: the wraps, then the completion when the last one landed.
    function _landWraps(
        bytes32 epochId,
        Epoch storage ep,
        uint256 first,
        Wrap[] calldata wraps,
        MemberKey[] memory members,
        bytes32[] memory hashes,
        uint256 limit
    ) internal {
        bool complete = _land(epochId, ep, first, wraps, members, hashes, limit);
        emit PqChatWraps(epochId, uint32(first), uint32(wraps.length));
        if (complete) emit PqChatEpochComplete(epochId);
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

    /// @notice P48 (owner 2026-11-10): an admin of the complete epoch `r.epochId` removes 1..REMOVE_MAX of its members,
    ///         strictly sorted; at home only while it has no complete child. The record and its `sigHash` in state.
    function remove(PqChatRemove calldata r, IUARegistry.UASig calldata sig) external {
        (IUARegistry reg, uint256 limit,) = _env();
        Epoch storage ep = _known(r.epochId);
        if (ep.sessionId != r.sessionId) revert PqChatUnknown(r.epochId);
        if (ep.landed != ep.wraps) revert PqChatIncomplete(r.epochId);
        bytes32 child = _s().childOf[r.epochId];
        if (child != 0) revert PqChatEpochTaken(r.epochId, child);
        if (r.nextEpoch != ep.epoch + 1) revert PqChatEpochNumber(ep.epoch + 1, r.nextEpoch);
        uint256 n = r.members.length;
        if (n == 0 || n > REMOVE_MAX) revert PqChatShape();
        (bytes32[] memory admins, MemberKey[] memory m,) = _lists(ep);
        if (!_has(admins, r.admin)) revert PqChatNotAdmin(r.admin);
        for (uint256 i; i < n; ++i) {
            if (i > 0 && r.members[i] <= r.members[i - 1]) revert PqChatShape();
            if (_memberAt(m, r.members[i]) == type(uint256).max) revert PqChatNotMember(r.members[i]);
        }
        _auth(reg, r.admin, PqChatTypes.hashRemove(r), sig);
        _useNonce(PqChatTypes.scopeEpoch(r.sessionId, r.admin), r.nonce);
        uint256 added;
        for (uint256 i; i < n; ++i) {
            if (!ep.removedOf[r.members[i]]) (ep.removedOf[r.members[i]], added) = (true, added + 1);
        }
        ep.removed += uint16(added);
        _s().removals[r.epochId].push(_put(abi.encode(r, keccak256(abi.encode(sig))), limit));
        emit PqChatRemoved(r.sessionId, r.epochId, r.admin, r.members);
    }

    /// @notice P16, D11: a member of the complete epoch `epochId` posts; the record and `keccak256(abi.encode(sig))` in one
    ///         blob appended to the session's list, the signature's bytes in the event.
    function postMessage(PqChatMessage calldata m, IUARegistry.UASig calldata sig) external returns (uint256 index) {
        (IUARegistry reg, uint256 limit,) = _env();
        Epoch storage ep = _known(m.epochId);
        if (ep.sessionId != m.sessionId) revert PqChatUnknown(m.epochId);
        if (ep.landed != ep.wraps) revert PqChatIncomplete(m.epochId);
        // spec §6.3 (Fable P1-1): at home an epoch with a complete child takes no message, so a member the child dropped
        // cannot post under it later; `childOf` is written at home only, so a replica orders nothing here
        bytes32 child = _s().childOf[m.epochId];
        if (child != 0) revert PqChatEpochTaken(m.epochId, child);
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
        w = _wrapAt(epochId, i);
    }

    function leftIn(bytes32 epochId, bytes32 member) external view returns (bool) {
        return _s().epochs[epochId].left[member];
    }

    function removedIn(bytes32 epochId, bytes32 member) external view returns (bool) {
        return _s().epochs[epochId].removedOf[member];
    }

    function removalCount(bytes32 epochId) external view returns (uint256) {
        return _s().removals[epochId].length;
    }

    function removalAt(bytes32 epochId, uint256 index) external view returns (PqChatRemove memory r, bytes32 sigHash) {
        (r, sigHash) = abi.decode(_get(_s().removals[epochId][index]), (PqChatRemove, bytes32));
    }

    function nonceUsed(bytes32 scope, uint64 nonce) external view returns (bool) {
        return _nonceUsed(scope, nonce);
    }

    function messageCount(bytes32 sessionId) external view returns (uint256) {
        return _s().messages[sessionId].length;
    }

    function messageAt(bytes32 sessionId, uint256 index)
        external
        view
        returns (PqChatMessage memory m, bytes32 sigHash)
    {
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
        for (uint256 i; i < page.length; ++i) {
            page[i] = SSTORE2.read(l[offset + i]);
        }
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
        for (uint256 i; i < page.length; ++i) {
            page[i] = l[offset + i];
        }
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
        for (uint256 i; i < page.length; ++i) {
            page[i] = offset + i == 0 ? sessionId : c[offset + i - 1];
        }
    }

    function latestEpoch(bytes32 sessionId) external view returns (bytes32) {
        uint256 n = epochCount(sessionId);
        return n == 0 ? bytes32(0) : n == 1 ? sessionId : _s().chain[sessionId][n - 2];
    }

    // ------------------------------------------------------------------ public topics: the module (CTR-TOK-30, 3C-D2)

    function createTopic(PqTopic calldata, IUARegistry.UASig calldata) external returns (bytes32) {
        _forward();
    }

    function updateTopic(PqTopicUpdate calldata, IUARegistry.UASig calldata) external {
        _forward();
    }

    function setTopicWriter(PqTopicWriter calldata, IUARegistry.UASig calldata) external {
        _forward();
    }

    function postEntry(PqTopicEntry calldata, IUARegistry.UASig calldata) external returns (bytes32) {
        _forward();
    }

    function editEntry(PqTopicEdit calldata, IUARegistry.UASig calldata) external {
        _forward();
    }

    function voteEntry(PqTopicVote calldata, IUARegistry.UASig calldata) external {
        _forward();
    }

    function topicOf(bytes32) external view returns (PqTopic memory, uint64) {
        _forwardView();
    }

    function entryOf(bytes32) external view returns (EntryView memory) {
        _forwardView();
    }

    function versionAt(bytes32, uint32) external view returns (string memory, bytes memory, bytes32) {
        _forwardView();
    }

    function writerOf(bytes32, bytes32) external view returns (bool, uint64) {
        _forwardView();
    }

    function scoreOf(bytes32) external view returns (uint128, uint128) {
        _forwardView();
    }

    function voteOf(bytes32, bytes32) external view returns (int8, uint64) {
        _forwardView();
    }

    function topics(uint256, uint256) external view returns (bytes32[] memory, uint256) {
        _forwardView();
    }

    function topicsByAdmin(bytes32, uint256, uint256) external view returns (bytes32[] memory, uint256) {
        _forwardView();
    }

    function writersOf(bytes32, uint256, uint256) external view returns (bytes32[] memory, uint256) {
        _forwardView();
    }

    function posts(bytes32, uint256, uint256) external view returns (bytes32[] memory, uint256) {
        _forwardView();
    }

    function replies(bytes32, uint256, uint256) external view returns (bytes32[] memory, uint256) {
        _forwardView();
    }

    function byAuthor(bytes32, uint256, uint256) external view returns (bytes32[] memory, uint256) {
        _forwardView();
    }

    function topicNonceUsed(bytes32, uint64) external view returns (bool) {
        _forwardView();
    }

    function entryNonceUsed(bytes32, bytes32, uint64) external view returns (bool) {
        _forwardView();
    }

    /// @dev CTR-TOK-30's unguarded stub (no entry here holds a guard): `DELEGATECALL` of this call's calldata to the module,
    ///      its revert data verbatim on failure, else its return data verbatim.
    function _forward() internal {
        (bool ok, bytes memory ret) = TOPICS.delegatecall(msg.data);
        assembly ("memory-safe") {
            if iszero(ok) { revert(add(ret, 32), mload(ret)) }
            return(add(ret, 32), mload(ret))
        }
    }

    /// @dev A `view` entry (the module's body writes nothing): `_forward` under a view cast, as the token faces do.
    function _forwardView() internal view {
        function() f = _forward;
        function() view v;
        assembly ("memory-safe") {
            v := f
        }
        v();
    }

    /// @notice The body module (CTR-TOK-30), as the token faces list theirs.
    function modules() external view returns (address[] memory m) {
        m = new address[](1);
        m[0] = TOPICS;
    }

    // ------------------------------------------------------------------ internal: the group's errors (PqGroupBase)

    /// @dev Every `PqGroupBase` code to its `PqChat` error (CTR-PQV-12: the selectors unchanged); the env and nonce codes as the
    ///      body module raises them (`PqChatCore._fail`).
    function _fail(uint8 code, uint256 a, uint256 b) internal pure override {
        if (code == F_SHAPE) revert PqChatShape();
        if (code == F_KEM_KEY) revert PqChatKemKey(bytes32(a), uint64(b));
        if (code == F_WRAP_HASH) revert PqChatWrapHash(bytes32(a), b);
        if (code == F_WRAP_STORED) revert PqChatWrapStored(bytes32(a), b);
        if (code == F_UNKNOWN) revert PqChatUnknown(bytes32(a));
        if (code == F_INCOMPLETE) revert PqChatIncomplete(bytes32(a));
        if (code == F_EPOCH_NUMBER) revert PqChatEpochNumber(uint64(a), uint64(b));
        if (code == F_EPOCH_TAKEN) revert PqChatEpochTaken(bytes32(a), bytes32(b));
        if (code == F_NOT_ADMIN) revert PqChatNotAdmin(bytes32(a));
        if (code == F_NOT_MEMBER) revert PqChatNotMember(bytes32(a));
        if (code == F_REMOVED_KEPT) revert PqChatRemovedKept(bytes32(a), bytes32(b));
        super._fail(code, a, b);
    }
}
