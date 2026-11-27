// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IPqChat} from "./IPqChat.sol";
import {PqChatTypes} from "./PqChatTypes.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {UAKinds} from "../ua/UAKinds.sol";
import {PqGroupBase} from "../pqgroup/PqGroupBase.sol";
import {PqGroupTree} from "../pqgroup/PqGroupTree.sol";

/// @title What `PqChat` and its body module `PqChatTopics` share (CTR-TOK-30, plan 3c 3C-D2): the ERC-7201 namespace
///        `scaas.pqchat`, the clone's chain values (`ChainEnv`, 3C-D1), the signature check, the nonce bitmaps and the
///        SSTORE2 blobs (3C-D3). The module runs by `DELEGATECALL` in the clone's context, so both read one state and one
///        env. The group code (epochs, wraps, lists, nonces, blobs, the env read) is `PqGroupBase`'s (CTR-PQV-12), reached
///        through this namespace by the hooks below; the TreeKEM mode's tree (`PqGroupTree`, CTR-CHAT-26) through the namespace
///        `scaas.pqchat.tree`, with PqChat's typehashes, bounds and errors. **UNAUDITED.**
abstract contract PqChatCore is PqGroupBase, PqGroupTree {
    struct Topic {
        bytes32 admin; // 0 = unknown
        address record; // the create record's head blob
        uint64 seq;
        bool openReplies;
        address latest; // the latest update's head blob, 0 before one
    }

    struct Entry {
        address record; // the original's head blob; 0 = unknown
        uint32 depth;
        uint64 postedAt; // CTR-CHAT-29: the block time the original landed, in the slot's free 64 bits
    }

    /// @dev CTR-CHAT-29: an edit's head blob and the block time it landed, one slot (was the `address` alone).
    struct Version {
        address record;
        uint64 editedAt;
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
        uint8 sigStore; // CTR-CHAT-23: SIG_NONE or SIG_SSTORE2, fixed at `initialize`
        mapping(bytes32 => Epoch) epochs;
        mapping(bytes32 => bytes32) childOf;
        mapping(bytes32 => mapping(uint256 => uint256)) nonces;
        mapping(bytes32 => address[]) messages;
        mapping(bytes8 => address[]) stored;
        mapping(bytes32 => Topic) topics;
        mapping(bytes32 => mapping(bytes32 => Writer)) writers;
        mapping(bytes32 => Entry) entries;
        mapping(bytes32 => Version[]) versions;
        mapping(bytes32 => mapping(bytes32 => Vote)) votes;
        mapping(bytes32 => Score) scores;
        bytes32[] allTopics;
        mapping(bytes32 => bytes32[]) topicsByAdmin;
        mapping(bytes32 => bytes32[]) writersOf;
        mapping(bytes32 => bytes32[]) posts;
        mapping(bytes32 => bytes32[]) replies;
        mapping(bytes32 => bytes32[]) byAuthor;
        mapping(bytes32 => bytes32[]) sessions; // per UA (owner 2026-11-10)
        mapping(bytes32 => bytes32[]) chain; // per session: its epochs >= 1 in completion order (epoch 0 implied)
        mapping(bytes32 => address[]) removals; // P48: per epoch, its `remove` records
        mapping(bytes32 => address[]) leaves; // CTR-CHAT-23: per epoch, its `leave` records (`sstore2` only)
    }

    /// @dev CTR-CHAT-23: the signature-storage modes, PQZ's numbering (`NONE` 0, `LOG` 1, `SSTORE2` 2); no log mode here.
    uint8 internal constant SIG_NONE = 0;
    uint8 internal constant SIG_SSTORE2 = 2;

    /// @dev `keccak256(abi.encode(uint256(keccak256("scaas.pqchat")) - 1)) & ~bytes32(uint256(0xff))`.
    bytes32 internal constant SLOT = 0xc7b36804b17476e9a19a6ebc690cd7b9326d322c515fd7dc91373f9bc6dc3000;

    /// @dev `PqGroupTree`'s namespace for PqChat: ERC-7201 of `scaas.pqchat.tree` (the app's id `scaas.pqchat` + `.tree`).
    bytes32 internal constant TREE_SLOT = 0x6dbf1a211620db3f6ac9abbc89a5beccc42b16cce14417bf002a104ad4e19c00;
    /// @dev CTR-CHAT-27 C10 (owner, R8; 256 -> 512 owner 2026-11-25): leaf positions of one tree session, depth 9; C24: its
    ///      admins and its `sealedInfo` (the sealed form of the 4,096-B padding bucket).
    uint256 internal constant TREE_LEAVES_MAX = 512;
    uint256 internal constant TREE_ADMINS_MAX = 32;
    uint256 internal constant TREE_INFO_MAX = 4124;
    /// @dev C10, C21: adds plus removes per commit, and the leaves one head may owe to removals (owner 2026-11-25: 32 ->
    ///      20, so the one-transaction commit of the last live leaf fits 2^24 with an ML-DSA-87 author at 512 leaves).
    uint256 internal constant TREE_CHANGES_MAX = 20;

    function _s() internal pure returns (S storage s) {
        assembly ("memory-safe") {
            s.slot := SLOT
        }
    }

    // ------------------------------------------------------------------ the group hooks (PqGroupBase)

    function _epochs() internal view override returns (mapping(bytes32 => Epoch) storage) {
        return _s().epochs;
    }

    function _childOf() internal view override returns (mapping(bytes32 => bytes32) storage) {
        return _s().childOf;
    }

    function _nonces() internal view override returns (mapping(bytes32 => mapping(uint256 => uint256)) storage) {
        return _s().nonces;
    }

    function _chain() internal view override returns (mapping(bytes32 => bytes32[]) storage) {
        return _s().chain;
    }

    /// @dev The admins, members and wrap hashes of a stored epoch record (the session for epoch 0).
    function _lists(Epoch storage ep)
        internal
        view
        override
        returns (bytes32[] memory admins, IPqChat.MemberKey[] memory members, bytes32[] memory hashes)
    {
        bytes memory b = _get(ep.record);
        if (ep.epoch == 0) {
            (IPqChat.PqChatSession memory s,) = abi.decode(b, (IPqChat.PqChatSession, bytes32));
            return (s.admins, s.members, s.wrapHashes);
        }
        (IPqChat.PqChatEpoch memory e,) = abi.decode(b, (IPqChat.PqChatEpoch, bytes32));
        return (e.admins, e.members, e.wrapHashes);
    }

    // ------------------------------------------------------------------ the tree hooks (PqGroupTree)

    function _treeSlot() internal pure override returns (bytes32) {
        return TREE_SLOT;
    }

    function _treeTypehashes() internal pure override returns (bytes32, bytes32) {
        return (PqChatTypes.TREE_LEAF_TYPEHASH, PqChatTypes.TREE_PARENT_TYPEHASH);
    }

    function _treeBounds() internal pure override returns (uint256, uint256, uint256, uint256) {
        return (TREE_LEAVES_MAX, TREE_ADMINS_MAX, TREE_CHANGES_MAX, KEYS_PER_UA_MAX);
    }

    /// @dev fable-11, codex-17: a UA added by a commit joins `sessionsOf` at its first leaf, once.
    function _treeListedNew(bytes32 gid, bytes32 ua) internal override {
        _s().sessions[ua].push(gid);
    }

    function _treeFail(uint8 code, uint256 a, uint256 b) internal pure override {
        if (code == T_KEM_KEY) _chatFail(F_KEM_KEY, a, b);
        if (code == T_KEY_LIVE) revert IPqChat.PqChatTreeKeyLive(bytes32(a));
        if (code == T_LEAF) revert IPqChat.PqChatTreeLeaf(uint32(a));
        if (code == T_RETURN) revert IPqChat.PqChatTreeReturn(bytes32(a));
        if (code == T_KEY_RETURN) revert IPqChat.PqChatTreeKeyReturn(bytes32(a));
        if (code == T_OWN_KEY_RETURN) revert IPqChat.PqChatTreeOwnKeyReturn(bytes32(a), bytes32(b));
        if (code == T_ADMINS) revert IPqChat.PqChatTreeAdmins();
        if (code == T_BACKLOG) revert IPqChat.PqChatTreeBacklog(a);
        if (code == T_TARGETS) revert IPqChat.PqChatTreeTargets(a);
        if (code == T_HASH) revert IPqChat.PqChatTreeHash(bytes32(a));
        if (code == T_PATH_REQUIRED) revert IPqChat.PqChatTreePathRequired();
        if (code == T_PATH_BOUND) revert IPqChat.PqChatTreePathBound(uint32(a), uint32(b));
        if (code == T_REMOVED_KEPT) _chatFail(F_REMOVED_KEPT, a, b);
        if (code == T_NOT_MEMBER) _chatFail(F_NOT_MEMBER, a, b);
        if (code == T_NOT_ADMIN) _chatFail(F_NOT_ADMIN, a, b);
        _chatFail(F_SHAPE, a, b);
    }

    /// @dev A session in the TreeKEM mode (CTR-CHAT-26): its tree is open from `createSession` on.
    function _isTree(bytes32 sessionId) internal view returns (bool) {
        return _tree(sessionId).treeId != 0;
    }

    /// @dev A path ciphertext packed: mlkemCt (1,568) ‖ x25519Eph (32) ‖ sealedSecret (48).
    uint256 internal constant PATH_CT = 1648;

    /// @dev A tree session's tree, else the flat session's `PqChatModeEntry(0)` (`PqChatUnknown` when there is none).
    function _treeOf(bytes32 sid) internal view returns (Tree storage t) {
        t = _tree(sid);
        if (t.treeId == 0) {
            _known(sid);
            revert IPqChat.PqChatModeEntry(0);
        }
    }

    /// @dev Every `PqGroupBase` code to its `PqChat` error (CTR-PQV-12: the selectors unchanged), for `PqChat` and the tree
    ///      module; the env and nonce codes as `_fail` here.
    function _chatFail(uint8 code, uint256 a, uint256 b) internal pure {
        if (code == F_SHAPE) revert IPqChat.PqChatShape();
        if (code == F_KEM_KEY) revert IPqChat.PqChatKemKey(bytes32(a), uint64(b));
        if (code == F_WRAP_HASH) revert IPqChat.PqChatWrapHash(bytes32(a), b);
        if (code == F_WRAP_STORED) revert IPqChat.PqChatWrapStored(bytes32(a), b);
        if (code == F_UNKNOWN) revert IPqChat.PqChatUnknown(bytes32(a));
        if (code == F_INCOMPLETE) revert IPqChat.PqChatIncomplete(bytes32(a));
        if (code == F_EPOCH_NUMBER) revert IPqChat.PqChatEpochNumber(uint64(a), uint64(b));
        if (code == F_EPOCH_TAKEN) revert IPqChat.PqChatEpochTaken(bytes32(a), bytes32(b));
        if (code == F_NOT_ADMIN) revert IPqChat.PqChatNotAdmin(bytes32(a));
        if (code == F_NOT_MEMBER) revert IPqChat.PqChatNotMember(bytes32(a));
        if (code == F_REMOVED_KEPT) revert IPqChat.PqChatRemovedKept(bytes32(a), bytes32(b));
        if (code == F_EXIT_LAG) revert IPqChat.PqChatExitLag(uint64(a), uint64(b));
        PqChatCore._fail(code, a, b);
    }

    /// @dev What the shared code here and in the body module raises (the env read, the nonce bitmap); `PqChat` maps every other
    ///      code (`_fail` there), so the module's ABI keeps its two errors.
    function _fail(uint8 code, uint256 a, uint256 b) internal pure virtual override {
        if (code == F_NONCE_USED) revert IPqChat.PqChatNonceUsed(bytes32(a), uint64(b));
        revert IPqChat.PqChatEnv();
    }

    /// @dev `PqGroupBase._authorOf` for both forms of a PqChat blob, here so that every body module reads it too (fable-U2):
    ///      the blob's first word is the record's offset (64 without the signature, 96 with it), `author` the record's
    ///      second field.
    function _authorOf(Epoch storage ep) internal view override returns (bytes32) {
        return _word(ep.record, uint256(_word(ep.record, 0)) + 32);
    }

    // ------------------------------------------------------------------ CTR-CHAT-23: the kept signatures

    /// @dev An `sstore2` instance keeps each signed record as `abi.encode(record, sigHash, sig)`.
    function _keep() internal view returns (bool) {
        return _s().sigStore == SIG_SSTORE2;
    }

    /// @dev The stored form of a signed record whose ABI tuple is dynamic, from `rec = abi.encode(record)` (`0x20` and its
    ///      tail): `abi.encode(record, sigHash)` on a `none` instance, `abi.encode(record, sigHash, sig)` on an `sstore2` one
    ///      (byte for byte; built here because the compiler's tuple encoder of a calldata record and signature runs out of
    ///      stack). `sigHash = keccak256(abi.encode(sig))`.
    function _blob(bytes memory rec, IUARegistry.UASig calldata sig) internal view returns (bytes memory out) {
        bytes memory es = abi.encode(sig);
        bytes32 sh = keccak256(es);
        bool keep = _keep();
        uint256 r = rec.length - 32;
        uint256 e = keep ? es.length - 32 : 0;
        uint256 head = keep ? 96 : 64;
        out = new bytes(head + r + e);
        assembly ("memory-safe") {
            let o := add(out, 32)
            mstore(o, head)
            mstore(add(o, 32), sh)
            if keep { mstore(add(o, 64), add(head, r)) }
            mcopy(add(o, head), add(rec, 64), r)
            if keep { mcopy(add(add(o, head), r), add(es, 64), e) }
        }
    }

    /// @dev P16, D11: the message's signature, nonce, one blob appended to the session's list, the event; the caller checked
    ///      the epoch and the sender's membership (`PqChat` for a flat session, `PqChatTree` for a tree one).
    function _post(IUARegistry reg, uint256 limit, IPqChat.PqChatMessage calldata m, IUARegistry.UASig calldata sig)
        internal
        returns (uint256 index)
    {
        bytes32 hm = PqChatTypes.hashMessage(m);
        _auth(reg, m.sender, hm, sig);
        _useNonce(PqChatTypes.scopeMessage(m.epochId, m.sender, m.device), m.counter);
        bytes memory blob = _blob(abi.encode(m), sig);
        if (blob.length + 2 > _codeCap(limit)) revert IPqChat.PqChatShape(); // one blob (P16), the kept signature included
        address[] storage list = _s().messages[m.sessionId];
        index = list.length;
        list.push(_put(blob, limit));
        emit IPqChat.PqChatMessagePosted(m.sessionId, PqChatTypes.typed(hm), m.sender, index, sig);
    }

    // ------------------------------------------------------------------ internal: signatures

    /// @dev P7: `ua`'s portable signature over `typed(structHash)` under `PURPOSE_PQCHAT`.
    function _auth(IUARegistry reg, bytes32 ua, bytes32 structHash, IUARegistry.UASig calldata sig) internal view {
        reg.requirePortable(ua, UAKinds.PURPOSE_PQCHAT, PqChatTypes.typed(structHash), sig);
    }
}
