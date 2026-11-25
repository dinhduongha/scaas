// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../ua/IUARegistry.sol";
import {IPqGroupTree} from "../pqgroup/IPqGroupTree.sol";

/// @title `PqChat` (UA-7, CTR-CHAT-01): post-quantum chat sessions and public topics, a factory kind (class 3, kind 0, D22).
/// @notice Spec `docs/superpowers/specs/2026-10-25-ua7-pq-e2e-sessions.md` version 2 (P1-P32) and
///         `2026-11-07-pqchat-public-topics.md` (P33-P46). Every record is a typed EIP-712 struct in the portable domain
///         `DS_C` (no chain id, no address), signed as a `UASig` over `uaMessage(kind, PURPOSE_PQCHAT, typed(record))` and
///         checked by the registry's `requirePortable`; anyone submits it, no record carries a fee (a payer pays a relayer
///         through `RelayFeeRouter`). Each instance has its own state; its owner UA names it and has no power (Q2).
///         **UNAUDITED.**
interface IPqChat is IPqGroupTree {
    // ------------------------------------------------------------------ session records (spec §4.1)

    struct MemberKey {
        bytes32 ua;
        uint64 keyId;
        bytes32 via;
    }

    struct Wrap {
        bytes32 member;
        uint64 keyId;
        bytes mlkemCt;
        bytes32 x25519Eph;
        bytes sealedKey;
    }

    struct PqChatSession {
        bytes32 creator;
        uint64 nonce;
        bytes32 homeChain;
        address homeChatContract;
        bytes32[] admins;
        MemberKey[] members;
        bytes32[] wrapHashes;
        bytes sealedInfo;
        /// @notice CTR-CHAT-25 (owner 2026-11-23): the group protocol, 0 flat wraps (1 TreeKEM in a later release); fixed at
        ///         creation (no epoch record names it); last, so every other field keeps its place; 0 only here
        ///         (`PqChatModeUnsupported`)
        uint8 groupMode;
    }

    struct PqChatEpoch {
        bytes32 sessionId;
        bytes32 author;
        uint64 nonce;
        uint64 epoch;
        bytes32 parentEpochId;
        bytes32[] admins;
        MemberKey[] members;
        bytes32[] wrapHashes;
        bytes sealedInfo;
    }

    /// @notice UA-7 spec P48 (owner 2026-11-10): an admin of `epochId` removes `members` from it; the next epoch
    ///         (`nextEpoch`) must drop them.
    struct PqChatRemove {
        bytes32 sessionId;
        bytes32 epochId;
        uint64 nextEpoch;
        bytes32[] members;
        bytes32 admin;
        uint64 nonce;
    }

    struct PqChatLeave {
        bytes32 sessionId;
        bytes32 epochId;
        bytes32 member;
        uint64 nonce;
    }

    struct PqChatMessage {
        bytes32 sessionId;
        bytes32 epochId;
        bytes32 sender;
        bytes16 device; // a 16-byte UUID, v7 or v4 at the client's choice, never parsed (owner 2026-11-10, P6)
        uint64 counter;
        bytes32[] parents;
        bytes ciphertext;
    }

    // ------------------------------------------------------------------ topic records (topics spec §2)

    struct PqTopic {
        bytes32 admin;
        uint64 nonce;
        bytes32 homeChain;
        address homeChatContract;
        string name;
        bytes about;
        bool openReplies;
    }

    struct PqTopicUpdate {
        bytes32 topicId;
        uint64 seq;
        string name;
        bytes about;
        bool openReplies;
    }

    struct PqTopicWriter {
        bytes32 topicId;
        bytes32 writer;
        bool granted;
        uint64 seq;
    }

    struct EntryRef {
        bytes32 chainUid;
        address pqchat;
        bytes32 entryId;
        bytes32 contentHash;
    }

    struct PqTopicEntry {
        bytes32 topicId;
        bytes32 author;
        uint64 nonce;
        bytes32 parentId;
        EntryRef ref;
        string mediaType;
        bytes body;
    }

    struct PqTopicEdit {
        bytes32 entryId;
        bytes32 author;
        uint64 nonce;
        uint32 version;
        string mediaType;
        bytes body;
    }

    struct PqTopicVote {
        bytes32 entryId;
        bytes32 voter;
        int8 value;
        uint64 seq;
    }

    /// @notice `entryOf`: the original's place (topic, author, parent, depth, reference) and its latest version's content.
    struct EntryView {
        bytes32 topicId;
        bytes32 author;
        bytes32 parentId;
        uint32 depth;
        EntryRef ref;
        string mediaType;
        bytes body;
        bytes32 sigHash;
        uint32 versionCount;
    }

    // CTR-CHAT-27 (spec 2026-11-23-pqchat-treekem §6): a tree epoch's changes are `IPqGroupTree.TreeAdd` (a key added to
    // leaf `leaf`, `via` as in `MemberKey`) and `IPqGroupTree.TreeRemove`, inherited (A-6): the records below name them
    // `TreeAdd`, `TreeRemove`; outside this interface they are `IPqGroupTree`'s.

    /// @notice A tree epoch (§6): `author` commits from its leaf `leaf` with key `keyId`; `leaves` the tree's size after it,
    ///         `admins` the new epoch's sorted list; `wrapHashes[i]` the Welcome wrap of `adds[i]`; `nodeKeyHashes[k]` the
    ///         `keccak256` of the `k`-th node key of the author's filtered path; `ctCount` path ciphertexts, their list
    ///         `hashStruct(PathList)` in `ctListHash` (of the empty list when 0, C14); `treeHash` the root after the commit.
    struct PqChatCommit {
        bytes32 sessionId;
        bytes32 author;
        uint64 nonce;
        uint64 epoch;
        bytes32 parentEpochId;
        bytes32 treeId;
        bytes32 parentTreeHash;
        uint32 leaf;
        uint64 keyId;
        uint32 leaves;
        bytes32[] admins;
        TreeRemove[] removes;
        TreeAdd[] adds;
        bytes32[] wrapHashes;
        bytes32[] nodeKeyHashes;
        uint32 ctCount;
        bytes32 ctListHash;
        bytes32 treeHash;
        bytes sealedInfo;
    }

    /// @notice A path ciphertext: 1,568 + 32 + 48 B, hashed as `PathCt` into the list's `ctHashes`.
    struct PathCt {
        bytes mlkemCt;
        bytes32 x25519Eph;
        bytes sealedSecret;
    }

    /// @notice `PqChatLeave` with `treeId` (C30): the leaver names the head; it is `gone` from then on (C28).
    struct PqChatTreeLeave {
        bytes32 sessionId;
        bytes32 treeId;
        bytes32 epochId;
        bytes32 member;
        uint64 nonce;
    }

    /// @notice `PqChatRemove` with `treeId` (C30): an admin of the head removes UAs; they are `gone` from then on (C28).
    struct PqChatTreeRemove {
        bytes32 sessionId;
        bytes32 treeId;
        bytes32 epochId;
        uint64 nextEpoch;
        bytes32[] members;
        bytes32 admin;
        uint64 nonce;
    }

    // ------------------------------------------------------------------ events (spec §4.4, topics P42)

    event PqChatSessionCreated(bytes32 indexed sessionId, bytes32 indexed creator, bytes32 homeChain);
    event PqChatEpochAdded(
        bytes32 indexed sessionId, bytes32 indexed epochId, bytes32 indexed parentEpochId, uint64 epoch, bytes32 author
    );
    event PqChatWraps(bytes32 indexed epochId, uint32 first, uint32 count);
    event PqChatEpochComplete(bytes32 indexed epochId);
    event PqChatLeft(bytes32 indexed sessionId, bytes32 indexed epochId, bytes32 indexed member);
    event PqChatRemoved(bytes32 indexed sessionId, bytes32 indexed epochId, bytes32 indexed admin, bytes32[] members);
    /// @notice D11: the signature's bytes here, its hash in the stored blob.
    event PqChatMessagePosted(
        bytes32 indexed sessionId,
        bytes32 indexed messageId,
        bytes32 indexed sender,
        uint256 index,
        IUARegistry.UASig sig
    );
    event PqChatStored(bytes8 indexed hint, uint256 index);
    /// @notice CTR-CHAT-27: a landed piece of a tree commit (`piece` 1 the list, 2 the node keys, 3 ciphertexts).
    event PqChatPath(bytes32 indexed epochId, uint8 piece, uint32 first, uint32 count);
    event PqTopicCreated(bytes32 indexed topicId, bytes32 indexed admin);
    event PqTopicUpdated(bytes32 indexed topicId, uint64 seq);
    event PqTopicWriterSet(bytes32 indexed topicId, bytes32 indexed writer, bool granted, uint64 seq);
    event PqTopicEntryPosted(
        bytes32 indexed topicId,
        bytes32 indexed entryId,
        bytes32 indexed parentId,
        bytes32 author,
        IUARegistry.UASig sig
    );
    event PqTopicEntryEdited(bytes32 indexed entryId, uint32 version, IUARegistry.UASig sig);
    event PqTopicVoted(bytes32 indexed entryId, bytes32 indexed voter, int8 value, uint64 seq);

    // ------------------------------------------------------------------ errors (named per check)

    /// @notice A shape the contract checks (3C-D6): lengths, order, counts, a blob over the code-size limit, `v != 1`.
    error PqChatShape();
    /// @notice `initialize`'s owner is neither 0 nor the factory's `creating()` (Fable D P3-1).
    error PqChatOwnerNotCreator(bytes32 ownerUA);
    error PqChatNonceUsed(bytes32 scope, uint64 nonce);
    /// @notice The member holds no KEM key of version `keyId` in this chain's registry (P3, P9).
    error PqChatKemKey(bytes32 member, uint64 keyId);
    error PqChatWrapHash(bytes32 epochId, uint256 index);
    error PqChatWrapStored(bytes32 epochId, uint256 index);
    /// @notice No session or epoch of that id in this instance (or of another session).
    error PqChatUnknown(bytes32 id);
    error PqChatIncomplete(bytes32 epochId);
    error PqChatEpochNumber(uint64 expected, uint64 got);
    /// @notice C9 (Change 2026-11-24, E-3, sc-E-2): an exit naming epoch number `named` lands at a head numbered `head`, more
    ///         than `EXIT_LAG_MAX` (16) above it.
    error PqChatExitLag(uint64 named, uint64 head);
    /// @notice The home instance's child slot of `parentEpochId` is `child`'s (P9).
    error PqChatEpochTaken(bytes32 parentEpochId, bytes32 child);
    error PqChatNotAdmin(bytes32 author);
    error PqChatNotMember(bytes32 ua);
    /// @notice P48: a child of `epochId` keeps `ua`, whom a `remove` took out of it.
    error PqChatRemovedKept(bytes32 epochId, bytes32 ua);
    error PqChatNotFactory();
    error PqChatInitialized();
    /// @notice CTR-CHAT-23: `initialize`'s signature-storage setting is neither 0 (`none`) nor 2 (`sstore2`).
    error PqChatSigStore(uint8 sigStore);
    /// @notice CTR-CHAT-23: a signature view on a `none` instance, which keeps each record's `sigHash` only.
    error PqChatSigNotStored();
    /// @notice CTR-CHAT-25, CTR-CHAT-26: a session's `groupMode` this release does not run (it runs 0, flat wraps, and 1,
    ///         TreeKEM): 2-255.
    error PqChatModeUnsupported(uint8 groupMode);
    /// @notice CTR-CHAT-27: an entry or view of the other mode (`rekey`, `leave` or `remove` on a tree session; `commit`,
    ///         `treeLeave` or `treeRemove` on a flat one).
    error PqChatModeEntry(uint8 groupMode);
    /// @notice CTR-CHAT-27 C1: a tree session on a `none` home.
    error PqChatTreeSigStore();
    /// @notice CTR-CHAT-27 C4: a tree session created outside its home instance; C16, C30: a commit, `treeLeave` or
    ///         `treeRemove` whose `treeId` is not the session's.
    error PqChatTreeHome();
    /// @notice C31: a commit whose `parentTreeHash` is not the head's tree hash `stored`.
    error PqChatTreeParent(bytes32 stored);
    /// @notice R14, C28: an Add of a UA that left or was removed.
    error PqChatTreeReturn(bytes32 ua);
    /// @notice R14, R16, C28: an Add, under any UA, of a key taken out of a UA that left or was removed (the session-wide set).
    error PqChatTreeKeyReturn(bytes32 kemHash);
    /// @notice R16, C28: an Add under `ua` of a key taken out of `ua`'s own leaves while it stayed a member (the pair set).
    error PqChatTreeOwnKeyReturn(bytes32 ua, bytes32 kemHash);
    /// @notice A leaf not live with the named key, not blank for an Add, the author's own in a Remove, or out of range.
    error PqChatTreeLeaf(uint32 leaf);
    /// @notice C24: no admin with a live leaf would remain.
    error PqChatTreeAdmins();
    /// @notice C21: a `treeRemove` or `treeLeave` that would owe more than `TREE_CHANGES_MAX` leaves at the head.
    error PqChatTreeBacklog(uint256 owed);
    /// @notice A list that does not hash to `ctListHash`, a second list, or a ciphertext before the list.
    error PqChatPathList(bytes32 epochId);
    /// @notice A node key or ciphertext that does not hash to its signed hash, or has the wrong size.
    error PqChatPathHash(bytes32 epochId, uint256 index);
    /// @notice A piece landed twice.
    error PqChatPathStored(bytes32 epochId, uint256 index);
    /// @notice At acceptance the path length or the target count differs from the walk (`count` the walk's); when the list
    ///         lands, its targets differ from the expected ones (`count` is `ctCount`: only their hash is kept, A-5).
    error PqChatTreeTargets(uint256 count);
    /// @notice At acceptance: `treeHash` differs from the root `computed` (R12, C7).
    error PqChatTreeHash(bytes32 computed);
    /// @notice CTR-CHAT-27 C18: a key that a live leaf already holds (`kemHash = keccak256(kemPk)`).
    error PqChatTreeKeyLive(bytes32 kemHash);
    /// @notice `validateEnv`: `chainUid` 0, registry 0, no code-size limit or one under EIP-170's 24,576 B (3C-D1); a
    ///         constructor id other than class 3, kind 0, version >= 1.
    error PqChatEnv();
    error PqTopicSeq(uint64 expected, uint64 got);
    error PqTopicNotAdmin(bytes32 admin);
    error PqTopicNotWriter(bytes32 author);
    error PqTopicNotAuthor(bytes32 author);
    error PqTopicParent(bytes32 parentId);
    error PqTopicVersion(uint32 expected, uint32 got);
    error PqTopicRef();
    error PqTopicVoteValue(int8 value);
    error PqTopicShape();
    error PqTopicUnknown(bytes32 id);

    // ------------------------------------------------------------------ the instance (D22, topics spec §11)

    /// @notice Once, by the factory, on a clone with its env; `ownerUA` 0 allowed, fixed, no transfer (Q2). `sigStore`, fixed
    ///         for the instance's life (CTR-CHAT-23, owner 2026-11-23): 0 `none` (each record with its `sigHash` only), 2
    ///         `sstore2` (each control-plane record and posted message also keeps its signature in state; the tools' default);
    ///         PQZ's numbering, 1 (log) is never valid here.
    function initialize(bytes32 ownerUA, uint8 sigStore) external;
    /// @notice CTR-CHAT-23: the signature-storage setting, 0 `none` or 2 `sstore2`.
    function sigStore() external view returns (uint8);
    /// @notice Names the instance; no power over anything (Q2).
    function owner() external view returns (bytes32);

    // ------------------------------------------------------------------ sessions (spec §4.4)

    function createSession(PqChatSession calldata s, Wrap[] calldata wraps, IUARegistry.UASig calldata sig)
        external
        returns (bytes32 sessionId);
    function rekey(PqChatEpoch calldata e, Wrap[] calldata wraps, IUARegistry.UASig calldata sig)
        external
        returns (bytes32 epochId);
    /// @notice Anyone, no signature: `wraps[j]` must hash to `wrapHashes[first + j]` (P11).
    function addWraps(bytes32 epochId, uint32 first, Wrap[] calldata wraps) external;
    function leave(PqChatLeave calldata l, IUARegistry.UASig calldata sig) external;
    /// @notice P48: an admin of `r.epochId` removes `r.members` from it; any child completes only without them.
    function remove(PqChatRemove calldata r, IUARegistry.UASig calldata sig) external;
    /// @notice CTR-CHAT-27 (spec §6, §8): a tree epoch; the list and `nodeKeys` each whole or absent, `cts` and `wraps` a
    ///         first chunk or none, `cts` only with the list. Completes in this call when it carries every piece.
    function commit(
        PqChatCommit calldata c,
        uint32[] calldata ctTargets,
        bytes32[] calldata ctHashes,
        bytes[] calldata nodeKeys,
        PathCt[] calldata cts,
        Wrap[] calldata wraps,
        IUARegistry.UASig calldata sig
    ) external returns (bytes32 epochId);
    /// @notice A staged commit's target list, whole, once, against `ctListHash` and the targets of the walk.
    function addPathList(bytes32 epochId, uint32[] calldata ctTargets, bytes32[] calldata ctHashes) external;
    /// @notice A staged commit's node keys, whole, once, each against its signed hash and the admission check.
    function addPathKeys(bytes32 epochId, bytes[] calldata nodeKeys) external;
    /// @notice A staged commit's ciphertexts `firstCt..`, each against its hash in the landed list.
    function addPath(bytes32 epochId, uint32 firstCt, PathCt[] calldata cts) external;
    /// @notice C9, C21, C28: the leaver names the head; it is `gone` and its live leaves are owed by the next commit.
    function treeLeave(PqChatTreeLeave calldata l, IUARegistry.UASig calldata sig) external;
    /// @notice C9, C21, C24, C28: an admin of the head removes UAs; they are `gone` and their leaves owed.
    function treeRemove(PqChatTreeRemove calldata r, IUARegistry.UASig calldata sig) external;
    function postMessage(PqChatMessage calldata m, IUARegistry.UASig calldata sig) external returns (uint256 index);
    /// @notice Anyone, no signature, membership or nonce (P29): `v == 1` and the blob fits; appends `abi.encode(v, hint,
    ///         env)` to `hint`'s list.
    function storeMessage(uint8 v, bytes8 hint, bytes calldata env) external returns (uint256 index);

    function sessionOf(bytes32 sessionId) external view returns (PqChatSession memory s, bytes32 sigHash);
    /// @notice An epoch >= 1 (epoch 0 is the session: `sessionOf`).
    function epochOf(bytes32 epochId) external view returns (PqChatEpoch memory e, bytes32 sigHash);
    function epochComplete(bytes32 epochId) external view returns (bool);
    /// @notice The winning child of `parentEpochId` in the home instance; zero elsewhere (P9).
    function childOf(bytes32 parentEpochId) external view returns (bytes32);
    /// @notice Wrap `i` of `epochId`; all zero / empty while it has not landed.
    function wrapAt(bytes32 epochId, uint256 i) external view returns (Wrap memory);
    function leftIn(bytes32 epochId, bytes32 member) external view returns (bool);
    function removedIn(bytes32 epochId, bytes32 member) external view returns (bool);
    function removalCount(bytes32 epochId) external view returns (uint256);
    function removalAt(bytes32 epochId, uint256 index) external view returns (PqChatRemove memory r, bytes32 sigHash);
    /// @notice CTR-CHAT-23: the signature each record was accepted with (`keccak256(abi.encode(sig))` is its `sigHash`),
    ///         on an `sstore2` instance; `PqChatSigNotStored` on a `none` one. Ids and indexes as the record views.
    function sessionSig(bytes32 sessionId) external view returns (IUARegistry.UASig memory sig);
    function epochSig(bytes32 epochId) external view returns (IUARegistry.UASig memory sig);
    function removalSig(bytes32 epochId, uint256 index) external view returns (IUARegistry.UASig memory sig);
    function messageSig(bytes32 sessionId, uint256 index) external view returns (IUARegistry.UASig memory sig);
    /// @notice CTR-CHAT-23: the accepted `leave` records of `epochId`, kept on an `sstore2` instance only (0 on a `none` one,
    ///         which keeps the `leftIn` flag alone).
    function leaveCount(bytes32 epochId) external view returns (uint256);
    function leaveAt(bytes32 epochId, uint256 index) external view returns (PqChatLeave memory l, bytes32 sigHash);
    function leaveSig(bytes32 epochId, uint256 index) external view returns (IUARegistry.UASig memory sig);
    /// @notice P48: at most this many members per `remove`.
    function REMOVE_MAX() external view returns (uint256);
    /// @notice The nonce bitmaps (3C-D5): `scope` per `PqChatTypes.scopeSession` / `scopeEpoch` / `scopeMessage`.
    function nonceUsed(bytes32 scope, uint64 nonce) external view returns (bool);
    function messageCount(bytes32 sessionId) external view returns (uint256);
    function messageAt(bytes32 sessionId, uint256 index) external view returns (PqChatMessage memory m, bytes32 sigHash);
    function storedCount(bytes8 hint) external view returns (uint256);
    /// @notice The stored bytes, `abi.encode(v, hint, env)`: the HCS payload of P25.
    function storedAt(bytes8 hint, uint256 index) external view returns (bytes memory);
    /// @notice The stored payloads `[offset, min(offset + min(limit, STORED_RANGE_MAX), count))` of `hint` (owner
    ///         2026-11-10, P29 Change); an offset past the end gives an empty page, never a revert.
    function storedRange(bytes8 hint, uint256 offset, uint256 limit) external view returns (bytes[] memory);
    /// @notice The largest `storedRange` page: 16 blobs of at most 65,535 B each, about 1 MiB returned and about 9 M gas
    ///         of memory in an `eth_call`, under the 50 M default call gas cap of common clients.
    function STORED_RANGE_MAX() external view returns (uint256);

    /// @notice Recovery from state alone (owner 2026-11-10): the sessions `ua` was listed in, one entry at `createSession` per
    ///         member and one at a `rekey` per member it adds; append-only (a removed or leaving member keeps its entry:
    ///         clients check `leftIn` and the latest epoch's members); a member added again gets another entry.
    function sessionCount(bytes32 ua) external view returns (uint256);
    /// @notice Entries `[offset, min(offset + min(limit, SESSIONS_RANGE_MAX), count))`; an offset past the end is empty.
    function sessionsOf(bytes32 ua, uint256 offset, uint256 limit) external view returns (bytes32[] memory);
    /// @notice The largest `sessionsOf` page: 128 ids, 4 KiB returned, about 0.3 M gas of cold reads in an `eth_call`.
    function SESSIONS_RANGE_MAX() external view returns (uint256);
    /// @notice The session's epochs (owner 2026-11-10), epoch 0 (the `sessionId`) first once complete, then each epoch >= 1
    ///         in the order it completed here: in the home instance a child completes only by taking its parent's slot
    ///         (P9), so the list is the winning chain 0..n; in a replica it is every complete epoch in completion order,
    ///         competing children included (a replica orders nothing, P18: clients follow the home's list).
    function epochCount(bytes32 sessionId) external view returns (uint256);
    /// @notice Entries `[offset, min(offset + min(limit, EPOCHS_RANGE_MAX), count))`; an offset past the end is empty.
    function epochsOf(bytes32 sessionId, uint256 offset, uint256 limit) external view returns (bytes32[] memory);
    /// @notice The largest `epochsOf` page: 128 ids, as `SESSIONS_RANGE_MAX`.
    function EPOCHS_RANGE_MAX() external view returns (uint256);
    /// @notice The last entry of `epochsOf` (zero while the session is not complete here); no slot of its own.
    function latestEpoch(bytes32 sessionId) external view returns (bytes32 epochId);

    // ------------------------------------------------------------------ public topics (topics spec §5)

    function createTopic(PqTopic calldata t, IUARegistry.UASig calldata sig) external returns (bytes32 topicId);
    function updateTopic(PqTopicUpdate calldata u, IUARegistry.UASig calldata sig) external;
    function setTopicWriter(PqTopicWriter calldata w, IUARegistry.UASig calldata sig) external;
    function postEntry(PqTopicEntry calldata e, IUARegistry.UASig calldata sig) external returns (bytes32 entryId);
    function editEntry(PqTopicEdit calldata e, IUARegistry.UASig calldata sig) external;
    function voteEntry(PqTopicVote calldata v, IUARegistry.UASig calldata sig) external;

    /// @notice The topic's create record with `name`, `about` and `openReplies` as its latest update set them.
    function topicOf(bytes32 topicId) external view returns (PqTopic memory t, uint64 seq);
    function entryOf(bytes32 entryId) external view returns (EntryView memory);
    /// @notice Version `version` (1 = the original, 2.. the edits).
    function versionAt(bytes32 entryId, uint32 version)
        external
        view
        returns (string memory mediaType, bytes memory body, bytes32 sigHash);
    function writerOf(bytes32 topicId, bytes32 ua) external view returns (bool granted, uint64 seq);
    function scoreOf(bytes32 entryId) external view returns (uint128 up, uint128 down);
    function voteOf(bytes32 entryId, bytes32 ua) external view returns (int8 value, uint64 seq);
    /// @notice The paged lists (P42, 3C-D8): at most `count` ids from `start` and the list's length (`count = 0`: the
    ///         length only).
    function topics(uint256 start, uint256 count) external view returns (bytes32[] memory ids, uint256 total);
    function topicsByAdmin(bytes32 admin_, uint256 start, uint256 count)
        external
        view
        returns (bytes32[] memory ids, uint256 total);
    function writersOf(bytes32 topicId, uint256 start, uint256 count)
        external
        view
        returns (bytes32[] memory ids, uint256 total);
    function posts(bytes32 topicId, uint256 start, uint256 count)
        external
        view
        returns (bytes32[] memory ids, uint256 total);
    function replies(bytes32 parentId, uint256 start, uint256 count)
        external
        view
        returns (bytes32[] memory ids, uint256 total);
    function byAuthor(bytes32 author, uint256 start, uint256 count)
        external
        view
        returns (bytes32[] memory ids, uint256 total);
    function topicNonceUsed(bytes32 admin_, uint64 nonce) external view returns (bool);
    function entryNonceUsed(bytes32 topicId, bytes32 author, uint64 nonce) external view returns (bool);
}
