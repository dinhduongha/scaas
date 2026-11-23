// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IPqChat} from "./IPqChat.sol";

/// @title The typed records of `PqChat` (spec §4, topics spec §2): the portable domain `DS_C`, the typehashes, `hashStruct`,
///        the ids and the nonce scopes. Pinned against `smartcontracts/vectors/pqchat/` (`*TypehashIsPinned`). **UNAUDITED.**
library PqChatTypes {
    /// @notice `keccak256(abi.encode(keccak256("EIP712Domain(string name,string version)"), keccak256("SCaaS PqChat"),
    ///         keccak256("1")))`: no chain id, no address (P7).
    bytes32 internal constant DS_C = keccak256(
        abi.encode(keccak256("EIP712Domain(string name,string version)"), keccak256("SCaaS PqChat"), keccak256("1"))
    );

    bytes32 internal constant MEMBER_KEY_TYPEHASH = keccak256("MemberKey(bytes32 ua,uint64 keyId,bytes32 via)");
    bytes32 internal constant WRAP_TYPEHASH =
        keccak256("Wrap(bytes32 member,uint64 keyId,bytes mlkemCt,bytes32 x25519Eph,bytes sealedKey)");
    bytes32 internal constant SESSION_TYPEHASH = keccak256(
        "PqChatSession(bytes32 creator,uint64 nonce,bytes32 homeChain,address homeChatContract,bytes32[] admins,"
        "MemberKey[] members,bytes32[] wrapHashes,bytes sealedInfo,uint8 groupMode)MemberKey(bytes32 ua,uint64 keyId,bytes32 via)"
    );
    bytes32 internal constant EPOCH_TYPEHASH = keccak256(
        "PqChatEpoch(bytes32 sessionId,bytes32 author,uint64 nonce,uint64 epoch,bytes32 parentEpochId,bytes32[] admins,"
        "MemberKey[] members,bytes32[] wrapHashes,bytes sealedInfo)MemberKey(bytes32 ua,uint64 keyId,bytes32 via)"
    );
    bytes32 internal constant REMOVE_TYPEHASH = keccak256(
        "PqChatRemove(bytes32 sessionId,bytes32 epochId,uint64 nextEpoch,bytes32[] members,bytes32 admin,uint64 nonce)"
    );
    bytes32 internal constant LEAVE_TYPEHASH =
        keccak256("PqChatLeave(bytes32 sessionId,bytes32 epochId,bytes32 member,uint64 nonce)");
    bytes32 internal constant MESSAGE_TYPEHASH = keccak256(
        "PqChatMessage(bytes32 sessionId,bytes32 epochId,bytes32 sender,bytes16 device,uint64 counter,bytes32[] parents,"
        "bytes ciphertext)"
    );
    bytes32 internal constant TOPIC_TYPEHASH = keccak256(
        "PqTopic(bytes32 admin,uint64 nonce,bytes32 homeChain,address homeChatContract,string name,bytes about,bool openReplies)"
    );
    bytes32 internal constant TOPIC_UPDATE_TYPEHASH =
        keccak256("PqTopicUpdate(bytes32 topicId,uint64 seq,string name,bytes about,bool openReplies)");
    bytes32 internal constant TOPIC_WRITER_TYPEHASH =
        keccak256("PqTopicWriter(bytes32 topicId,bytes32 writer,bool granted,uint64 seq)");
    bytes32 internal constant ENTRY_REF_TYPEHASH =
        keccak256("EntryRef(bytes32 chainUid,address pqchat,bytes32 entryId,bytes32 contentHash)");
    bytes32 internal constant TOPIC_ENTRY_TYPEHASH = keccak256(
        "PqTopicEntry(bytes32 topicId,bytes32 author,uint64 nonce,bytes32 parentId,EntryRef ref,string mediaType,bytes body)"
        "EntryRef(bytes32 chainUid,address pqchat,bytes32 entryId,bytes32 contentHash)"
    );
    bytes32 internal constant TOPIC_EDIT_TYPEHASH = keccak256(
        "PqTopicEdit(bytes32 entryId,bytes32 author,uint64 nonce,uint32 version,string mediaType,bytes body)"
    );
    bytes32 internal constant TOPIC_VOTE_TYPEHASH =
        keccak256("PqTopicVote(bytes32 entryId,bytes32 voter,int8 value,uint64 seq)");

    /// @notice The TreeKEM mode's tree hash (CTR-CHAT-26, spec §4): `PqGroupTree`'s leaf and parent typehashes for PqChat,
    ///         hashed, never signed.
    bytes32 internal constant TREE_LEAF_TYPEHASH =
        keccak256("TreeLeaf(uint32 leaf,bytes32 ua,uint64 keyId,bytes32 kemHash)");
    bytes32 internal constant TREE_PARENT_TYPEHASH =
        keccak256("TreeParent(bytes32 keyHash,bytes32 left,bytes32 right)");
    /// @dev The tree records (spec 2026-11-23-pqchat-treekem §6, CTR-CHAT-27); `TREE_GENESIS_TYPEHASH` is hashed by clients
    ///      (`genesisCtx`, C29), never signed.
    bytes32 internal constant TREE_ADD_TYPEHASH =
        keccak256("TreeAdd(uint32 leaf,bytes32 ua,uint64 keyId,bytes32 via,bytes32 kemHash)");
    bytes32 internal constant TREE_REMOVE_TYPEHASH = keccak256("TreeRemove(uint32 leaf,bytes32 ua,uint64 keyId)");
    bytes32 internal constant COMMIT_TYPEHASH = keccak256(
        "PqChatCommit(bytes32 sessionId,bytes32 author,uint64 nonce,uint64 epoch,bytes32 parentEpochId,bytes32 treeId,"
        "bytes32 parentTreeHash,uint32 leaf,uint64 keyId,uint32 leaves,bytes32[] admins,TreeRemove[] removes,TreeAdd[] adds,"
        "bytes32[] wrapHashes,bytes32[] nodeKeyHashes,uint32 ctCount,bytes32 ctListHash,bytes32 treeHash,bytes sealedInfo)"
        "TreeAdd(uint32 leaf,bytes32 ua,uint64 keyId,bytes32 via,bytes32 kemHash)TreeRemove(uint32 leaf,bytes32 ua,uint64 keyId)"
    );
    bytes32 internal constant PATH_LIST_TYPEHASH = keccak256("PathList(uint32[] ctTargets,bytes32[] ctHashes)");
    bytes32 internal constant PATH_CT_TYPEHASH =
        keccak256("PathCt(bytes mlkemCt,bytes32 x25519Eph,bytes sealedSecret)");
    bytes32 internal constant TREE_LEAVE_RECORD_TYPEHASH =
        keccak256("PqChatTreeLeave(bytes32 sessionId,bytes32 treeId,bytes32 epochId,bytes32 member,uint64 nonce)");
    bytes32 internal constant TREE_REMOVE_RECORD_TYPEHASH = keccak256(
        "PqChatTreeRemove(bytes32 sessionId,bytes32 treeId,bytes32 epochId,uint64 nextEpoch,bytes32[] members,"
        "bytes32 admin,uint64 nonce)"
    );
    bytes32 internal constant TREE_GENESIS_TYPEHASH = keccak256(
        "TreeGenesis(bytes32 creator,uint64 nonce,bytes32 homeChain,address homeChatContract,bytes32[] admins,"
        "MemberKey[] members,uint8 groupMode)MemberKey(bytes32 ua,uint64 keyId,bytes32 via)"
    );

    /// @notice Id tags (spec §4.3, topics P36) and nonce-scope tags (3C-D5).
    bytes32 internal constant TAG_SESSION = keccak256("scaas/pqchat/v1/session");
    bytes32 internal constant TAG_EPOCH = keccak256("scaas/pqchat/v1/epoch");
    bytes32 internal constant TAG_TOPIC = keccak256("scaas/pqchat/v1/topic");
    bytes32 internal constant TAG_ENTRY = keccak256("scaas/pqchat/v1/entry");
    bytes32 internal constant SCOPE_SESSION = keccak256("scaas/pqchat/v1/scope/session");
    bytes32 internal constant SCOPE_EPOCH = keccak256("scaas/pqchat/v1/scope/epoch");
    bytes32 internal constant SCOPE_MESSAGE = keccak256("scaas/pqchat/v1/scope/message");
    bytes32 internal constant SCOPE_TOPIC = keccak256("scaas/pqchat/v1/scope/topic");
    bytes32 internal constant SCOPE_ENTRY = keccak256("scaas/pqchat/v1/scope/entry");

    function typed(bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(hex"1901", DS_C, structHash));
    }

    // ------------------------------------------------------------------ hashStruct

    function hashMembers(IPqChat.MemberKey[] calldata m) internal pure returns (bytes32) {
        bytes32[] memory h = new bytes32[](m.length);
        for (uint256 i; i < m.length; ++i) {
            h[i] = keccak256(abi.encode(MEMBER_KEY_TYPEHASH, m[i].ua, m[i].keyId, m[i].via));
        }
        return keccak256(abi.encodePacked(h));
    }

    function hashWrap(IPqChat.Wrap calldata w) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(WRAP_TYPEHASH, w.member, w.keyId, keccak256(w.mlkemCt), w.x25519Eph, keccak256(w.sealedKey))
        );
    }

    function hashSession(IPqChat.PqChatSession calldata s) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                SESSION_TYPEHASH,
                s.creator,
                s.nonce,
                s.homeChain,
                s.homeChatContract,
                keccak256(abi.encodePacked(s.admins)),
                hashMembers(s.members),
                keccak256(abi.encodePacked(s.wrapHashes)),
                keccak256(s.sealedInfo),
                s.groupMode
            )
        );
    }

    function hashEpoch(IPqChat.PqChatEpoch calldata e) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                EPOCH_TYPEHASH,
                e.sessionId,
                e.author,
                e.nonce,
                e.epoch,
                e.parentEpochId,
                keccak256(abi.encodePacked(e.admins)),
                hashMembers(e.members),
                keccak256(abi.encodePacked(e.wrapHashes)),
                keccak256(e.sealedInfo)
            )
        );
    }

    function hashRemove(IPqChat.PqChatRemove calldata r) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                REMOVE_TYPEHASH,
                r.sessionId,
                r.epochId,
                r.nextEpoch,
                keccak256(abi.encodePacked(r.members)),
                r.admin,
                r.nonce
            )
        );
    }

    function hashCommit(IPqChat.PqChatCommit calldata c) internal pure returns (bytes32) {
        bytes memory a = abi.encode(
            COMMIT_TYPEHASH,
            c.sessionId,
            c.author,
            c.nonce,
            c.epoch,
            c.parentEpochId,
            c.treeId,
            c.parentTreeHash,
            c.leaf,
            c.keyId,
            c.leaves
        );
        bytes memory b = abi.encode(
            keccak256(abi.encodePacked(c.admins)),
            _hashRemoves(c.removes),
            _hashAdds(c.adds),
            keccak256(abi.encodePacked(c.wrapHashes)),
            keccak256(abi.encodePacked(c.nodeKeyHashes)),
            c.ctCount,
            c.ctListHash,
            c.treeHash,
            keccak256(c.sealedInfo)
        );
        return keccak256(bytes.concat(a, b));
    }

    function _hashRemoves(IPqChat.TreeRemove[] calldata r) private pure returns (bytes32) {
        bytes32[] memory h = new bytes32[](r.length);
        for (uint256 i; i < r.length; ++i) {
            h[i] = keccak256(abi.encode(TREE_REMOVE_TYPEHASH, r[i].leaf, r[i].ua, r[i].keyId));
        }
        return keccak256(abi.encodePacked(h));
    }

    function _hashAdds(IPqChat.TreeAdd[] calldata a) private pure returns (bytes32) {
        bytes32[] memory h = new bytes32[](a.length);
        for (uint256 i; i < a.length; ++i) {
            h[i] = keccak256(abi.encode(TREE_ADD_TYPEHASH, a[i].leaf, a[i].ua, a[i].keyId, a[i].via, a[i].kemHash));
        }
        return keccak256(abi.encodePacked(h));
    }

    function hashPathList(uint32[] calldata ctTargets, bytes32[] calldata ctHashes) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                PATH_LIST_TYPEHASH, keccak256(abi.encodePacked(ctTargets)), keccak256(abi.encodePacked(ctHashes))
            )
        );
    }

    function hashPathCt(IPqChat.PathCt calldata c) internal pure returns (bytes32) {
        return keccak256(abi.encode(PATH_CT_TYPEHASH, keccak256(c.mlkemCt), c.x25519Eph, keccak256(c.sealedSecret)));
    }

    function hashTreeLeave(IPqChat.PqChatTreeLeave calldata l) internal pure returns (bytes32) {
        return keccak256(abi.encode(TREE_LEAVE_RECORD_TYPEHASH, l.sessionId, l.treeId, l.epochId, l.member, l.nonce));
    }

    function hashTreeRemove(IPqChat.PqChatTreeRemove calldata r) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                TREE_REMOVE_RECORD_TYPEHASH,
                r.sessionId,
                r.treeId,
                r.epochId,
                r.nextEpoch,
                keccak256(abi.encodePacked(r.members)),
                r.admin,
                r.nonce
            )
        );
    }

    function hashLeave(IPqChat.PqChatLeave calldata l) internal pure returns (bytes32) {
        return keccak256(abi.encode(LEAVE_TYPEHASH, l.sessionId, l.epochId, l.member, l.nonce));
    }

    function hashMessage(IPqChat.PqChatMessage calldata m) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                MESSAGE_TYPEHASH,
                m.sessionId,
                m.epochId,
                m.sender,
                m.device,
                m.counter,
                keccak256(abi.encodePacked(m.parents)),
                keccak256(m.ciphertext)
            )
        );
    }

    function hashTopic(IPqChat.PqTopic calldata t) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                TOPIC_TYPEHASH,
                t.admin,
                t.nonce,
                t.homeChain,
                t.homeChatContract,
                keccak256(bytes(t.name)),
                keccak256(t.about),
                t.openReplies
            )
        );
    }

    function hashTopicUpdate(IPqChat.PqTopicUpdate calldata u) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                TOPIC_UPDATE_TYPEHASH, u.topicId, u.seq, keccak256(bytes(u.name)), keccak256(u.about), u.openReplies
            )
        );
    }

    function hashTopicWriter(IPqChat.PqTopicWriter calldata w) internal pure returns (bytes32) {
        return keccak256(abi.encode(TOPIC_WRITER_TYPEHASH, w.topicId, w.writer, w.granted, w.seq));
    }

    function hashEntry(IPqChat.PqTopicEntry calldata e) internal pure returns (bytes32) {
        IPqChat.EntryRef calldata r = e.ref;
        bytes32 ref = keccak256(abi.encode(ENTRY_REF_TYPEHASH, r.chainUid, r.pqchat, r.entryId, r.contentHash));
        return keccak256(
            abi.encode(
                TOPIC_ENTRY_TYPEHASH,
                e.topicId,
                e.author,
                e.nonce,
                e.parentId,
                ref,
                keccak256(bytes(e.mediaType)),
                keccak256(e.body)
            )
        );
    }

    function hashEdit(IPqChat.PqTopicEdit calldata e) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                TOPIC_EDIT_TYPEHASH,
                e.entryId,
                e.author,
                e.nonce,
                e.version,
                keccak256(bytes(e.mediaType)),
                keccak256(e.body)
            )
        );
    }

    function hashVote(IPqChat.PqTopicVote calldata v) internal pure returns (bytes32) {
        return keccak256(abi.encode(TOPIC_VOTE_TYPEHASH, v.entryId, v.voter, v.value, v.seq));
    }

    // ------------------------------------------------------------------ ids and scopes

    function sessionId(bytes32 creator, uint64 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encode(TAG_SESSION, creator, nonce));
    }

    function epochId(bytes32 sessionId_, bytes32 author, uint64 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encode(TAG_EPOCH, sessionId_, author, nonce));
    }

    function topicId(bytes32 admin, uint64 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encode(TAG_TOPIC, admin, nonce));
    }

    function entryId(bytes32 topicId_, bytes32 author, uint64 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encode(TAG_ENTRY, topicId_, author, nonce));
    }

    function scopeSession(bytes32 creator) internal pure returns (bytes32) {
        return keccak256(abi.encode(SCOPE_SESSION, creator));
    }

    function scopeEpoch(bytes32 sessionId_, bytes32 author) internal pure returns (bytes32) {
        return keccak256(abi.encode(SCOPE_EPOCH, sessionId_, author));
    }

    function scopeMessage(bytes32 epochId_, bytes32 sender, bytes16 device) internal pure returns (bytes32) {
        return keccak256(abi.encode(SCOPE_MESSAGE, epochId_, sender, device));
    }

    function scopeTopic(bytes32 admin) internal pure returns (bytes32) {
        return keccak256(abi.encode(SCOPE_TOPIC, admin));
    }

    function scopeEntry(bytes32 topicId_, bytes32 author) internal pure returns (bytes32) {
        return keccak256(abi.encode(SCOPE_ENTRY, topicId_, author));
    }
}
