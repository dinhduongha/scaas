// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {PqChat} from "../../src/pqchat/PqChat.sol";
import {PqChatTypes} from "../../src/pqchat/PqChatTypes.sol";
import {PqChatBase} from "./PqChatBase.sol";

/// Builders of the topic records (topics spec §2): `ids[0]` is the topics' admin unless a test says otherwise.
abstract contract PqTopicsBase is PqChatBase {
    function _topicRec(bytes32 admin_, uint64 nonce, bool open) internal view returns (IPqChat.PqTopic memory t) {
        t = IPqChat.PqTopic(admin_, nonce, chainUidA, address(chat), "General", bytes("# About\n"), open);
    }

    function _createTopic(PqChat c, IPqChat.PqTopic memory t) internal returns (bytes32) {
        return c.createTopic(t, _sig(t.admin, h.topic(t)));
    }

    function _newTopic(bool open) internal returns (bytes32) {
        return _createTopic(chat, _topicRec(ids[0], 1, open));
    }

    function _grant(PqChat c, bytes32 tid, bytes32 admin_, bytes32 writer, bool granted, uint64 seq) internal {
        IPqChat.PqTopicWriter memory w = IPqChat.PqTopicWriter(tid, writer, granted, seq);
        c.setTopicWriter(w, _sig(admin_, h.topicWriter(w)));
    }

    function _entryRec(bytes32 tid, bytes32 author, uint64 nonce, bytes32 parent, bytes memory body)
        internal pure returns (IPqChat.PqTopicEntry memory e)
    {
        e.topicId = tid;
        e.author = author;
        e.nonce = nonce;
        e.parentId = parent;
        e.mediaType = "text/markdown";
        e.body = body;
    }

    function _postRec(PqChat c, IPqChat.PqTopicEntry memory e) internal returns (bytes32) {
        return c.postEntry(e, _sig(e.author, h.entry(e)));
    }

    function _post(PqChat c, bytes32 tid, bytes32 author, uint64 nonce, bytes32 parent) internal returns (bytes32) {
        return _postRec(c, _entryRec(tid, author, nonce, parent, bytes("a *post*")));
    }

    function _refusedPost(PqChat c, IPqChat.PqTopicEntry memory e, bytes memory err) internal {
        IUARegistry.UASig memory sig = _sig(e.author, h.entry(e));
        vm.expectRevert(err);
        c.postEntry(e, sig);
    }

    function _editRec(bytes32 eid, bytes32 author, uint64 nonce, uint32 version)
        internal pure returns (IPqChat.PqTopicEdit memory d)
    {
        d = IPqChat.PqTopicEdit(eid, author, nonce, version, "text/markdown", abi.encodePacked("edit ", uint8(version)));
    }

    function _edit(PqChat c, IPqChat.PqTopicEdit memory d) internal {
        c.editEntry(d, _sig(d.author, h.edit(d)));
    }

    function _vote(PqChat c, bytes32 eid, bytes32 voter, int8 value, uint64 seq) internal {
        IPqChat.PqTopicVote memory v = IPqChat.PqTopicVote(eid, voter, value, seq);
        c.voteEntry(v, _sig(voter, h.vote(v)));
    }
}
