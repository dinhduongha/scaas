// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {PqTopicsBase} from "./PqTopicsBase.sol";

/// Owner 2026-11-27 (public-topics UI research §8, G1 and G5): the block time of each entry and each version, kept in the
/// slots the entry already has, and each version's nonce in the views. Every assertion through views (logs ignored).
contract PqTopicRowsTest is PqTopicsBase {
    uint64 internal constant T0 = 1_900_000_000;

    /// G1 (CTR-CHAT-29): `postedAt` is the block time the original landed and never moves; `editedAt` is the latest edit's
    /// (0 before one); `versionAt` returns the original's `postedAt` and that version's `editedAt` (0 for version 1).
    function test_topics_postedAtAndEditedAt() public {
        bytes32 t = _newTopic(true);
        vm.warp(T0);
        bytes32 p = _post(chat, t, ids[0], 1, 0);
        vm.warp(T0 + 7);
        bytes32 r = _post(chat, t, ids[2], 1, p);
        IPqChat.EntryView memory v = chat.entryOf(p);
        assertEq(v.postedAt, T0, "the post's time");
        assertEq(v.editedAt, 0, "no edit yet");
        assertEq(chat.entryOf(r).postedAt, T0 + 7, "the reply's own time");
        vm.warp(T0 + 100);
        _edit(chat, _editRec(p, ids[0], 2, 2));
        vm.warp(T0 + 250);
        _edit(chat, _editRec(p, ids[0], 3, 3));
        v = chat.entryOf(p);
        assertEq(v.postedAt, T0, "an edit leaves the original's time");
        assertEq(v.editedAt, T0 + 250, "the latest edit's time");
        uint64[3] memory edited = [uint64(0), T0 + 100, T0 + 250];
        for (uint32 i = 1; i <= 3; ++i) {
            (,,,, uint64 postedAt, uint64 editedAt) = chat.versionAt(p, i);
            assertEq(postedAt, T0, "versionAt: the original's time");
            assertEq(editedAt, edited[i - 1], "versionAt: this version's time");
        }
    }

    /// G5 (CTR-CHAT-31): `entryOf` returns the latest version's nonce and `versionAt` each version's, so the typed digest of
    /// any version (a `ref`'s pinned `contentHash`, CTR-CHAT-16) is rebuilt from the views alone.
    function test_topics_versionNonceRebuildsTheDigest() public {
        bytes32 t = _newTopic(true);
        IPqChat.PqTopicEntry memory e = _entryRec(t, ids[2], 41, 0, bytes("the original"));
        _grant(chat, t, ids[0], ids[2], true, 1);
        bytes32 p = _postRec(chat, e);
        assertEq(chat.entryOf(p).nonce, 41, "the original's nonce before an edit");
        IPqChat.PqTopicEdit[2] memory d = [_editRec(p, ids[2], 7, 2), _editRec(p, ids[2], 99, 3)];
        _edit(chat, d[0]);
        _edit(chat, d[1]);
        assertEq(chat.entryOf(p).nonce, 99, "the latest version's nonce");
        IPqChat.EntryView memory v = chat.entryOf(p);
        (string memory mt, bytes memory body, bytes32 sh, uint64 nonce,,) = chat.versionAt(p, 1);
        IPqChat.PqTopicEntry memory back = _entryRec(v.topicId, v.author, nonce, v.parentId, body);
        (back.ref, back.mediaType) = (v.ref, mt);
        assertEq(h.entry(back), h.entry(e), "version 1's digest from the views");
        assertTrue(sh != 0);
        for (uint32 i = 2; i <= 3; ++i) {
            (mt, body,, nonce,,) = chat.versionAt(p, i);
            IPqChat.PqTopicEdit memory b = IPqChat.PqTopicEdit(p, v.author, nonce, i, mt, body);
            assertEq(h.edit(b), h.edit(d[i - 2]), "an edit's digest from the views");
        }
    }
}
