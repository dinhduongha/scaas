// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {PqTopicsBase} from "./PqTopicsBase.sol";

/// Owner 2026-11-27 (public-topics UI research §8, G1, G2 and G5): the block time of each entry and each version, kept in
/// the slots the entry already has, each version's nonce in the views, and a feed's rows in one call. Every assertion through views (logs ignored).
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

    /// A row equals `entryOf` without the body, field by field.
    function _sameAsEntryOf(IPqChat.EntryRow memory w, bytes32 id) internal view {
        IPqChat.EntryView memory v = chat.entryOf(id);
        assertEq(w.topicId, v.topicId, "topicId");
        assertEq(w.author, v.author, "author");
        assertEq(w.parentId, v.parentId, "parentId");
        assertEq(w.depth, v.depth, "depth");
        assertEq(keccak256(abi.encode(w.ref)), keccak256(abi.encode(v.ref)), "ref");
        assertEq(w.mediaType, v.mediaType, "mediaType");
        assertEq(w.sigHash, v.sigHash, "sigHash");
        assertEq(w.versionCount, v.versionCount, "versionCount");
        assertEq(w.postedAt, v.postedAt, "postedAt");
        assertEq(w.editedAt, v.editedAt, "editedAt");
        assertEq(w.nonce, v.nonce, "nonce");
        assertEq(w.bodyLength, v.body.length, "bodyLength");
    }

    function _counts(IPqChat.EntryRow memory w, uint256 up, uint256 down, uint256 replies) internal pure {
        assertEq(w.up, up, "up");
        assertEq(w.down, down, "down");
        assertEq(w.replies, replies, "replies");
    }

    /// G2 (CTR-CHAT-30): `entryRows` gives each id's row in order, without the body: the place, the latest version's media
    /// type, signature hash, nonce and body length, the times, the counts, the viewer's vote and the direct reply count.
    function test_topics_entryRows() public {
        bytes32 t = _newTopic(true);
        vm.warp(T0);
        IPqChat.PqTopicEntry memory e = _entryRec(t, ids[0], 5, 0, new bytes(150_000)); // a chain of blobs
        e.mediaType = string(bytes.concat("text/markdown; x=", new bytes(47))); // 64 B, two words
        e.ref = IPqChat.EntryRef(keccak256("chain"), address(0xC0FFEE), keccak256("there"), keccak256("pinned"));
        bytes32 p = _postRec(chat, e);
        vm.warp(T0 + 9);
        bytes32 r1 = _post(chat, t, ids[2], 1, p);
        bytes32 r2 = _post(chat, t, ids[3], 1, p);
        _post(chat, t, ids[3], 2, r1);
        vm.warp(T0 + 30);
        _edit(chat, IPqChat.PqTopicEdit(r1, ids[2], 8, 2, "text/plain", bytes("edited, 18 bytes!!")));
        _vote(chat, p, ids[1], 1, 1);
        _vote(chat, p, ids[2], 1, 1);
        _vote(chat, p, ids[3], -1, 1);
        _vote(chat, r1, ids[1], -1, 1);
        bytes32[] memory q = new bytes32[](3);
        (q[0], q[1], q[2]) = (r1, p, r2);
        IPqChat.EntryRow[] memory w = chat.entryRows(q, ids[1]);
        assertEq(w.length, 3);
        for (uint256 i; i < 3; ++i) {
            _sameAsEntryOf(w[i], q[i]);
        }
        assertEq(w[1].bodyLength, 150_000, "the original's length, across blobs");
        assertEq(bytes(w[1].mediaType).length, 64, "a 64-B media type");
        assertEq(w[0].mediaType, "text/plain", "the edit's media type");
        assertEq(w[0].bodyLength, 18, "the edit's length");
        assertEq(w[0].nonce, 8, "the edit's nonce");
        assertEq(w[0].editedAt, T0 + 30, "the edit's time");
        assertEq(w[0].postedAt, T0 + 9, "r1's own time");
        assertEq(w[1].nonce, 5, "p: the original's nonce");
        _counts(w[1], 2, 1, 2); // p: 2 up, 1 down, 2 direct replies
        _counts(w[0], 0, 1, 1); // r1
        _counts(w[2], 0, 0, 0); // r2
        assertEq(w[1].vote, 1, "ids[1] on p");
        assertEq(w[0].vote, -1, "ids[1] on r1");
        assertEq(w[2].vote, 0, "ids[1] on r2: none");
        w = chat.entryRows(q, ids[3]);
        assertEq(w[1].vote, -1, "ids[3] on p");
        assertEq(w[0].vote, 0, "ids[3] on r1: none");
        assertEq(chat.entryRows(new bytes32[](0), ids[1]).length, 0, "no id, no row");
    }

    /// G2: at most `ENTRY_ROWS_MAX` (64) ids: 64 answer, 65 `PqTopicRows(65)`; an unknown id `PqTopicUnknown`.
    function test_topics_entryRowsBound() public {
        assertEq(chat.ENTRY_ROWS_MAX(), 64);
        bytes32 t = _newTopic(true);
        bytes32 p = _post(chat, t, ids[0], 1, 0);
        bytes32[] memory q = new bytes32[](64);
        for (uint256 i; i < q.length; ++i) {
            q[i] = p;
        }
        assertEq(chat.entryRows(q, 0).length, 64, "the bound answers");
        bytes32[] memory over = new bytes32[](65);
        for (uint256 i; i < over.length; ++i) {
            over[i] = p;
        }
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqTopicRows.selector, uint256(65)));
        chat.entryRows(over, 0);
        q = new bytes32[](2);
        (q[0], q[1]) = (p, keccak256("nothing"));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqTopicUnknown.selector, keccak256("nothing")));
        chat.entryRows(q, 0);
    }

    /// G2: a row never reads the body: 64 rows of a 150,000-B body (a chain of blobs) cost no more than 64 rows of an 8-B body
    /// plus 20,000 gas (measured 2026-11-27: 1,493,207 and 1,484,247; reading the bodies would add millions).
    function test_topics_entryRowsSkipTheBody() public {
        bytes32 t = _newTopic(true);
        bytes32 small = _post(chat, t, ids[0], 1, 0);
        bytes32 big = _postRec(chat, _entryRec(t, ids[0], 2, 0, new bytes(150_000)));
        bytes32[] memory q = new bytes32[](64);
        for (uint256 i; i < q.length; ++i) {
            q[i] = small;
        }
        chat.entryRows(q, ids[1]);
        uint256 a = vm.lastCallGas().gasTotalUsed;
        for (uint256 i; i < q.length; ++i) {
            q[i] = big;
        }
        chat.entryRows(q, ids[1]);
        uint256 b = vm.lastCallGas().gasTotalUsed;
        emit log_named_uint("GAS entryRows 64 rows, 8-B body", a);
        emit log_named_uint("GAS entryRows 64 rows, 150,000-B body", b);
        assertLe(b, a + 20_000, "the body's size does not raise the cost");
    }
}
