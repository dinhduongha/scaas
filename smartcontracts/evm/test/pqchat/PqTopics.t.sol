// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UACall} from "../ua/UACall.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {PqChat} from "../../src/pqchat/PqChat.sol";
import {PqChatTypes} from "../../src/pqchat/PqChatTypes.sol";
import {PqTopicsBase} from "./PqTopicsBase.sol";

/// Plan 3c T88 (PT2): public topics, the tests 1-4 and 6-10 of the topics spec §8. Every refusal beside its positive control;
/// every assertion through views (logs ignored).
contract PqTopicsTest is PqTopicsBase {
    // 1. writers
    function test_topics_writersPost() public {
        bytes32 t = _newTopic(true);
        (IPqChat.PqTopic memory got, uint64 seq) = chat.topicOf(t);
        assertEq(got.owner, ids[0]);
        assertEq(seq, 0);
        bytes32 p0 = _post(chat, t, ids[0], 1, 0); // the owner
        _refusedPost(chat, _entryRec(t, ids[1], 1, 0, "x"), abi.encodeWithSelector(IPqChat.PqTopicNotWriter.selector, ids[1]));
        _grant(chat, t, ids[0], ids[1], true, 1);
        bytes32 p1 = _post(chat, t, ids[1], 1, 0); // a granted writer
        _grant(chat, t, ids[0], ids[1], false, 2);
        _refusedPost(chat, _entryRec(t, ids[1], 2, 0, "x"), abi.encodeWithSelector(IPqChat.PqTopicNotWriter.selector, ids[1]));
        (bytes32[] memory l, uint256 n) = chat.posts(t, 0, 10);
        assertEq(n, 2);
        assertEq(l[0], p0);
        assertEq(l[1], p1, "the revoked writer's post stays");
        assertEq(chat.entryOf(p1).author, ids[1]);
    }

    // 2. writer records
    function test_topics_writerSeqAndOwner() public {
        bytes32 t = _newTopic(true);
        IPqChat.PqTopicWriter memory w = IPqChat.PqTopicWriter(t, ids[1], true, 2);
        IUARegistry.UASig memory sig = _sig(ids[0], h.topicWriter(w));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqTopicSeq.selector, uint64(1), uint64(2)));
        chat.setTopicWriter(w, sig); // skipped
        w.seq = 1;
        sig = _sig(ids[1], h.topicWriter(w));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqTopicNotOwner.selector, ids[0]));
        chat.setTopicWriter(w, sig); // not the owner's signature
        _grant(chat, t, ids[0], ids[1], true, 1);
        sig = _sig(ids[0], h.topicWriter(w));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqTopicSeq.selector, uint64(2), uint64(1)));
        chat.setTopicWriter(w, sig); // repeated
        _grant(chat, t, ids[0], ids[1], false, 2);
        _grant(chat, t, ids[0], ids[1], true, 3); // re-grant
        (bool g, uint64 s) = chat.writerOf(t, ids[1]);
        assertTrue(g);
        assertEq(s, 3);
        (, uint256 n) = chat.writersOf(t, 0, 0);
        assertEq(n, 1, "listed at its first record only");
        // the owner as a writer
        w = IPqChat.PqTopicWriter(t, ids[0], true, 1);
        sig = _sig(ids[0], h.topicWriter(w));
        vm.expectRevert(IPqChat.PqTopicShape.selector);
        chat.setTopicWriter(w, sig);
    }

    /// The instance's owner UA has no power over a topic (Q2).
    function test_topics_instanceOwnerIsNoTopicOwner() public {
        PqChat c = _instance("owned", ids[4]);
        bytes32 t = _createTopic(c, _topicRec(ids[0], 1, true));
        IPqChat.PqTopicWriter memory w = IPqChat.PqTopicWriter(t, ids[1], true, 1);
        IUARegistry.UASig memory sig = _sig(ids[4], h.topicWriter(w));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqTopicNotOwner.selector, ids[0]));
        c.setTopicWriter(w, sig);
        _refusedPost(c, _entryRec(t, ids[4], 1, 0, "x"), abi.encodeWithSelector(IPqChat.PqTopicNotWriter.selector, ids[4]));
    }

    // 3. replies
    function test_topics_replies() public {
        bytes32 t = _newTopic(true);
        bytes32 p = _post(chat, t, ids[0], 1, 0);
        bytes32 r1 = _post(chat, t, ids[2], 1, p); // a stranger, open replies
        bytes32 r2 = _post(chat, t, ids[3], 1, r1);
        assertEq(chat.entryOf(r1).depth, 1);
        assertEq(chat.entryOf(r2).depth, 2);
        assertEq(chat.entryOf(r2).parentId, r1);
        (bytes32[] memory l, uint256 n) = chat.replies(p, 0, 5);
        assertEq(n, 1);
        assertEq(l[0], r1);
        (, n) = chat.posts(t, 0, 0);
        assertEq(n, 1, "replies are not posts");
        IPqChat.PqTopicUpdate memory u = IPqChat.PqTopicUpdate(t, 1, "General", "", false);
        chat.updateTopic(u, _sig(ids[0], h.topicUpdate(u)));
        (IPqChat.PqTopic memory got, uint64 seq) = chat.topicOf(t);
        assertFalse(got.openReplies);
        assertEq(seq, 1);
        _refusedPost(chat, _entryRec(t, ids[2], 2, p, "x"), abi.encodeWithSelector(IPqChat.PqTopicNotWriter.selector, ids[2]));
        _grant(chat, t, ids[0], ids[1], true, 1);
        _post(chat, t, ids[1], 1, p); // a writer replies
    }

    /// A parent of another topic, unknown, or of another instance.
    function test_topics_replyParents() public {
        bytes32 t = _newTopic(true);
        bytes32 p = _post(chat, t, ids[0], 1, 0);
        bytes32 t2 = _createTopic(chat, _topicRec(ids[0], 2, true));
        bytes32 q = _post(chat, t2, ids[0], 1, 0);
        _refusedPost(chat, _entryRec(t, ids[0], 9, q, "x"), abi.encodeWithSelector(IPqChat.PqTopicParent.selector, q));
        _refusedPost(chat, _entryRec(t, ids[0], 9, keccak256("x"), "x"),
            abi.encodeWithSelector(IPqChat.PqTopicParent.selector, keccak256("x")));
        bytes32 tb = _createTopic(chatB, _topicRec(ids[0], 1, true)); // the same record in B: the same id
        assertEq(tb, t);
        _refusedPost(chatB, _entryRec(t, ids[2], 1, p, "x"), abi.encodeWithSelector(IPqChat.PqTopicParent.selector, p));
    }

    // 4. edits
    function test_topics_edits() public {
        bytes32 t = _newTopic(true);
        bytes32 p = _post(chat, t, ids[1 - 1], 1, 0);
        bytes32 r = _post(chat, t, ids[2], 1, p);
        _edit(chat, _editRec(r, ids[2], 2, 2));
        _edit(chat, _editRec(r, ids[2], 3, 3));
        IPqChat.EntryView memory v = chat.entryOf(r);
        assertEq(v.versionCount, 3);
        assertEq(v.body, abi.encodePacked("edit ", uint8(3)));
        assertEq(v.parentId, p, "the original's parent");
        (, bytes memory b1,) = chat.versionAt(r, 1);
        (, bytes memory b2,) = chat.versionAt(r, 2);
        assertEq(b1, bytes("a *post*"));
        assertEq(b2, abi.encodePacked("edit ", uint8(2)));
        IPqChat.PqTopicEdit memory d = _editRec(r, ids[0], 1, 4); // the topic owner, not the author
        IUARegistry.UASig memory sig = _sig(ids[0], h.edit(d));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqTopicNotAuthor.selector, ids[0]));
        chat.editEntry(d, sig);
        d = _editRec(r, ids[2], 4, 3); // version 3 again
        sig = _sig(ids[2], h.edit(d));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqTopicVersion.selector, uint32(4), uint32(3)));
        chat.editEntry(d, sig);
        d = _editRec(r, ids[2], 2, 4); // the nonce of an earlier edit, in the original's topic scope
        sig = _sig(ids[2], h.edit(d));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatNonceUsed.selector, PqChatTypes.scopeEntry(t, ids[2]), uint64(2)));
        chat.editEntry(d, sig);
        bytes32 rr = _post(chat, t, ids[3], 1, r); // replies attach to the original id
        assertEq(chat.entryOf(rr).parentId, r);
        (, uint256 n) = chat.byAuthor(ids[2], 0, 0);
        assertEq(n, 1, "edits are not listed");
    }

    // 6. bodies and references
    function test_topics_bodiesAndRefs() public {
        bytes32 t = _newTopic(true);
        bytes memory big = new bytes(150_000); // over two 65,535 B blobs
        for (uint256 i; i < big.length; i += 97) big[i] = bytes1(uint8(i));
        IPqChat.PqTopicEntry memory e = _entryRec(t, ids[0], 1, 0, big);
        bytes32 p = _postRec(chat, e);
        assertEq(keccak256(chat.entryOf(p).body), keccak256(big), "read back byte-exact");
        _refusedPost(chat, _entryRec(t, ids[0], 2, 0, ""), abi.encodeWithSelector(IPqChat.PqTopicShape.selector));
        e = _entryRec(t, ids[0], 2, 0, "x");
        e.mediaType = string(new bytes(65));
        _refusedPost(chat, e, abi.encodeWithSelector(IPqChat.PqTopicShape.selector));
        e.mediaType = "";
        _refusedPost(chat, e, abi.encodeWithSelector(IPqChat.PqTopicShape.selector));
        e = _entryRec(t, ids[0], 2, 0, "x");
        e.ref = IPqChat.EntryRef(keccak256("chain"), address(0xC0FFEE), 0, 0);
        _refusedPost(chat, e, abi.encodeWithSelector(IPqChat.PqTopicRef.selector));
        e.ref = IPqChat.EntryRef(0, address(0), 0, keccak256("hash"));
        _refusedPost(chat, e, abi.encodeWithSelector(IPqChat.PqTopicRef.selector));
        e.ref = IPqChat.EntryRef(keccak256("chain"), address(0xC0FFEE), keccak256("nothing there"), 0);
        bytes32 q = _postRec(chat, e); // not checked across chains
        IPqChat.EntryRef memory got = chat.entryOf(q).ref;
        assertEq(keccak256(abi.encode(got)), keccak256(abi.encode(e.ref)), "returned as given");
        IPqChat.PqTopic memory tr = _topicRec(ids[0], 9, true);
        tr.name = string(new bytes(513)); // owner 2026-11-10: `name` 1-512 B (was 1-128)
        IUARegistry.UASig memory sig = _sig(ids[0], h.topic(tr));
        vm.expectRevert(IPqChat.PqTopicShape.selector);
        chat.createTopic(tr, sig);
        tr.name = "";
        sig = _sig(ids[0], h.topic(tr));
        vm.expectRevert(IPqChat.PqTopicShape.selector);
        chat.createTopic(tr, sig);
        tr.name = string(new bytes(512));
        _createTopic(chat, tr); // the control
    }

    /// Owner 2026-11-10: `updateTopic`'s `name` is 1-512 B as `createTopic`'s: 513 B and "" refused (`PqTopicShape`), 512 B
    /// lands and reads back.
    function test_topics_updateNameBound() public {
        bytes32 t = _newTopic(true);
        IPqChat.PqTopicUpdate memory u = IPqChat.PqTopicUpdate(t, 1, string(new bytes(513)), "", true);
        IUARegistry.UASig memory sig = _sig(ids[0], h.topicUpdate(u));
        vm.expectRevert(IPqChat.PqTopicShape.selector);
        chat.updateTopic(u, sig);
        u.name = "";
        sig = _sig(ids[0], h.topicUpdate(u));
        vm.expectRevert(IPqChat.PqTopicShape.selector);
        chat.updateTopic(u, sig);
        u.name = string(new bytes(512));
        chat.updateTopic(u, _sig(ids[0], h.topicUpdate(u))); // the control
        (IPqChat.PqTopic memory got, uint64 seq) = chat.topicOf(t);
        assertEq(bytes(got.name).length, 512);
        assertEq(seq, 1);
    }

    /// Owner 2026-11-10: a 512 B `name` beside an `about` longer than one blob (`LIMIT` 131,072: a blob holds 65,534 B): the
    /// record is stored by `_put` as every record is, a chain of blobs (as an entry body over one blob), and reads back whole;
    /// the same for the update. `about` has no bound of its own, so a long one chains with any name.
    function test_topics_longAboutAndNameChain() public {
        IPqChat.PqTopic memory tr = _topicRec(ids[0], 9, true);
        tr.name = string(new bytes(512));
        tr.about = new bytes(70_000);
        tr.about[69_999] = 0x7e;
        bytes32 t = _createTopic(chat, tr);
        (IPqChat.PqTopic memory got,) = chat.topicOf(t);
        assertEq(keccak256(abi.encode(got)), keccak256(abi.encode(tr)), "the topic as signed");
        IPqChat.PqTopicUpdate memory u = IPqChat.PqTopicUpdate(t, 1, string(new bytes(512)), new bytes(66_000), false);
        chat.updateTopic(u, _sig(ids[0], h.topicUpdate(u)));
        (got,) = chat.topicOf(t);
        assertEq(bytes(got.name).length, 512);
        assertEq(keccak256(got.about), keccak256(u.about));
        assertFalse(got.openReplies);
    }

    // 7. nonces
    function test_topics_nonces() public {
        bytes32 t = _newTopic(true);
        _post(chat, t, ids[0], 5, 0);
        _post(chat, t, ids[0], 4, 0); // any order
        _refusedPost(chat, _entryRec(t, ids[0], 5, 0, "other"), abi.encodeWithSelector(IPqChat.PqChatNonceUsed.selector,
            PqChatTypes.scopeEntry(t, ids[0]), uint64(5)));
        IPqChat.PqTopicEntry memory e = _entryRec(t, ids[0], 6, 0, "x");
        IUARegistry.UASig memory forged = _sig(ids[1], h.entry(e));
        vm.expectRevert(_unauthorized(ids[0]));
        chat.postEntry(e, forged);
        assertFalse(chat.entryNonceUsed(t, ids[0], 6), "a forged record burns no nonce");
        assertTrue(chat.entryNonceUsed(t, ids[0], 5));
        assertTrue(chat.topicNonceUsed(ids[0], 1));
        IPqChat.PqTopic memory tr = _topicRec(ids[0], 1, false);
        IUARegistry.UASig memory sig = _sig(ids[0], h.topic(tr));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatNonceUsed.selector, PqChatTypes.scopeTopic(ids[0]), uint64(1)));
        chat.createTopic(tr, sig);
    }

    // 8. paged views
    function test_topics_pagedViews() public {
        bytes32 t1 = _newTopic(true);
        bytes32 t2 = _createTopic(chat, _topicRec(ids[0], 2, true));
        bytes32 t3 = _createTopic(chat, _topicRec(ids[1], 1, true));
        bytes32 a = _post(chat, t1, ids[0], 1, 0);
        bytes32 b = _post(chat, t2, ids[0], 1, 0);
        bytes32 c = _post(chat, t3, ids[1], 1, 0);
        _post(chat, t3, ids[0], 2, c); // a reply by ids[0] in another owner's topic
        (bytes32[] memory l, uint256 n) = chat.topics(0, 10);
        assertEq(n, 3);
        assertEq(l.length, 3);
        assertEq(l[2], t3);
        (l, n) = chat.topics(1, 1);
        assertEq(l.length, 1);
        assertEq(l[0], t2);
        (l, n) = chat.topics(3, 5);
        assertEq(l.length, 0, "start at the end");
        assertEq(n, 3);
        (l,) = chat.topics(9, 5);
        assertEq(l.length, 0, "start past the end");
        (l, n) = chat.topicsByOwner(ids[0], 0, 10);
        assertEq(n, 2);
        assertEq(l[1], t2);
        (l, n) = chat.byAuthor(ids[0], 0, 10);
        assertEq(n, 3, "across topics, replies included");
        assertEq(l[0], a);
        assertEq(l[1], b);
        (l, n) = chat.byAuthor(ids[0], 2, 10);
        assertEq(l.length, 1, "count clipped at the end");
    }

    // 9. two instances
    function test_topics_copyIntoAnotherInstance() public {
        bytes32 t = _newTopic(true);
        IPqChat.PqTopicEntry memory pe = _entryRec(t, ids[0], 1, 0, "post");
        bytes32 p = _postRec(chat, pe);
        IPqChat.PqTopicEntry memory re = _entryRec(t, ids[2], 1, p, "reply");
        bytes32 r = _postRec(chat, re);
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqTopicUnknown.selector, t));
        chatB.topicOf(t);
        // copied in order: the same ids; a reply before its parent refused there, then accepted
        _createTopic(chatB, _topicRec(ids[0], 1, true));
        _refusedPost(chatB, re, abi.encodeWithSelector(IPqChat.PqTopicParent.selector, p));
        assertEq(_postRec(chatB, pe), p);
        assertEq(_postRec(chatB, re), r);
    }

    // 10. msig owner, type separation
    function test_topics_msigOwnerAndTypeSeparation() public {
        _register(p, 0x0101, _key(0x0101));
        _register(p, 0x0102, _key(0x0102));
        (uint16 lo, uint16 hi) = UAKinds.uaOf(0x0101, _key(0x0101)) < UAKinds.uaOf(0x0102, _key(0x0102))
            ? (uint16(0x0101), uint16(0x0102)) : (uint16(0x0102), uint16(0x0101));
        Member[] memory mm = new Member[](2);
        mm[0] = Member(lo, UAKinds.uaOf(lo, _key(lo)), 1);
        mm[1] = Member(hi, UAKinds.uaOf(hi, _key(hi)), 1);
        bytes memory d = _msigKey(2, mm);
        bytes32 ms = UACall.register(p, UAKinds.MSIG, d, _none(), "", "");
        p.acceptMembership(ms, _acceptKeySig(d, lo, _key(lo)));
        p.acceptMembership(ms, _acceptKeySig(d, hi, _key(hi)));
        IPqChat.PqTopic memory tr = _topicRec(ms, 1, true);
        bytes32 t = chat.createTopic(tr, _quorum(ms, lo, hi, h.topic(tr)));
        IPqChat.PqTopicWriter memory w = IPqChat.PqTopicWriter(t, ids[1], true, 1);
        chat.setTopicWriter(w, _quorum(ms, lo, hi, h.topicWriter(w)));
        _post(chat, t, ids[1], 1, 0);
        // a session record's signature is no topic record's
        (IPqChat.PqChatSession memory s,) = _session(2, 1, address(chat));
        IPqChat.PqTopic memory t2 = _topicRec(ids[0], 2, true);
        IUARegistry.UASig memory sessionSig = _sig(ids[0], h.session(s));
        vm.expectRevert(_unauthorized(ids[0]));
        chat.createTopic(t2, sessionSig);
    }

    function _quorum(bytes32 ms, uint16 lo, uint16 hi, bytes32 digest) internal view returns (IUARegistry.UASig memory q) {
        bytes32 md = _memberDigest(ms, UAKinds.PURPOSE_PQCHAT, digest);
        q.members = new IUARegistry.MemberSig[](2);
        q.members[0] = IUARegistry.MemberSig(0, new IUARegistry.InnerSig[](0), _sig(_key(lo), UAKinds.uaMessage(lo, UAKinds.PURPOSE_MEMBER, md)));
        q.members[1] = IUARegistry.MemberSig(1, new IUARegistry.InnerSig[](0), _sig(_key(hi), UAKinds.uaMessage(hi, UAKinds.PURPOSE_MEMBER, md)));
    }

    function test_topics_unknownIds() public {
        bytes32 x = keccak256("x");
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqTopicUnknown.selector, x));
        chat.entryOf(x);
        IPqChat.PqTopicUpdate memory u = IPqChat.PqTopicUpdate(x, 1, "n", "", true);
        IUARegistry.UASig memory sig = _sig(ids[0], h.topicUpdate(u));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqTopicUnknown.selector, x));
        chat.updateTopic(u, sig);
        _refusedPost(chat, _entryRec(x, ids[0], 1, 0, "x"), abi.encodeWithSelector(IPqChat.PqTopicUnknown.selector, x));
        IPqChat.PqTopicEdit memory d = _editRec(x, ids[0], 1, 2);
        sig = _sig(ids[0], h.edit(d));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqTopicUnknown.selector, x));
        chat.editEntry(d, sig);
    }
}
