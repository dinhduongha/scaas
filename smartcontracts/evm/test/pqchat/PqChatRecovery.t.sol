// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {PqChat} from "../../src/pqchat/PqChat.sol";
import {PqChatTypes} from "../../src/pqchat/PqChatTypes.sol";
import {PqChatBase} from "./PqChatBase.sol";

/// Plan 3c T96 (owner 2026-11-10: recovery from state alone): `sessionsOf` / `sessionCount`, `epochsOf` / `epochCount` and
/// `latestEpoch`, each list paged and clamped, an offset past the end empty.
contract PqChatRecoveryTest is PqChatBase {
    function _ids(PqChat c, bytes32 ua, uint256 offset, uint256 limit) internal view returns (bytes32[] memory) {
        return c.sessionsOf(ua, offset, limit);
    }

    function test_sessionsOf_createListsEveryMember() public {
        (bytes32 sid,) = _newSession(3);
        for (uint256 i; i < 3; ++i) {
            assertEq(chat.sessionCount(ids[i]), 1);
            assertEq(_ids(chat, ids[i], 0, 10)[0], sid);
        }
        assertEq(chat.sessionCount(ids[3]), 0);
        assertEq(_ids(chat, ids[3], 0, 10).length, 0);
    }

    /// A rekey lists only the members it adds; a removed member keeps its entry.
    function test_sessionsOf_rekeyListsAddedOnly() public {
        (bytes32 sid,) = _newSession(3);
        IPqChat.MemberKey[] memory m = _without(_members(4), ids[2]); // ids[3] added, ids[2] removed
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w) = _epoch(sid, ids[0], 1, 1, sid, _list(ids[0]), m);
        _rekey(chat, e, w);
        assertEq(chat.sessionCount(ids[3]), 1);
        assertEq(_ids(chat, ids[3], 0, 1)[0], sid);
        assertEq(chat.sessionCount(ids[0]), 1, "kept members: no new entry");
        assertEq(chat.sessionCount(ids[1]), 1);
        assertEq(chat.sessionCount(ids[2]), 1, "the removed member keeps its entry");
        // a plain rekey adds nobody
        (e, w) = _epoch(sid, ids[1], 1, 2, PqChatTypes.epochId(sid, ids[0], 1), _list(ids[0]), m);
        _rekey(chat, e, w);
        for (uint256 i; i < 4; ++i) assertEq(chat.sessionCount(ids[i]), 1);
    }

    function test_sessionsOf_pagesAndEnd() public {
        bytes32[] memory all = new bytes32[](5);
        for (uint64 n = 1; n <= 5; ++n) {
            (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(2, n, address(chat));
            all[n - 1] = _create(chat, s, w);
        }
        assertEq(chat.sessionCount(ids[0]), 5);
        bytes32[] memory a = _ids(chat, ids[0], 0, 2);
        bytes32[] memory b = _ids(chat, ids[0], 2, 2);
        bytes32[] memory c = _ids(chat, ids[0], 4, 2);
        assertEq(a.length, 2);
        assertEq(b.length, 2);
        assertEq(c.length, 1, "cut at the end");
        assertEq(a[0], all[0]); assertEq(a[1], all[1]); assertEq(b[0], all[2]); assertEq(b[1], all[3]);
        assertEq(c[0], all[4]);
        assertEq(_ids(chat, ids[0], 5, 2).length, 0, "at the end: empty");
        assertEq(_ids(chat, ids[0], 99, 2).length, 0, "past the end: empty");
    }

    /// The clamp, on a list made long through its slot (the layout is pinned in `PqChatLayout.t.sol`).
    function test_sessionsOf_limitClamped() public {
        assertEq(chat.SESSIONS_RANGE_MAX(), 128);
        uint256 root = uint256(keccak256(abi.encode(uint256(keccak256("scaas.pqchat")) - 1))) & ~uint256(0xff);
        bytes32 listSlot = keccak256(abi.encode(ids[0], root + 19));
        vm.store(address(chat), listSlot, bytes32(uint256(200)));
        assertEq(chat.sessionCount(ids[0]), 200);
        assertEq(_ids(chat, ids[0], 0, type(uint256).max).length, 128);
        assertEq(_ids(chat, ids[0], 100, 1000).length, 100, "clamped, then cut at the end");
    }

    // ----- latestEpoch -----

    function test_latestEpoch_movesOnCompletionOnly() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(3, 1, address(chat));
        bytes32 sid = _create(chat, s, _slice(w, 0, 2));
        assertEq(chat.latestEpoch(sid), bytes32(0), "the session not complete");
        chat.addWraps(sid, 2, _slice(w, 2, 3));
        assertEq(chat.latestEpoch(sid), sid);
        // an incomplete child does not move it
        (IPqChat.PqChatEpoch memory a, IPqChat.Wrap[] memory aw) = _epoch(sid, ids[1], 1, 1, sid, _list(ids[0]), _members(3));
        chat.rekey(a, _slice(aw, 0, 1), _sig(a.author, h.epoch(a)));
        assertEq(chat.latestEpoch(sid), sid);
        (IPqChat.PqChatEpoch memory b, IPqChat.Wrap[] memory bw) = _epoch(sid, ids[0], 1, 1, sid, _list(ids[0]), _members(2));
        bytes32 eb = _rekey(chat, b, bw);
        assertEq(chat.latestEpoch(sid), eb, "the child taking the slot");
        (IPqChat.PqChatEpoch memory c, IPqChat.Wrap[] memory cw) = _epoch(sid, ids[1], 2, 2, eb, _list(ids[0]), _members(2));
        bytes32 ec = chat.rekey(c, _slice(cw, 0, 1), _sig(c.author, h.epoch(c)));
        assertEq(chat.latestEpoch(sid), eb);
        chat.addWraps(ec, 1, _slice(cw, 1, 2));
        assertEq(chat.latestEpoch(sid), ec);
    }

    /// `epochsOf` at home is the `childOf` chain from the session; an incomplete or losing child never appears; `latestEpoch`
    /// is the last entry.
    function test_epochsOf_homeIsTheChildOfChain() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(3, 1, address(chat));
        bytes32 sid = _create(chat, s, _slice(w, 0, 2));
        assertEq(chat.epochCount(sid), 0, "the session not complete");
        chat.addWraps(sid, 2, _slice(w, 2, 3));
        (IPqChat.PqChatEpoch memory a, IPqChat.Wrap[] memory aw) = _epoch(sid, ids[1], 1, 1, sid, _list(ids[0]), _members(3));
        bytes32 ea = chat.rekey(a, _slice(aw, 0, 1), _sig(a.author, h.epoch(a))); // incomplete, then losing
        (IPqChat.PqChatEpoch memory b, IPqChat.Wrap[] memory bw) = _epoch(sid, ids[0], 1, 1, sid, _list(ids[0]), _members(2));
        bytes32 eb = _rekey(chat, b, bw);
        (IPqChat.PqChatEpoch memory c, IPqChat.Wrap[] memory cw) = _epoch(sid, ids[1], 2, 2, eb, _list(ids[0]), _members(2));
        bytes32 ec = _rekey(chat, c, cw);
        bytes32[] memory l = chat.epochsOf(sid, 0, 10);
        assertEq(l.length, 3);
        assertEq(l[0], sid); assertEq(l[1], eb); assertEq(l[2], ec);
        assertEq(chat.childOf(sid), l[1]);
        assertEq(chat.childOf(l[1]), l[2]);
        assertEq(chat.latestEpoch(sid), ec);
        for (uint256 i; i < l.length; ++i) assertTrue(l[i] != ea, "the losing child never listed");
        bytes32[] memory p1 = chat.epochsOf(sid, 1, 1);
        bytes32[] memory p2 = chat.epochsOf(sid, 2, 5);
        assertEq(p1.length, 1);
        assertEq(p2.length, 1);
        assertEq(p1[0], eb); assertEq(p2[0], ec);
        assertEq(chat.epochsOf(sid, 3, 5).length, 0, "at the end: empty");
        assertEq(chat.epochsOf(sid, 50, 5).length, 0, "past the end: empty");
        assertEq(chat.epochsOf(keccak256("unknown"), 0, 5).length, 0);
    }

    function test_epochsOf_limitClamped() public {
        (bytes32 sid,) = _newSession(2);
        assertEq(chat.EPOCHS_RANGE_MAX(), 128);
        uint256 root = uint256(keccak256(abi.encode(uint256(keccak256("scaas.pqchat")) - 1))) & ~uint256(0xff);
        vm.store(address(chat), keccak256(abi.encode(sid, root + 20)), bytes32(uint256(199))); // 199 children + epoch 0
        assertEq(chat.epochCount(sid), 200);
        bytes32[] memory all = chat.epochsOf(sid, 0, type(uint256).max);
        assertEq(all.length, 128);
        assertEq(all[0], sid);
        assertEq(chat.epochsOf(sid, 150, 1000).length, 50, "clamped, then cut at the end");
    }

    /// A replica lists every complete epoch in the order it completed there, competing children included.
    function test_epochsOf_replicaCompletionOrder() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(3, 1, address(chat));
        bytes32 sid = chatB.createSession(s, w, _sig(s.creator, h.session(s))); // a copy: the home is A
        assertEq(chatB.latestEpoch(sid), sid);
        (IPqChat.PqChatEpoch memory a, IPqChat.Wrap[] memory aw) =
            _epoch(sid, ids[0], 1, 1, sid, _list(ids[0]), _without(_members(3), ids[2]));
        (IPqChat.PqChatEpoch memory b, IPqChat.Wrap[] memory bw) = _epoch(sid, ids[2], 1, 1, sid, _list(ids[0]), _members(3));
        bytes32 ea = chatB.rekey(a, _slice(aw, 0, 1), _sig(a.author, h.epoch(a)));
        bytes32 eb = _rekey(chatB, b, bw);
        chatB.addWraps(ea, 1, _slice(aw, 1, 2));
        bytes32[] memory l = chatB.epochsOf(sid, 0, 10);
        assertEq(l.length, 3);
        assertEq(l[0], sid); assertEq(l[1], eb); assertEq(l[2], ea);
        assertEq(chatB.latestEpoch(sid), ea, "the last to complete here");
        assertEq(chatB.childOf(sid), bytes32(0));
        assertEq(chatB.sessionCount(ids[0]), 1, "the replica indexes its own records");
    }
}
