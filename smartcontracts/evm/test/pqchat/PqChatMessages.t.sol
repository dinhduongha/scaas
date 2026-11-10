// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {PqChat} from "../../src/pqchat/PqChat.sol";
import {PqChatTypes} from "../../src/pqchat/PqChatTypes.sol";
import {PqChatBase} from "./PqChatBase.sol";

/// Plan 3c T87 (UA-7 T7; spec P16, P29, D11, D15; owner 2026-11-10 `storedRange`): on-chain messages checked by the contract
/// and the chain as a store. Every refusal beside its positive control.
contract PqChatMessagesTest is PqChatBase {
    bytes32 internal sid;
    string internal msgs;

    function setUp() public override {
        super.setUp();
        (sid,) = _newSession(3);
        msgs = vm.readFile("../vectors/pqchat/messages.json");
    }

    /// A fixed device id from `n` (owner 2026-11-10: a 16-byte UUID the device makes, v7 or v4; nothing checks its bits).
    function _dev(uint8 n) internal pure returns (bytes16) {
        return bytes16(keccak256(abi.encode("device", n)));
    }

    function _msg(bytes32 sender, uint8 dn, uint64 counter, uint256 size)
        internal view returns (IPqChat.PqChatMessage memory m)
    {
        (m.sessionId, m.epochId, m.sender, m.device, m.counter) = (sid, sid, sender, _dev(dn), counter);
        m.parents = _list(keccak256("head a"), keccak256("head b"));
        m.ciphertext = new bytes(size);
        for (uint256 i; i < size; i += 32) m.ciphertext[i] = bytes1(uint8(i >> 5));
    }

    function _post(PqChat c, IPqChat.PqChatMessage memory m) internal returns (uint256) {
        return c.postMessage(m, _sig(m.sender, h.message(m)));
    }

    function _refusedPost(IPqChat.PqChatMessage memory m, bytes memory err) internal {
        IUARegistry.UASig memory sig = _sig(m.sender, h.message(m));
        vm.expectRevert(err);
        chat.postMessage(m, sig);
    }

    // ----- postMessage (P16) -----

    /// D11: the record and `keccak256(abi.encode(sig))` in state, the signature's bytes in the event, hashing to it.
    function test_postMessage_memberPostsHashInStateBytesInEvent() public {
        IPqChat.PqChatMessage memory m = _msg(ids[1], 7, 0, 1024);
        IUARegistry.UASig memory sig = _sig(m.sender, h.message(m));
        vm.recordLogs();
        vm.prank(STRANGER);
        assertEq(chat.postMessage(m, sig), 0);
        bytes32 eventSigHash = _postedSigHash(vm.getRecordedLogs(), h.message(m), m.sender);
        assertEq(chat.messageCount(sid), 1);
        (IPqChat.PqChatMessage memory stored, bytes32 sigHash) = chat.messageAt(sid, 0);
        assertEq(keccak256(abi.encode(stored)), keccak256(abi.encode(m)), "header and ciphertext in state");
        assertEq(eventSigHash, sigHash, "the event's bytes hash to the stored hash");
        assertEq(sigHash, keccak256(abi.encode(sig)));
        assertTrue(chat.nonceUsed(PqChatTypes.scopeMessage(sid, m.sender, _dev(7)), 0));
    }

    /// The last `PqChatMessagePosted`'s topics checked; the hash of its signature's bytes.
    function _postedSigHash(Vm.Log[] memory logs, bytes32 messageId, bytes32 sender) internal view returns (bytes32) {
        Vm.Log memory l = logs[logs.length - 1];
        assertEq(l.topics[0], IPqChat.PqChatMessagePosted.selector);
        assertEq(l.topics[1], sid);
        assertEq(l.topics[2], messageId, "messageId = typed(PqChatMessage)");
        assertEq(l.topics[3], sender);
        // data = abi.encode(index, sig) = index ‖ 0x40 ‖ the struct; abi.encode(sig) = 0x20 ‖ the struct
        assertEq(uint256(bytes32(l.data)), 0, "index 0");
        bytes memory tail = new bytes(l.data.length - 64);
        for (uint256 i; i < tail.length; ++i) tail[i] = l.data[64 + i];
        return keccak256(bytes.concat(bytes32(uint256(0x20)), tail));
    }

    function test_postMessage_nonMemberRefused() public {
        _refusedPost(_msg(ids[3], 1, 0, 64), abi.encodeWithSelector(IPqChat.PqChatNotMember.selector, ids[3]));
        _post(chat, _msg(ids[2], 1, 0, 64)); // the control
    }

    function test_postMessage_epochRules() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(3, 2, address(chat));
        bytes32 s2 = _create(chat, s, _slice(w, 0, 1));
        IPqChat.PqChatMessage memory m = _msg(ids[1], 1, 0, 64);
        (m.sessionId, m.epochId) = (s2, s2);
        _refusedPost(m, abi.encodeWithSelector(IPqChat.PqChatIncomplete.selector, s2));
        m.epochId = keccak256("x");
        _refusedPost(m, abi.encodeWithSelector(IPqChat.PqChatUnknown.selector, m.epochId));
        (m.sessionId, m.epochId) = (s2, sid); // the epoch of another session
        _refusedPost(m, abi.encodeWithSelector(IPqChat.PqChatUnknown.selector, sid));
        chat.addWraps(s2, 1, _slice(w, 1, 3));
        (m.sessionId, m.epochId) = (s2, s2);
        _post(chat, m); // the control
        assertEq(chat.messageCount(s2), 1);
        assertEq(chat.messageCount(sid), 0);
    }

    /// The nonce scope `(epochId, sender, device)` over `counter`, in any order.
    function test_postMessage_deviceDimensionAnyOrder() public {
        _post(chat, _msg(ids[1], 1, 0, 32));
        _post(chat, _msg(ids[1], 2, 0, 32)); // another device, the same counter
        _refusedPost(_msg(ids[1], 1, 0, 33), abi.encodeWithSelector(IPqChat.PqChatNonceUsed.selector,
            PqChatTypes.scopeMessage(sid, ids[1], _dev(1)), uint64(0)));
        _post(chat, _msg(ids[1], 1, 5, 32));
        _post(chat, _msg(ids[1], 1, 4, 32)); // 5 before 4
        assertEq(chat.messageCount(sid), 4);
    }

    /// Owner 2026-11-10 (P6): the device id is 16 opaque bytes; no version or variant bit is checked, so a v7, a v4, the
    /// zero id and an id of no UUID shape all post, and two ids that differ only in the version nibble are two scopes.
    function test_postMessage_deviceIdNeverParsed() public {
        bytes16[5] memory d = [bytes16(0x0190f5c0a1e07000800000000000d0c5), bytes16(0x3b2f6c1e9d4a4c7e8f1a2b3c4d5e6f70),
            bytes16(0), bytes16(type(uint128).max), bytes16(0x0190f5c0a1e04000800000000000d0c5)];
        for (uint256 i; i < d.length; ++i) {
            IPqChat.PqChatMessage memory m = _msg(ids[1], 1, 0, 32);
            m.device = d[i];
            _post(chat, m);
            assertTrue(chat.nonceUsed(PqChatTypes.scopeMessage(sid, ids[1], d[i]), 0));
        }
        assertEq(chat.messageCount(sid), 5, "counter 0 on each of the five ids");
    }

    /// Fable P1-1 (spec §6.3): at home, once an epoch has a complete child, a message under it is refused
    /// (`PqChatEpochTaken`); before the child, the same post is accepted (the control); the new epoch takes it; a replica,
    /// which orders nothing, still takes a message under the old epoch.
    function test_postMessage_supersededEpochRefusedAtHome() public {
        _post(chat, _msg(ids[1], 1, 0, 32));
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory w) = _epoch(sid, ids[0], 1, 1, sid, _list(ids[0]), _members(3));
        bytes32 e1 = _rekey(chat, e, w);
        _refusedPost(_msg(ids[1], 1, 1, 32), abi.encodeWithSelector(IPqChat.PqChatEpochTaken.selector, sid, e1));
        IPqChat.PqChatMessage memory m = _msg(ids[1], 1, 1, 32);
        m.epochId = e1;
        _post(chat, m);
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory sw) = _session(3, 1, address(chat));
        _create(chatB, s, sw);
        _rekey(chatB, e, w);
        _post(chatB, _msg(ids[1], 1, 1, 32));
        assertEq(chatB.messageCount(sid), 1);
    }

    function test_postMessage_forgedBurnsNoNonce() public {
        IPqChat.PqChatMessage memory m = _msg(ids[1], 1, 9, 32);
        IUARegistry.UASig memory forged = _sig(ids[2], h.message(m));
        vm.expectRevert(_unauthorized(ids[1]));
        chat.postMessage(m, forged);
        assertFalse(chat.nonceUsed(PqChatTypes.scopeMessage(sid, ids[1], _dev(1)), 9));
        _post(chat, m);
    }

    /// P16: one blob per message (the code-size limit, at most 65,535 B of code).
    function test_postMessage_oneBlobOnly() public {
        _refusedPost(_msg(ids[1], 1, 0, 65_400), abi.encodeWithSelector(IPqChat.PqChatShape.selector));
        _post(chat, _msg(ids[1], 1, 0, 65_000)); // the control: just under
    }

    // ----- storeMessage (P29) -----

    function _payload() internal view returns (uint8 v, bytes8 hint, bytes memory env, bytes memory payload) {
        v = uint8(vm.parseJsonUint(msgs, ".payload.v"));
        hint = bytes8(vm.parseJsonBytes(msgs, ".payload.hint"));
        env = vm.parseJsonBytes(msgs, ".payload.env");
        payload = vm.parseJsonBytes(msgs, ".payload.payload");
    }

    /// A stranger with no epoch on this instance stores the vector's payload; `storedAt` returns its bytes.
    function test_storeMessage_strangerStoresTheVectorPayload() public {
        (uint8 v, bytes8 hint, bytes memory env, bytes memory payload) = _payload();
        assertEq(payload, abi.encode(v, hint, env));
        vm.expectEmit(address(chatB));
        emit IPqChat.PqChatStored(hint, 0);
        vm.prank(STRANGER);
        assertEq(chatB.storeMessage(v, hint, env), 0);
        assertEq(chatB.storedCount(hint), 1);
        assertEq(chatB.storedAt(hint, 0), payload);
        assertEq(chatB.storedCount(bytes8(uint64(1))), 0, "listed by hint");
    }

    function test_storeMessage_shapeRefused() public {
        (, bytes8 hint, bytes memory env,) = _payload();
        vm.expectRevert(IPqChat.PqChatShape.selector);
        chat.storeMessage(2, hint, env);
        vm.expectRevert(IPqChat.PqChatShape.selector);
        chat.storeMessage(0, hint, env);
        // the payload over one blob: 128 B of head and length, then the padded env
        vm.expectRevert(IPqChat.PqChatShape.selector);
        chat.storeMessage(1, hint, new bytes(65_407));
        chat.storeMessage(1, hint, new bytes(65_376)); // the control: 65,504 B of payload
        assertEq(chat.storedCount(hint), 1);
    }

    /// Owner 2026-11-10: `storedRange` pages, an offset past the end is empty, the limit clamped to `STORED_RANGE_MAX`, each
    /// element `storedAt`'s.
    function test_storedRange_pages() public {
        bytes8 hint = bytes8(keccak256("hint"));
        for (uint256 i; i < 20; ++i) chat.storeMessage(1, hint, abi.encodePacked(keccak256(abi.encode(i)), uint8(i)));
        bytes[] memory p0 = chat.storedRange(hint, 0, 3);
        bytes[] memory p1 = chat.storedRange(hint, 3, 3);
        assertEq(p0.length, 3);
        assertEq(p1.length, 3);
        for (uint256 i; i < 3; ++i) {
            assertEq(p0[i], chat.storedAt(hint, i));
            assertEq(p1[i], chat.storedAt(hint, 3 + i), "across the page boundary");
        }
        bytes[] memory tail = chat.storedRange(hint, 18, 5);
        assertEq(tail.length, 2, "cut at the end");
        assertEq(tail[1], chat.storedAt(hint, 19));
        assertEq(chat.storedRange(hint, 20, 5).length, 0, "an offset at the end: empty");
        assertEq(chat.storedRange(hint, 1000, 5).length, 0, "past the end: empty");
        assertEq(chat.storedRange(bytes8(0), 0, 5).length, 0, "an empty list");
        assertEq(chat.STORED_RANGE_MAX(), 16);
        bytes[] memory all = chat.storedRange(hint, 0, type(uint256).max);
        assertEq(all.length, 16, "the limit clamped");
        assertEq(all[15], chat.storedAt(hint, 15));
        assertEq(chat.storedRange(hint, 10, 100).length, 10, "clamped, then cut at the end");
        assertEq(chat.storedRange(hint, 0, 0).length, 0);
    }
}
