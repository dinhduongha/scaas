// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {EnvKit} from "../helpers/EnvKit.sol";
import {MetaTxLib} from "../../src/common/MetaTxLib.sol";
import {Vm} from "forge-std/Vm.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {PqChatTypes} from "../../src/pqchat/PqChatTypes.sol";
import {PqChat} from "../../src/pqchat/PqChat.sol";
import {PqChatTopics} from "../../src/pqchat/PqChatTopics.sol";
import {PqTopicsBase} from "./PqTopicsBase.sol";

/// A CREATE2 in its own call, so `vm.lastCallGas` is that deployment's transaction (`isolate = true`).
contract Create2Once {
    function deploy(bytes memory code, bytes32 salt) external returns (address a) {
        assembly ("memory-safe") {
            a := create2(0, add(code, 32), mload(code), salt)
        }
        require(a != address(0), "create2");
    }
}

/// Plan 3c T90 (UA-7 T9, PT4; owner 2026-11-10: the 2-person chat first):
// gas rows of `PqChat`, `isolate = true`, so each
/// figure is one transaction's: `vm.lastCallGas()` regular gas (intrinsic and calldata floor included) and the EIP-8037

// // state gas apart. Signatures go through the stand-in verifier (`MockVerifier`, no work), so a row is `PqChat`'s and the
/// registry's own cost; a real signer adds its verifier's gas (regular):
// FN-DSA-512 about 2.3 M, ML-DSA-65 on the cached key
/// about 5.8 M, an EIP-8355 precompile about 0.2 M (spec §11; pinned in `test/ua`). New pins:
// regular within ±500 gas, state
/// exact; a move needs old -> new figures in its commit.
contract PqChatGasTest is PqTopicsBase {
    uint256 internal constant SLACK = 500;
    // round 3r T4 (R1, Q4: `factoryInfo()` six words, no owner):
    // 27,825 -> 27,801 B; regular 1,908,760 -> 1,906,679; state
    // 43,147,530 -> 43,110,810 (-24 x 1,530)
    // Fable D P3-1 (2026-11-11, `initialize` checks `creating()`): 27,801 -> 27,999 B; regular 1,906,679 -> 1,921,243;
    // state 43,110,810 -> 43,413,750 (+198 x 1,530)
    // fix2 CTR-GOV-26 (owner 2026-11-12, `rescue(asset)` to the constant dev address): 27,999 -> 28,776 B; regular
    // 1,921,243 -> 1,971,175; state 43,413,750 -> 44,602,560 (+777 x 1,530)
    // fix2 recheck-2 P3-1 (CTR-GOV-27, `deployImplementation`'s last `chainUid_`:
    // one more calldata word, the EIP-7976 floor;
    // PqChat unchanged): regular 1,971,175 -> 1,973,256
    // pqvault R3 (CTR-PQV-12:
    // the group code in `PqGroupBase`, its errors through `_fail`; behaviour unchanged, CTR-PQV-15):
    // 28,776 -> 29,152 B; regular 1,973,256 -> 1,998,222; state 44,602,560 -> 45,177,840 (+376 x 1,530)
    // code-format F2 (`bytecode_hash = "none"`:
    // the metadata hash leaves runtime and init code, 41 B each; code unchanged):
    // 29,152 -> 29,111 B; regular 1,998,222 -> 1,996,141; state 45,177,840 -> 45,115,110 (-41 x 1,530)

    //    // pqvault review F1 / F2 / F7 (controller call 2026-11-21, `PqGroupBase._liveAdmin` and the author check at completion; O2 (a)
    // precedent): 29,111 -> 29,383 B; regular 1,996,141 -> 2,012,785; state 45,115,110 -> 45,531,270 (+272 x 1,530)
    // pqvault review F3 in PqChat too (controller call 2026-11-21, `PqGroupBase._removable`:
    // an admin that is no member is
    // removable): 29,383 -> 29,412 B; regular 2,012,785 -> 2,014,866; state 45,531,270 -> 45,575,640 (+29 x 1,530)
    // CTR-CHAT-23 (owner 2026-11-23: the signature-storage setting, its views, the kept blobs and the `_authorOf` hook):
    // 29,412 ->
    // 31,419 B; regular 2,014,866 -> 2,145,938; state 45,575,640 -> 48,646,350 (+2,007 x 1,530)
    // owner (M) 2026-11-23, CTR-CHAT-24: members by `(ua, keyId)`, the distinct-UA count:
    // 31,419 -> 31,897 B; regular 2,145,938
    // -> 2,177,145; state 48,646,350 -> 49,377,690 (+478 x 1,530)
    // CTR-CHAT-25 (owner 2026-11-23, `groupMode`, one word more in calldata and the record, the last field):
    // 31,897 -> 32,069 B; regular 2,177,145 ->
    // 2,187,548; state 49,377,690 -> 49,640,850 (+172 x 1,530)
    // TreeKEM T3a part 1 (`PqGroupBase._land` split into `_storeWraps` and `_complete`, `_authorOf` moved to `PqChatCore`):
    // 32,069 -> 32,104 B; regular 2,187,548 -> 2,189,628; state 49,640,850 -> 49,694,400 (+35 x 1,530)
    // TreeKEM T3a (CTR-CHAT-26: the immutable `TREE`, its check in the constructor, the dispatch of `createSession` and
    // `addWraps` to it, `rekey` refused on a tree session, `modules()` of two, `groupMode` 1 accepted):
    // 32,104 -> 32,695 B; regular 2,189,628 -> 2,247,883; state 49,694,400 -> 50,598,630 (+591 x 1,530)
    uint256 internal constant RUNTIME = 32_695;
    uint256 internal constant RELEASE_REGULAR = 2_247_883;
    uint256 internal constant RELEASE_STATE = 50_598_630;
    // owner 2026-11-10 (group 3p): the topic `name` bound 128 -> 512 B, one PUSH2 for a PUSH1 twice:
    // 16,396 -> 16,398 B, state
    // 25,269,480 -> 25,272,540 (+2 x 1,530), regular unchanged
    // pqvault R3 (CTR-PQV-12: the shared code from `PqGroupBase`, the env and nonce errors through `PqChatCore._fail`):
    // 16,398 ->
    // 16,449 B; regular 1,099,442 -> 1,101,523; state 25,272,540 -> 25,350,570 (+51 x 1,530)
    // code-format F2 (`bytecode_hash = "none"`, 41 B less runtime and init code; code unchanged):
    // 16,449 -> 16,408 B; regular
    // 1,101,523 -> 1,099,442; state 25,350,570 -> 25,287,840 (-41 x 1,530)
    uint256 internal constant MODULE_RUNTIME = 16_408;
    uint256 internal constant MODULE_REGULAR = 1_099_442;
    uint256 internal constant MODULE_STATE = 25_287_840;

    function _row(string memory what, uint256 regular, uint256 state) internal {
        Vm.Gas memory g = vm.lastCallGas();
        uint256 s = uint256(int256(g.gasStateUsed));
        emit log_named_uint(string.concat("GAS ", what, " regular"), g.gasTotalUsed);
        emit log_named_uint(string.concat("GAS ", what, " state"), s);
        emit log_named_uint(string.concat("GAS ", what, " total"), g.gasTotalUsed + s);
        if (regular != 0 && !vm.envOr("GAS_MEASURE", false)) {
            // GAS_MEASURE=true: the figures, no pin
            assertApproxEqAbs(g.gasTotalUsed, regular, SLACK, string.concat(what, " regular"));
            assertEq(s, state, string.concat(what, " state"));
        }
    }

    function _msg(bytes32 sid, bytes32 eid, bytes32 sender, uint64 counter, uint256 size)
        internal
        pure
        returns (IPqChat.PqChatMessage memory m)
    {
        (m.sessionId, m.epochId, m.sender, m.device, m.counter) =
        (sid, eid, sender, bytes16(0x0190f5c0a1e07000800000000000d0c5), counter);
        m.parents = new bytes32[](2);
        (m.parents[0], m.parents[1]) = (keccak256("a"), keccak256("b"));
        m.ciphertext = new bytes(size);
    }

    // ----- 2 members (the main case) -----

    function test_gas_twoMembers() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(2, 1, address(chat));
        IUARegistry.UASig memory sig = _sig(s.creator, h.session(s));
        vm.prank(STRANGER);
        bytes32 sid = chat.createSession(s, w, sig);
        // CTR-CHAT-23 (the tests' instance at `sstore2`:
        // one SLOAD of the setting, the 32-B stand-in signature kept, 256 B more
        // per blob): 340,852 / 7,691,310 -> 344,756 / 8,082,990 (+256 x 1,530)
        // owner (M) 2026-11-23, CTR-CHAT-24: members by `(ua, keyId)`, the distinct-UA count:
        // regular 344,756 -> 345,909
        // CTR-CHAT-25 / CTR-PQV-18 (owner 2026-11-23: `groupMode` in the session and create records, one word more, 0 only):
        // 345,909 / 8,082,990 -> 346,600 / 8,131,950
        _row("createSession 2 members, both wraps, index 2", 346_600, 8_131_950);

        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory ew) = _epoch(sid, ids[1], 1, 1, sid, s.admins, s.members);
        sig = _sig(e.author, h.epoch(e));
        vm.prank(STRANGER);
        bytes32 e1 = chat.rekey(e, ew, sig);
        // CTR-CHAT-23: 367,359 / 7,740,270 -> 371,249 / 8,131,950
        // owner (M) 2026-11-23, CTR-CHAT-24: members by `(ua, keyId)`, the distinct-UA count:
        // regular 371,249 -> 373,424
        // TreeKEM T3a (CTR-CHAT-27: `rekey` reads the tree namespace to refuse a tree session): regular 373,424 -> 375,895
        _row("rekey 2 members, plain, first epoch list entry", 375_895, 8_131_950);

        (e, ew) = _epoch(sid, ids[0], 1, 2, e1, s.admins, s.members);
        sig = _sig(e.author, h.epoch(e));
        vm.prank(STRANGER);
        bytes32 e2 = chat.rekey(e, ew, sig);
        // CTR-CHAT-23: 367,240 / 7,642,350 -> 371,131 / 8,034,030
        // owner (M) 2026-11-23, CTR-CHAT-24: members by `(ua, keyId)`, the distinct-UA count:
        // regular 371,131 -> 373,306
        // TreeKEM T3a (the tree-session read in `rekey`): regular 373,306 -> 375,633
        _row("rekey 2 members, plain, next epoch list entry", 375_633, 8_034_030);

        IPqChat.PqChatMessage memory m = _msg(sid, e2, ids[1], 0, 1040); // a 1,024-B bucket + the GCM-SIV tag
        sig = _sig(m.sender, h.message(m));
        vm.prank(STRANGER);
        chat.postMessage(m, sig);
        // CTR-CHAT-23: 153,744 / 2,732,580 -> 157,767 / 3,124,260
        _row("postMessage 2 members, 1,040 B ciphertext", 157_767, 3_124_260);

        m = _msg(sid, e2, ids[1], 1, 1040);
        sig = _sig(m.sender, h.message(m));
        vm.prank(STRANGER);
        chat.postMessage(m, sig);
        // CTR-CHAT-23: 153,756 / 2,536,740 -> 157,779 / 2,928,420
        _row("postMessage 2 members, 1,040 B ciphertext, warm list", 157_779, 2_928_420);

        IPqChat.PqChatLeave memory l = IPqChat.PqChatLeave(sid, e2, ids[1], 9);
        sig = _sig(ids[1], h.leave(l));
        vm.prank(STRANGER);
        chat.leave(l, sig);
        // CTR-CHAT-23 (`sstore2` keeps the leave record and its signature: a blob, the list's slots):
        // 107,485 / 97,920 ->
        // 150,721 / 1,116,900
        _row("leave 2 members", 150_721, 1_116_900);
    }

    /// Owner (M) 2026-11-23 (CTR-CHAT-24): a member's device key is one more `(ua, keyId)` entry and one more wrap: a

    //    /// 2-member session whose creator adds a device key (3 wraps), and a plain rekey by the other member adding its own (4).
    function test_gas_deviceKeys() public {
        _devices(ids[0], 1);
        _devices(ids[1], 1);
        (IPqChat.PqChatSession memory s,) = _session(2, 1, address(chat));
        IPqChat.MemberKey[] memory m = new IPqChat.MemberKey[](3);
        (bytes32 a, bytes32 b) = (s.members[0].ua, s.members[1].ua);
        (m[0], m[1], m[2]) =
        (IPqChat.MemberKey(a, 0, bytes32(0)), IPqChat.MemberKey(a, 1, bytes32(0)), IPqChat.MemberKey(b, 0, bytes32(0)));
        s.members = m;
        IPqChat.Wrap[] memory w = _wraps(m, PqChatTypes.sessionId(s.creator, 1));
        s.wrapHashes = _hashes(w);
        IUARegistry.UASig memory sig = _sig(s.creator, h.session(s));
        vm.prank(STRANGER);
        bytes32 sid = chat.createSession(s, w, sig);
        // a device key adds one wrap:
        // +108,944 regular, +2,876,400 state (the wrap's 1,688 B, its slot, its MemberKey and hash
        // in the record) over the 2-wrap row
        // CTR-CHAT-25 / CTR-PQV-18 (owner 2026-11-23: `groupMode` in the session and create records, one word more, 0 only):
        // 453,528 / 10,959,390 -> 455,576 / 11,008,350
        _row("createSession 2 members, 3 wraps (a device key)", 455_576, 11_008_350);
        IPqChat.MemberKey[] memory m4 = new IPqChat.MemberKey[](4);
        (m4[0], m4[1], m4[2], m4[3]) = (m[0], m[1], m[2], IPqChat.MemberKey(b, 1, bytes32(0)));
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory ew) = _epoch(sid, ids[1], 1, 1, sid, s.admins, m4);
        sig = _sig(e.author, h.epoch(e));
        vm.prank(STRANGER);
        chat.rekey(e, ew, sig);
        // +105,588 regular, +2,876,400 state per extra wrap over the plain 2-member rekey (373,424 / 8,131,950)
        _row("rekey 2 members, plain, 4 wraps (two device keys)", 584_600, 13_884_750);
    }

    function test_gas_twoMembersInChunks() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(2, 1, address(chat));
        IUARegistry.UASig memory sig = _sig(s.creator, h.session(s));
        IPqChat.Wrap[] memory first = _slice(w, 0, 1);
        vm.prank(STRANGER);
        bytes32 sid = chat.createSession(s, first, sig);
        // CTR-CHAT-23: 293,223 / 5,010,750 -> 297,087 / 5,402,430
        // owner (M) 2026-11-23, CTR-CHAT-24: members by `(ua, keyId)`, the distinct-UA count:
        // regular 297,087 -> 298,235
        // CTR-CHAT-25 / CTR-PQV-18 (owner 2026-11-23: `groupMode` in the session and create records, one word more, 0 only):
        // 298,235 / 5,402,430 -> 298,914 / 5,451,390
        _row("createSession 2 members, one wrap", 298_914, 5_451_390);
        IPqChat.Wrap[] memory rest = _slice(w, 1, 2);
        vm.prank(STRANGER);
        chat.addWraps(sid, 1, rest);
        _row("addWraps one wrap, completing", 144_280, 2_865_690);
    }

    /// `storeMessage` of a 1,024-B bucket's envelope (spec §11: about 2.4 KB with FN-DSA-512, 5.1 KB with ML-DSA-65).
    function test_gas_storeMessage() public {
        bytes8 hint = bytes8(keccak256("hint"));
        bytes memory env = new bytes(2400);
        vm.prank(STRANGER);
        chat.storeMessage(1, hint, env);
        _row("storeMessage 2,400 B envelope, new hint", 177_048, 4_248_810);
        vm.prank(STRANGER);
        chat.storeMessage(1, hint, env);
        _row("storeMessage 2,400 B envelope, warm hint", 177_048, 4_150_890);
        env = new bytes(5100);
        vm.prank(STRANGER);
        chat.storeMessage(1, hint, env);
        _row("storeMessage 5,100 B envelope, warm hint", 351_128, 8_312_490);
    }

    // ----- groups (correct, not optimised for) -----

    function test_gas_groups() public {
        for (uint8 i = 6; i <= 20; ++i) {
            _member(i);
        }
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(10, 1, address(chat));
        IUARegistry.UASig memory sig = _sig(s.creator, h.session(s));
        vm.prank(STRANGER);
        chat.createSession(s, w, sig);
        // CTR-CHAT-23 (the calldata floor holds the regular figure): state 32,269,230 -> 32,660,910
        // CTR-CHAT-25 / CTR-PQV-18 (owner 2026-11-23: `groupMode` in the session and create records, one word more, 0 only):
        // 1,356,696 / 32,660,910 -> 1,358,744 / 32,709,870
        _row("createSession 10 members, all wraps", 1_358_744, 32_709_870);
        (s, w) = _session(20, 2, address(chat));
        sig = _sig(s.creator, h.session(s));
        vm.prank(STRANGER);
        bytes32 sid = chat.createSession(s, w, sig);
        // CTR-CHAT-23: state 61,914,510 -> 62,306,190
        // CTR-CHAT-25 / CTR-PQV-18 (owner 2026-11-23: `groupMode` in the session and create records, one word more, 0 only):
        // 2,646,936 / 62,306,190 -> 2,648,984 / 62,355,150
        _row("createSession 20 members, all wraps", 2_648_984, 62_355_150);
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory ew) = _epoch(sid, ids[3], 1, 1, sid, s.admins, s.members);
        sig = _sig(e.author, h.epoch(e));
        vm.prank(STRANGER);
        chat.rekey(e, ew, sig);
        // CTR-CHAT-23: state 59,515,470 -> 59,907,150
        _row("rekey 20 members, plain", 2_648_984, 59_907_150);

        //        // all 20 wraps in one call ask more than 60 M ((regular + state) x 1.05), a create (67.8 M) and a rekey (65.3 M)
        // alike:
        // a 20-member record goes in chunks. The 20-member rows are warm (the 10-member session above wrote 11 of
        // the slots and a wrap blob in this test): a cold call is about 1.26 M higher (Fable P3-7).
        assertGt(uint256(2_646_936 + 62_306_190) * 105 / 100, 60_000_000, "20 wraps in one create: over 60 M");
        assertGt(uint256(2_648_984 + 59_907_150) * 105 / 100, 60_000_000, "20 wraps in one rekey: over 60 M");
        (s, w) = _session(20, 3, address(chat));
        sig = _sig(s.creator, h.session(s));
        vm.prank(STRANGER);
        sid = chat.createSession(s, _slice(w, 0, 10), sig);
        // CTR-CHAT-23: 1,519,320 / 34,129,710 -> 1,525,793 / 34,521,390
        // owner (M) 2026-11-23, CTR-CHAT-24: members by `(ua, keyId)`, the distinct-UA count:
        // regular 1,525,793 -> 1,540,631
        // CTR-CHAT-25 / CTR-PQV-18 (owner 2026-11-23: `groupMode` in the session and create records, one word more, 0 only):
        // 1,540,631 / 34,521,390 -> 1,541,381 / 34,570,350
        _row("createSession 20 members, first 10 wraps", 1_541_381, 34_570_350);
        vm.prank(STRANGER);
        chat.addWraps(sid, 10, _slice(w, 10, 20));
        _row("addWraps 10 wraps, completing 20 members", 1_231_768, 26_990_730);
        assertTrue(chat.epochComplete(sid));
    }

    /// UA-7 P48 (owner 2026-11-10): a removal by the admin of a 3-member session, then the rekey that drops the member.
    function test_gas_remove() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(3, 1, address(chat));
        bytes32 sid = _create(chat, s, w);
        IPqChat.PqChatRemove memory r = IPqChat.PqChatRemove(sid, sid, 1, _list(ids[2]), ids[0], 7);
        IUARegistry.UASig memory sig = _sig(ids[0], h.remove(r));
        vm.prank(STRANGER);
        chat.remove(r, sig);
        // pqvault review F2 / F7 (`_liveAdmin`: the admin's removed and left flags read cold):
        // regular 168,513 -> 173,112
        // CTR-CHAT-23: 173,112 / 1,067,940 -> 176,666 / 1,459,620
        _row("remove 1 of 3 members", 176_666, 1_459_620);
        IPqChat.MemberKey[] memory m = new IPqChat.MemberKey[](2);
        (m[0], m[1]) = (s.members[0], s.members[1]);
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory ew) = _epoch(sid, ids[0], 1, 1, sid, s.admins, m);
        sig = _sig(e.author, h.epoch(e));
        vm.prank(STRANGER);
        chat.rekey(e, ew, sig);
        // pqvault review F1 (the completing child's author read from its record and checked against the removals):
        // regular
        // 382,412 -> 383,942
        // CTR-CHAT-23 (and the author read through the record's offset word, `PqChat._authorOf`): 383,942 / 7,642,350
        // -> 389,335 / 8,034,030
        // owner (M) 2026-11-23, CTR-CHAT-24: members by `(ua, keyId)`, the distinct-UA count:
        // regular 389,335 -> 391,869
        // TreeKEM T3a (the tree-session read in `rekey`): regular 391,869 -> 394,329
        _row("rekey dropping the removed member, 2 left", 394_329, 8_034_030);
    }

    // ----- topics (topics spec §6) -----

    function test_gas_topics() public {
        IPqChat.PqTopic memory t = _topicRec(ids[0], 1, true);
        t.about = new bytes(256);
        IUARegistry.UASig memory sig = _sig(t.admin, h.topic(t));
        vm.prank(STRANGER);
        bytes32 tid = chat.createTopic(t, sig);
        // CTR-CHAT-23 (the release's dispatcher before the forward; the module unchanged): regular 179,045 -> 179,192
        _row("createTopic 256 B about", 179_192, 1_851_300);

        IPqChat.PqTopicWriter memory w = IPqChat.PqTopicWriter(tid, ids[1], true, 1);
        sig = _sig(ids[0], h.topicWriter(w));
        vm.prank(STRANGER);
        chat.setTopicWriter(w, sig);
        // CTR-CHAT-23: regular 112,920 -> 113,046
        _row("setTopicWriter grant", 113_046, 293_760);

        IPqChat.PqTopicEntry memory p = _entryRec(tid, ids[0], 1, 0, new bytes(1024));
        sig = _sig(p.author, h.entry(p));
        vm.prank(STRANGER);
        bytes32 pid = chat.postEntry(p, sig);
        // CTR-CHAT-23 (the release's dispatcher): regular 178,583 -> 178,686
        // TreeKEM T3a (the dispatcher with the tree module's selectors, `_forward(module)`): regular 178,686 -> 179,259
        _row("postEntry 1 KiB post", 179_259, 3_075_300);

        IPqChat.PqTopicEntry memory r = _entryRec(tid, ids[2], 1, pid, new bytes(256));
        sig = _sig(r.author, h.entry(r));
        vm.prank(STRANGER);
        chat.postEntry(r, sig);
        // CTR-CHAT-23 (the release's dispatcher): regular 183,285 -> 183,388
        _row("postEntry 256 B reply", 183_388, 1_900_260);

        IPqChat.PqTopicEdit memory d = IPqChat.PqTopicEdit(pid, ids[0], 2, 2, "text/markdown", new bytes(1024));
        sig = _sig(d.author, h.edit(d));
        vm.prank(STRANGER);
        chat.editEntry(d, sig);
        // CTR-CHAT-23 (the release's dispatcher): regular 144,427 -> 144,596
        // TreeKEM T3a (the dispatcher with the tree module's selectors): regular 144,596 -> 145,142
        _row("editEntry 1 KiB", 145_142, 2_487_780);

        IPqChat.PqTopicVote memory v = IPqChat.PqTopicVote(pid, ids[3], 1, 1);
        sig = _sig(v.voter, h.vote(v));
        vm.prank(STRANGER);
        chat.voteEntry(v, sig);
        // CTR-CHAT-23 (the release's dispatcher): regular 101,326 -> 101,429
        _row("voteEntry first on the entry", 101_429, 195_840);
        v = IPqChat.PqTopicVote(pid, ids[3], -1, 2);
        sig = _sig(v.voter, h.vote(v));
        vm.prank(STRANGER);
        chat.voteEntry(v, sig);
        // CTR-CHAT-23 (the release's dispatcher): regular 102,292 -> 102,395
        _row("voteEntry changed", 102_395, 0);
    }

    /// The release transaction (`deployImplementation` through the factory:
    // a CREATE2 of the whole implementation), as the deploy
    /// sends it:
    // regular x 64/63 (the gas a CREATE2 frame keeps back, `GovDeploy.t.sol`'s method) + EIP-8037 state, x 1.05

    //    /// (`DeploySend.s.sol`'s limit, NET-EVM-11) within the 60 M every transaction asks (Step 5b), regular x 1.05 < 2^24.
    function test_gas_deployImplementation() public {
        bytes memory code = type(PqChat).creationCode;
        vm.prank(REGISTRAR);
        address r = f.deployImplementation(
            IOpenFactory.ReleaseId(3, 0, 2),
            1,
            IPqChat.initialize.selector,
            type(IPqChat).interfaceId,
            code,
            _args(),
            EnvKit.uidOf(address(f))
        );
        Vm.Gas memory g = vm.lastCallGas();
        (uint256 regular, uint256 state) = (uint256(g.gasTotalUsed) * 64 / 63, uint256(int256(g.gasStateUsed)));
        uint256 asked = (regular + state) * 105 / 100;
        emit log_named_uint("SIZE PqChat runtime", r.code.length);
        emit log_named_uint("SIZE PqChat init", code.length);
        emit log_named_uint("GAS deployImplementation PqChat regular x 64/63", regular);
        emit log_named_uint("GAS deployImplementation PqChat state", state);
        emit log_named_uint("GAS deployImplementation PqChat asked x 1.05", asked);
        assertLt(regular * 105 / 100, 1 << 24, "regular gas x 1.05 under 2^24 (EIP-7825)");
        assertLe(asked, 60_000_000, "the release transaction asks at most 60 M");
        if (!vm.envOr("GAS_MEASURE", false)) {
            assertEq(r.code.length, RUNTIME, "the PqChat runtime (size-baseline.json row)");
            assertApproxEqAbs(regular, RELEASE_REGULAR, SLACK, "deployImplementation regular");
            assertEq(state, RELEASE_STATE, "deployImplementation state");
        }
    }

    /// The body module's deployment (CTR-TOK-30, 3C-D2): its own CREATE2 transaction, the same rule.
    function test_gas_deployModule() public {
        Create2Once probe = new Create2Once();
        bytes memory code = abi.encodePacked(type(PqChatTopics).creationCode, abi.encode(address(f)));
        address m = probe.deploy(code, keccak256("topics"));
        Vm.Gas memory g = vm.lastCallGas();
        (uint256 regular, uint256 state) = (uint256(g.gasTotalUsed) * 64 / 63, uint256(int256(g.gasStateUsed)));
        uint256 asked = (regular + state) * 105 / 100;
        emit log_named_uint("SIZE PqChatTopics runtime", m.code.length);
        emit log_named_uint("SIZE PqChatTopics init", code.length);
        emit log_named_uint("GAS deploy PqChatTopics regular x 64/63", regular);
        emit log_named_uint("GAS deploy PqChatTopics state", state);
        emit log_named_uint("GAS deploy PqChatTopics asked x 1.05", asked);
        assertLt(regular * 105 / 100, 1 << 24, "regular gas x 1.05 under 2^24 (EIP-7825)");
        assertLe(asked, 60_000_000, "the module transaction asks at most 60 M");
        if (!vm.envOr("GAS_MEASURE", false)) {
            assertEq(m.code.length, MODULE_RUNTIME, "the PqChatTopics runtime (size-baseline.json row)");
            assertApproxEqAbs(regular, MODULE_REGULAR, SLACK, "deploy PqChatTopics regular");
            assertEq(state, MODULE_STATE, "deploy PqChatTopics state");
        }
    }

    function test_gas_createInstance() public {
        bytes memory init = abi.encodeCall(IPqChat.initialize, (MetaTxLib.pad(STRANGER), 2)); // the owner is the creator (D P3-1)
        vm.prank(STRANGER);
        f.createInstance(IOpenFactory.ReleaseId(3, 0, 1), "gas", init);
        // round 3r T4 (R1: no owner word in the record, no owner list, no `factoryInfo().ownerUA`):
        // 227,583 / 1,523,880 ->
        // 188,761 / 1,328,040 (state -2 x 97,920)
        // Fable D P3-1 (the `creating()` staticcall in `initialize`): regular 188,761 -> 189,561
        // CTR-CHAT-23 (the `sigStore` argument and its check): regular 189,561 -> 189,995
        _row("createInstance PqChat", 189_995, 1_328_040);
    }
}
