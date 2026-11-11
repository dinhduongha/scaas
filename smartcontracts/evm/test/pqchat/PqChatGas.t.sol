// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

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

/// Plan 3c T90 (UA-7 T9, PT4; owner 2026-11-10: the 2-person chat first): gas rows of `PqChat`, `isolate = true`, so each
/// figure is one transaction's: `vm.lastCallGas()` regular gas (intrinsic and calldata floor included) and the EIP-8037
/// state gas apart. Signatures go through the stand-in verifier (`MockVerifier`, no work), so a row is `PqChat`'s and the
/// registry's own cost; a real signer adds its verifier's gas (regular): FN-DSA-512 about 2.3 M, ML-DSA-65 on the cached key
/// about 5.8 M, an EIP-8355 precompile about 0.2 M (spec §11; pinned in `test/ua`). New pins: regular within ±500 gas, state
/// exact; a move needs old -> new figures in its commit.
contract PqChatGasTest is PqTopicsBase {
    uint256 internal constant SLACK = 500;
    // round 3r T4 (R1, Q4: `factoryInfo()` six words, no owner): 27,825 -> 27,801 B; regular 1,908,760 -> 1,906,679; state
    // 43,147,530 -> 43,110,810 (-24 x 1,530)
    // Fable D P3-1 (2026-11-11, `initialize` checks `creating()`): 27,801 -> 27,999 B; regular 1,906,679 -> 1,921,243;
    // state 43,110,810 -> 43,413,750 (+198 x 1,530)
    uint256 internal constant RUNTIME = 27_999;
    uint256 internal constant RELEASE_REGULAR = 1_921_243;
    uint256 internal constant RELEASE_STATE = 43_413_750;
    // owner 2026-11-10 (group 3p): the topic `name` bound 128 -> 512 B, one PUSH2 for a PUSH1 twice: 16,396 -> 16,398 B, state
    // 25,269,480 -> 25,272,540 (+2 x 1,530), regular unchanged
    uint256 internal constant MODULE_RUNTIME = 16_398;
    uint256 internal constant MODULE_REGULAR = 1_099_442;
    uint256 internal constant MODULE_STATE = 25_272_540;

    function _row(string memory what, uint256 regular, uint256 state) internal {
        Vm.Gas memory g = vm.lastCallGas();
        uint256 s = uint256(int256(g.gasStateUsed));
        emit log_named_uint(string.concat("GAS ", what, " regular"), g.gasTotalUsed);
        emit log_named_uint(string.concat("GAS ", what, " state"), s);
        emit log_named_uint(string.concat("GAS ", what, " total"), g.gasTotalUsed + s);
        if (regular != 0 && !vm.envOr("GAS_MEASURE", false)) { // GAS_MEASURE=true: the figures, no pin
            assertApproxEqAbs(g.gasTotalUsed, regular, SLACK, string.concat(what, " regular"));
            assertEq(s, state, string.concat(what, " state"));
        }
    }

    function _msg(bytes32 sid, bytes32 eid, bytes32 sender, uint64 counter, uint256 size)
        internal pure returns (IPqChat.PqChatMessage memory m)
    {
        (m.sessionId, m.epochId, m.sender, m.device, m.counter) = (sid, eid, sender, bytes16(0x0190f5c0a1e07000800000000000d0c5), counter);
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
        _row("createSession 2 members, both wraps, index 2", 340_852, 7_691_310);

        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory ew) = _epoch(sid, ids[1], 1, 1, sid, s.admins, s.members);
        sig = _sig(e.author, h.epoch(e));
        vm.prank(STRANGER);
        bytes32 e1 = chat.rekey(e, ew, sig);
        _row("rekey 2 members, plain, first epoch list entry", 366_797, 7_740_270);

        (e, ew) = _epoch(sid, ids[0], 1, 2, e1, s.admins, s.members);
        sig = _sig(e.author, h.epoch(e));
        vm.prank(STRANGER);
        bytes32 e2 = chat.rekey(e, ew, sig);
        _row("rekey 2 members, plain, next epoch list entry", 366_678, 7_642_350);

        IPqChat.PqChatMessage memory m = _msg(sid, e2, ids[1], 0, 1040); // a 1,024-B bucket + the GCM-SIV tag
        sig = _sig(m.sender, h.message(m));
        vm.prank(STRANGER);
        chat.postMessage(m, sig);
        _row("postMessage 2 members, 1,040 B ciphertext", 153_744, 2_732_580);

        m = _msg(sid, e2, ids[1], 1, 1040);
        sig = _sig(m.sender, h.message(m));
        vm.prank(STRANGER);
        chat.postMessage(m, sig);
        _row("postMessage 2 members, 1,040 B ciphertext, warm list", 153_756, 2_536_740);

        IPqChat.PqChatLeave memory l = IPqChat.PqChatLeave(sid, e2, ids[1], 9);
        sig = _sig(ids[1], h.leave(l));
        vm.prank(STRANGER);
        chat.leave(l, sig);
        _row("leave 2 members", 107_485, 97_920);
    }

    function test_gas_twoMembersInChunks() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(2, 1, address(chat));
        IUARegistry.UASig memory sig = _sig(s.creator, h.session(s));
        IPqChat.Wrap[] memory first = _slice(w, 0, 1);
        vm.prank(STRANGER);
        bytes32 sid = chat.createSession(s, first, sig);
        _row("createSession 2 members, one wrap", 293_223, 5_010_750);
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
        for (uint8 i = 6; i <= 20; ++i) _member(i);
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(10, 1, address(chat));
        IUARegistry.UASig memory sig = _sig(s.creator, h.session(s));
        vm.prank(STRANGER);
        chat.createSession(s, w, sig);
        _row("createSession 10 members, all wraps", 1_356_696, 32_269_230);
        (s, w) = _session(20, 2, address(chat));
        sig = _sig(s.creator, h.session(s));
        vm.prank(STRANGER);
        bytes32 sid = chat.createSession(s, w, sig);
        _row("createSession 20 members, all wraps", 2_646_936, 61_914_510);
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory ew) = _epoch(sid, ids[3], 1, 1, sid, s.admins, s.members);
        sig = _sig(e.author, h.epoch(e));
        vm.prank(STRANGER);
        chat.rekey(e, ew, sig);
        _row("rekey 20 members, plain", 2_648_984, 59_515_470);
        // all 20 wraps in one call ask more than 60 M ((regular + state) x 1.05), a create (67.8 M) and a rekey (65.3 M)
        // alike: a 20-member record goes in chunks. The 20-member rows are warm (the 10-member session above wrote 11 of
        // the slots and a wrap blob in this test): a cold call is about 1.26 M higher (Fable P3-7).
        assertGt(uint256(2_646_936 + 61_914_510) * 105 / 100, 60_000_000, "20 wraps in one create: over 60 M");
        assertGt(uint256(2_648_984 + 59_515_470) * 105 / 100, 60_000_000, "20 wraps in one rekey: over 60 M");
        (s, w) = _session(20, 3, address(chat));
        sig = _sig(s.creator, h.session(s));
        vm.prank(STRANGER);
        sid = chat.createSession(s, _slice(w, 0, 10), sig);
        _row("createSession 20 members, first 10 wraps", 1_518_726, 34_129_710);
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
        _row("remove 1 of 3 members", 168_513, 1_067_940);
        IPqChat.MemberKey[] memory m = new IPqChat.MemberKey[](2);
        (m[0], m[1]) = (s.members[0], s.members[1]);
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory ew) = _epoch(sid, ids[0], 1, 1, sid, s.admins, m);
        sig = _sig(e.author, h.epoch(e));
        vm.prank(STRANGER);
        chat.rekey(e, ew, sig);
        _row("rekey dropping the removed member, 2 left", 381_828, 7_642_350);
    }

    // ----- topics (topics spec §6) -----

    function test_gas_topics() public {
        IPqChat.PqTopic memory t = _topicRec(ids[0], 1, true);
        t.about = new bytes(256);
        IUARegistry.UASig memory sig = _sig(t.admin, h.topic(t));
        vm.prank(STRANGER);
        bytes32 tid = chat.createTopic(t, sig);
        _row("createTopic 256 B about", 179_045, 1_851_300);

        IPqChat.PqTopicWriter memory w = IPqChat.PqTopicWriter(tid, ids[1], true, 1);
        sig = _sig(ids[0], h.topicWriter(w));
        vm.prank(STRANGER);
        chat.setTopicWriter(w, sig);
        _row("setTopicWriter grant", 112_920, 293_760);

        IPqChat.PqTopicEntry memory p = _entryRec(tid, ids[0], 1, 0, new bytes(1024));
        sig = _sig(p.author, h.entry(p));
        vm.prank(STRANGER);
        bytes32 pid = chat.postEntry(p, sig);
        _row("postEntry 1 KiB post", 178_583, 3_075_300);

        IPqChat.PqTopicEntry memory r = _entryRec(tid, ids[2], 1, pid, new bytes(256));
        sig = _sig(r.author, h.entry(r));
        vm.prank(STRANGER);
        chat.postEntry(r, sig);
        _row("postEntry 256 B reply", 183_285, 1_900_260);

        IPqChat.PqTopicEdit memory d = IPqChat.PqTopicEdit(pid, ids[0], 2, 2, "text/markdown", new bytes(1024));
        sig = _sig(d.author, h.edit(d));
        vm.prank(STRANGER);
        chat.editEntry(d, sig);
        _row("editEntry 1 KiB", 144_427, 2_487_780);

        IPqChat.PqTopicVote memory v = IPqChat.PqTopicVote(pid, ids[3], 1, 1);
        sig = _sig(v.voter, h.vote(v));
        vm.prank(STRANGER);
        chat.voteEntry(v, sig);
        _row("voteEntry first on the entry", 101_326, 195_840);
        v = IPqChat.PqTopicVote(pid, ids[3], -1, 2);
        sig = _sig(v.voter, h.vote(v));
        vm.prank(STRANGER);
        chat.voteEntry(v, sig);
        _row("voteEntry changed", 102_292, 0);
    }

    /// The release transaction (`deployImplementation` through the factory: a CREATE2 of the whole implementation), as the deploy
    /// sends it: regular x 64/63 (the gas a CREATE2 frame keeps back, `GovDeploy.t.sol`'s method) + EIP-8037 state, x 1.05
    /// (`DeploySend.s.sol`'s limit, NET-EVM-11) within the 60 M every transaction asks (Step 5b), regular x 1.05 < 2^24.
    function test_gas_deployImplementation() public {
        bytes memory code = type(PqChat).creationCode;
        vm.prank(REGISTRAR);
        address r = f.deployImplementation(IOpenFactory.ReleaseId(3, 0, 2), 1, IPqChat.initialize.selector,
            type(IPqChat).interfaceId, code, _args());
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
        bytes memory init = abi.encodeCall(IPqChat.initialize, (MetaTxLib.pad(STRANGER))); // the owner is the creator (D P3-1)
        vm.prank(STRANGER);
        f.createInstance(IOpenFactory.ReleaseId(3, 0, 1), "gas", init);
        // round 3r T4 (R1: no owner word in the record, no owner list, no `factoryInfo().ownerUA`): 227,583 / 1,523,880 ->
        // 188,761 / 1,328,040 (state -2 x 97,920)
        // Fable D P3-1 (the `creating()` staticcall in `initialize`): regular 188,761 -> 189,561
        _row("createInstance PqChat", 189_561, 1_328_040);
    }
}
