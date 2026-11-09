// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {PqChatTypes} from "../../src/pqchat/PqChatTypes.sol";
import {PqChatHasher} from "./PqChatBase.sol";

/// Plan 3c T85 / T88: the typed records of `PqChat` against `smartcontracts/vectors/pqchat/` (written by clientkeys,
/// `scripts/pqchat-vectors.mjs`): typehashes, `DS_C`, tags, every record's digest, id, scope and stored blob. A literal pin
/// beside each vector value, so a regenerated vector cannot move a typehash unnoticed.
contract PqChatTypesTest is Test {
    PqChatHasher internal h;
    string internal rec;
    string internal top;

    function setUp() public {
        h = new PqChatHasher();
        rec = vm.readFile("../vectors/pqchat/records.json");
        top = vm.readFile("../vectors/pqchat/topics.json");
    }

    function _th(string memory j, string memory name) internal pure returns (bytes32) {
        return vm.parseJsonBytes32(j, string.concat(".typehashes.", name, ".hash"));
    }

    function test_pqchatTypehashIsPinned() public view {
        assertEq(PqChatTypes.MEMBER_KEY_TYPEHASH, 0x6d7e57dfbfdfbc352504f1e82bc1658aeeb466b69ba168e7a3d69b0c1d448113);
        assertEq(PqChatTypes.WRAP_TYPEHASH, 0xf7d817cc55f4324caed15db75da261c4bd468454b80ac0cc8d30cd5a0d331e87);
        assertEq(PqChatTypes.SESSION_TYPEHASH, 0xf7feab992d33b04a998655786b28fde03f83b25d51d155746127927fa43d71dd);
        assertEq(PqChatTypes.EPOCH_TYPEHASH, 0x00b07f15a60f8d4960c9262ffd3a307a3f2f2e790bcbc65911b4630ad0d2888c);
        assertEq(PqChatTypes.LEAVE_TYPEHASH, 0xe68d65ceec0d13ce4006e86e03cca815b44ff94ced5a2aa4b7244abf7502eea1);
        assertEq(PqChatTypes.MESSAGE_TYPEHASH, 0x89b7ecd529b23df420ab952a119254e1e7d312d3dbb94ddeb4a71351ea78a0cc);
        assertEq(PqChatTypes.MEMBER_KEY_TYPEHASH, _th(rec, "MemberKey"));
        assertEq(PqChatTypes.WRAP_TYPEHASH, _th(rec, "Wrap"));
        assertEq(PqChatTypes.SESSION_TYPEHASH, _th(rec, "PqChatSession"));
        assertEq(PqChatTypes.EPOCH_TYPEHASH, _th(rec, "PqChatEpoch"));
        assertEq(PqChatTypes.LEAVE_TYPEHASH, _th(rec, "PqChatLeave"));
        assertEq(PqChatTypes.MESSAGE_TYPEHASH, _th(rec, "PqChatMessage"));
        assertEq(PqChatTypes.DS_C, 0x9f21cbeb7458f98acbc569cab1c2d39d4b3eb68203d1f91dd1084197554d8e08);
        assertEq(PqChatTypes.DS_C, vm.parseJsonBytes32(rec, ".domain.separator"));
        assertEq(UAKinds.PURPOSE_PQCHAT, vm.parseJsonBytes32(rec, ".purpose.hash"));
        assertEq(PqChatTypes.TAG_SESSION, vm.parseJsonBytes32(rec, ".tags['scaas/pqchat/v1/session']"));
        assertEq(PqChatTypes.TAG_EPOCH, vm.parseJsonBytes32(rec, ".tags['scaas/pqchat/v1/epoch']"));
        assertEq(PqChatTypes.SCOPE_SESSION, vm.parseJsonBytes32(rec, ".tags['scaas/pqchat/v1/scope/session']"));
        assertEq(PqChatTypes.SCOPE_EPOCH, vm.parseJsonBytes32(rec, ".tags['scaas/pqchat/v1/scope/epoch']"));
        assertEq(PqChatTypes.SCOPE_MESSAGE, vm.parseJsonBytes32(rec, ".tags['scaas/pqchat/v1/scope/message']"));
    }

    function test_pqtopicTypehashIsPinned() public view {
        assertEq(PqChatTypes.TOPIC_TYPEHASH, 0x036410199359c4078236396c31f3e7dad433cc6683b909381bbf77498778cd92);
        assertEq(PqChatTypes.TOPIC_UPDATE_TYPEHASH, 0x91027af710f50981ddd96a8956a4741037e30cdb39510c7ccc497d9d7e95fd43);
        assertEq(PqChatTypes.TOPIC_WRITER_TYPEHASH, 0x98c6762cb0fe12a3e571a6e57e5356db25bd35abf3e71ee230c87c1a3979c6d6);
        assertEq(PqChatTypes.TOPIC_ENTRY_TYPEHASH, 0x52078674040d84432edab865e567b3fe279100575e5d4496f6be51acf924c32c);
        assertEq(PqChatTypes.ENTRY_REF_TYPEHASH, 0x7ba7739bb3fdfce60182520013572143dfa33e287299bdb4612752a785b7c16a);
        assertEq(PqChatTypes.TOPIC_EDIT_TYPEHASH, 0xd9517bcc19e3701e1f7ca78d211a4a8c072103e2ef815e03f13fb50398094b7b);
        assertEq(PqChatTypes.TOPIC_VOTE_TYPEHASH, 0xddb33cebf26a389251a4a1f178107dcaa1ebc142403ede69604f69613755fd6a);
        assertEq(PqChatTypes.TOPIC_TYPEHASH, _th(top, "PqTopic"));
        assertEq(PqChatTypes.TOPIC_UPDATE_TYPEHASH, _th(top, "PqTopicUpdate"));
        assertEq(PqChatTypes.TOPIC_WRITER_TYPEHASH, _th(top, "PqTopicWriter"));
        assertEq(PqChatTypes.TOPIC_ENTRY_TYPEHASH, _th(top, "PqTopicEntry"));
        assertEq(PqChatTypes.ENTRY_REF_TYPEHASH, _th(top, "EntryRef"));
        assertEq(PqChatTypes.TOPIC_EDIT_TYPEHASH, _th(top, "PqTopicEdit"));
        assertEq(PqChatTypes.TOPIC_VOTE_TYPEHASH, _th(top, "PqTopicVote"));
        assertEq(PqChatTypes.DS_C, vm.parseJsonBytes32(top, ".domain.separator"));
        assertEq(PqChatTypes.TAG_TOPIC, vm.parseJsonBytes32(top, ".tags['scaas/pqchat/v1/topic']"));
        assertEq(PqChatTypes.TAG_ENTRY, vm.parseJsonBytes32(top, ".tags['scaas/pqchat/v1/entry']"));
        assertEq(PqChatTypes.SCOPE_TOPIC, vm.parseJsonBytes32(top, ".tags['scaas/pqchat/v1/scope/topic']"));
        assertEq(PqChatTypes.SCOPE_ENTRY, vm.parseJsonBytes32(top, ".tags['scaas/pqchat/v1/scope/entry']"));
    }

    // ----- records from the vectors -----

    function _b32(string memory j, string memory k) internal pure returns (bytes32) {
        return vm.parseJsonBytes32(j, k);
    }

    function _u64(string memory j, string memory k) internal pure returns (uint64) {
        return uint64(vm.parseJsonUint(j, k));
    }

    function _membersAt(string memory j, string memory p) internal pure returns (IPqChat.MemberKey[] memory m) {
        uint256 n = vm.parseJsonBytes32Array(j, string.concat(p, ".wrapHashes")).length;
        m = new IPqChat.MemberKey[](n);
        for (uint256 i; i < n; ++i) {
            string memory q = string.concat(p, ".members[", vm.toString(i), "]");
            m[i] = IPqChat.MemberKey(_b32(j, string.concat(q, ".ua")), _u64(j, string.concat(q, ".keyId")),
                _b32(j, string.concat(q, ".via")));
        }
    }

    function _session() internal pure returns (IPqChat.PqChatSession memory s) {}

    function test_sessionVector() public view {
        string memory p = ".session.record";
        IPqChat.PqChatSession memory s;
        s.creator = _b32(rec, string.concat(p, ".creator"));
        s.nonce = _u64(rec, string.concat(p, ".nonce"));
        s.homeChain = _b32(rec, string.concat(p, ".homeChain"));
        s.homeContract = vm.parseJsonAddress(rec, string.concat(p, ".homeContract"));
        s.admins = vm.parseJsonBytes32Array(rec, string.concat(p, ".admins"));
        s.members = _membersAt(rec, p);
        s.wrapHashes = vm.parseJsonBytes32Array(rec, string.concat(p, ".wrapHashes"));
        s.sealedInfo = vm.parseJsonBytes(rec, string.concat(p, ".sealedInfo"));
        bytes32 t = h.session(s);
        assertEq(t, _b32(rec, ".session.typed"));
        assertEq(PqChatTypes.sessionId(s.creator, s.nonce), _b32(rec, ".session.id"));
        assertEq(PqChatTypes.scopeSession(s.creator), _b32(rec, ".session.scope"));
        assertEq(UAKinds.uaMessage(uint16(vm.parseJsonUint(rec, ".session.uaMessage.kind")), UAKinds.PURPOSE_PQCHAT, t),
            _b32(rec, ".session.uaMessage.digest"));
        // one change at a time moves the digest: `via`
        s.members[0].via = bytes32(uint256(s.members[0].via) ^ 1);
        assertTrue(h.session(s) != t);
    }

    function test_epochAndLeaveVectors() public view {
        string memory p = ".epoch.record";
        IPqChat.PqChatEpoch memory e;
        e.sessionId = _b32(rec, string.concat(p, ".sessionId"));
        e.author = _b32(rec, string.concat(p, ".author"));
        e.nonce = _u64(rec, string.concat(p, ".nonce"));
        e.epoch = _u64(rec, string.concat(p, ".epoch"));
        e.parentEpochId = _b32(rec, string.concat(p, ".parentEpochId"));
        e.admins = vm.parseJsonBytes32Array(rec, string.concat(p, ".admins"));
        e.members = _membersAt(rec, p);
        e.wrapHashes = vm.parseJsonBytes32Array(rec, string.concat(p, ".wrapHashes"));
        e.sealedInfo = vm.parseJsonBytes(rec, string.concat(p, ".sealedInfo"));
        assertEq(h.epoch(e), _b32(rec, ".epoch.typed"));
        assertEq(PqChatTypes.epochId(e.sessionId, e.author, e.nonce), _b32(rec, ".epoch.id"));
        assertEq(PqChatTypes.scopeEpoch(e.sessionId, e.author), _b32(rec, ".epoch.scope"));
        p = ".leave.record";
        IPqChat.PqChatLeave memory l = IPqChat.PqChatLeave(_b32(rec, string.concat(p, ".sessionId")),
            _b32(rec, string.concat(p, ".epochId")), _b32(rec, string.concat(p, ".member")), _u64(rec, string.concat(p, ".nonce")));
        assertEq(h.leave(l), _b32(rec, ".leave.typed"));
        assertEq(h.leave(l), _b32(rec, ".leave.id"));
        assertEq(PqChatTypes.scopeEpoch(l.sessionId, l.member), _b32(rec, ".leave.scope"));
    }

    function _uaSig(string memory j, string memory p) internal pure returns (IUARegistry.UASig memory s) {
        s.keyData = vm.parseJsonBytes(j, string.concat(p, ".keyData"));
        s.signature = vm.parseJsonBytes(j, string.concat(p, ".signature"));
    }

    function _message() internal view returns (IPqChat.PqChatMessage memory m) {
        string memory p = ".message.record";
        m.sessionId = _b32(rec, string.concat(p, ".sessionId"));
        m.epochId = _b32(rec, string.concat(p, ".epochId"));
        m.sender = _b32(rec, string.concat(p, ".sender"));
        m.device = uint32(vm.parseJsonUint(rec, string.concat(p, ".device")));
        m.counter = _u64(rec, string.concat(p, ".counter"));
        m.parents = vm.parseJsonBytes32Array(rec, string.concat(p, ".parents"));
        m.ciphertext = vm.parseJsonBytes(rec, string.concat(p, ".ciphertext"));
    }

    /// The vector message's id is `typed(PqChatMessage)`; its blob is `abi.encode(record, keccak256(abi.encode(UASig)))`.
    function test_messageVector() public view {
        IPqChat.PqChatMessage memory m = _message();
        IUARegistry.UASig memory sig = _uaSig(rec, ".message.uaSig");
        assertEq(h.message(m), _b32(rec, ".message.id"));
        assertEq(PqChatTypes.scopeMessage(m.epochId, m.sender, m.device), _b32(rec, ".message.scope"));
        assertEq(keccak256(abi.encode(sig)), _b32(rec, ".message.sigHash"));
        assertEq(abi.encode(m, keccak256(abi.encode(sig))), vm.parseJsonBytes(rec, ".message.blob"));
    }

    // ----- topics -----

    function test_topicVectors() public view {
        string memory p = ".topic.record";
        IPqChat.PqTopic memory t = IPqChat.PqTopic(_b32(top, string.concat(p, ".owner")), _u64(top, string.concat(p, ".nonce")),
            _b32(top, string.concat(p, ".homeChain")), vm.parseJsonAddress(top, string.concat(p, ".homeContract")),
            vm.parseJsonString(top, string.concat(p, ".name")), vm.parseJsonBytes(top, string.concat(p, ".about")),
            vm.parseJsonBool(top, string.concat(p, ".openReplies")));
        assertEq(h.topic(t), _b32(top, ".topic.typed"));
        assertEq(PqChatTypes.topicId(t.owner, t.nonce), _b32(top, ".topic.id"));
        assertEq(PqChatTypes.scopeTopic(t.owner), _b32(top, ".topic.scope"));
        assertEq(abi.encode(t, keccak256(abi.encode(_uaSig(top, ".topic.uaSig")))), vm.parseJsonBytes(top, ".topic.blob"));
        p = ".update.record";
        IPqChat.PqTopicUpdate memory u = IPqChat.PqTopicUpdate(_b32(top, string.concat(p, ".topicId")),
            _u64(top, string.concat(p, ".seq")), vm.parseJsonString(top, string.concat(p, ".name")),
            vm.parseJsonBytes(top, string.concat(p, ".about")), vm.parseJsonBool(top, string.concat(p, ".openReplies")));
        assertEq(h.topicUpdate(u), _b32(top, ".update.typed"));
        p = ".writer.record";
        IPqChat.PqTopicWriter memory w = IPqChat.PqTopicWriter(_b32(top, string.concat(p, ".topicId")),
            _b32(top, string.concat(p, ".writer")), vm.parseJsonBool(top, string.concat(p, ".granted")),
            _u64(top, string.concat(p, ".seq")));
        assertEq(h.topicWriter(w), _b32(top, ".writer.typed"));
    }

    function _entry(string memory row) internal view returns (IPqChat.PqTopicEntry memory e) {
        string memory p = string.concat(".", row, ".record");
        e.topicId = _b32(top, string.concat(p, ".topicId"));
        e.author = _b32(top, string.concat(p, ".author"));
        e.nonce = _u64(top, string.concat(p, ".nonce"));
        e.parentId = _b32(top, string.concat(p, ".parentId"));
        e.ref = IPqChat.EntryRef(_b32(top, string.concat(p, ".ref.chainUid")), vm.parseJsonAddress(top, string.concat(p,
            ".ref.pqchat")), _b32(top, string.concat(p, ".ref.entryId")), _b32(top, string.concat(p, ".ref.contentHash")));
        e.mediaType = vm.parseJsonString(top, string.concat(p, ".mediaType"));
        e.body = vm.parseJsonBytes(top, string.concat(p, ".body"));
    }

    function test_entryEditVoteVectors() public view {
        for (uint256 k; k < 2; ++k) {
            string memory row = k == 0 ? "post" : "reply";
            IPqChat.PqTopicEntry memory e = _entry(row);
            assertEq(h.entry(e), _b32(top, string.concat(".", row, ".typed")));
            assertEq(PqChatTypes.entryId(e.topicId, e.author, e.nonce), _b32(top, string.concat(".", row, ".id")));
            assertEq(PqChatTypes.scopeEntry(e.topicId, e.author), _b32(top, string.concat(".", row, ".scope")));
            assertEq(abi.encode(e, keccak256(abi.encode(_uaSig(top, string.concat(".", row, ".uaSig"))))),
                vm.parseJsonBytes(top, string.concat(".", row, ".blob")));
        }
        string memory p = ".edit.record";
        IPqChat.PqTopicEdit memory d = IPqChat.PqTopicEdit(_b32(top, string.concat(p, ".entryId")),
            _b32(top, string.concat(p, ".author")), _u64(top, string.concat(p, ".nonce")),
            uint32(vm.parseJsonUint(top, string.concat(p, ".version"))), vm.parseJsonString(top, string.concat(p, ".mediaType")),
            vm.parseJsonBytes(top, string.concat(p, ".body")));
        assertEq(h.edit(d), _b32(top, ".edit.typed"));
        p = ".vote.record";
        IPqChat.PqTopicVote memory v = IPqChat.PqTopicVote(_b32(top, string.concat(p, ".entryId")),
            _b32(top, string.concat(p, ".voter")), int8(vm.parseJsonInt(top, string.concat(p, ".value"))),
            _u64(top, string.concat(p, ".seq")));
        assertEq(v.value, -1);
        assertEq(h.vote(v), _b32(top, ".vote.typed"));
    }
}
