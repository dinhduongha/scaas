// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Vm.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {UAKinds} from "../../src/ua/UAKinds.sol";
import {UACall} from "../ua/UACall.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {PqChat} from "../../src/pqchat/PqChat.sol";
import {PqChatTopics} from "../../src/pqchat/PqChatTopics.sol";
import {PqChatTypes} from "../../src/pqchat/PqChatTypes.sol";
import {PqChatBase} from "./PqChatBase.sol";

/// Plan 3c T85 (UA-7 T5, PC0): the release on the generic path, sessions and wraps in chunks. Every refusal beside its positive
/// control, one change at a time.
contract PqChatTest is PqChatBase {
    // ----- the instance (D22, topics spec §11) -----

    function test_instance_factoryInfoAndInterfaces() public view {
        IOpenFactory.FactoryInfo memory i = chat.factoryInfo();
        assertEq(i.factory, address(f));
        assertEq(i.chainUid, chainUidA);
        assertEq(i.contractClass, 3);
        assertEq(i.kind, 0);
        assertEq(i.version, 1);
        assertEq(i.ownerUA, OWNER_UA);
        assertTrue(i.initialized);
        assertEq(chat.owner(), OWNER_UA);
        assertEq(chatB.owner(), bytes32(0), "owner 0 allowed");
        assertTrue(chat.supportsInterface(0x01ffc9a7));
        assertTrue(chat.supportsInterface(type(IPqChat).interfaceId));
        assertFalse(chat.supportsInterface(0xffffffff));
        // the implementation: locked, chain-neutral
        IOpenFactory.FactoryInfo memory r = PqChat(impl).factoryInfo();
        assertEq(r.chainUid, bytes32(0));
        assertEq(r.ownerUA, bytes32(0));
        assertTrue(r.initialized);
        // the env read from the clone's code
        IFactoryToken.ChainEnv memory e = chat.chainEnv();
        assertEq(e.registry, address(p));
        assertEq(uint256(e.params[0]), LIMIT);
        assertEq(f.infoOf(address(chat)).contractClass, 3);
    }

    function test_initialize_onceAndOnlyByTheFactory() public {
        vm.expectRevert(IPqChat.PqChatNotFactory.selector);
        chat.initialize(bytes32(uint256(7)));
        vm.prank(address(f));
        vm.expectRevert(IPqChat.PqChatInitialized.selector);
        chat.initialize(bytes32(uint256(7)));
        vm.prank(address(f));
        vm.expectRevert(IPqChat.PqChatInitialized.selector);
        PqChat(impl).initialize(bytes32(uint256(7)));
        assertEq(chat.owner(), OWNER_UA);
    }

    function test_validateEnv_refusals() public view {
        IFactoryToken.ChainEnv memory e;
        e.chainUid = chainUidA;
        e.registry = address(p);
        e.params = new bytes32[](1);
        e.params[0] = bytes32(uint256(24_576));
        chat.validateEnv(e); // the positive control: EIP-170's limit
        _envRefused(e, 0);
        _envRefused(e, 1);
        _envRefused(e, 2);
        _envRefused(e, 3);
    }

    function _envRefused(IFactoryToken.ChainEnv memory good, uint256 which) internal view {
        IFactoryToken.ChainEnv memory e = IFactoryToken.ChainEnv(good.chainUid, good.registry, good.govRouter,
            good.smartKeyAccountImpl, good.hedera, good.deps, good.params);
        if (which == 0) e.chainUid = 0;
        if (which == 1) e.registry = address(0);
        if (which == 2) e.params = new bytes32[](0);
        if (which == 3) {
            e.params = new bytes32[](1);
            e.params[0] = bytes32(uint256(24_575));
        }
        try chat.validateEnv(e) {
            revert("validateEnv accepted a bad env");
        } catch (bytes memory err) {
            assertEq(bytes4(err), IPqChat.PqChatEnv.selector);
        }
    }

    /// The factory runs `validateEnv` at the release's deployment: a class env with a limit under 24,576 B refuses it.
    function test_deployRelease_smallLimitRefused() public {
        vm.prank(REGISTRAR);
        f.publishClassEnv(3, 0, 2, _classEnv(address(p), 24_575));
        vm.prank(REGISTRAR);
        vm.expectRevert(IPqChat.PqChatEnv.selector);
        f.deployRelease(IOpenFactory.ReleaseId(3, 0, 2), 2, IPqChat.initialize.selector, type(IPqChat).interfaceId,
            type(PqChat).creationCode, _args());
        vm.prank(REGISTRAR);
        f.publishClassEnv(3, 0, 3, _classEnv(address(p), 24_576));
        vm.prank(REGISTRAR);
        f.deployRelease(IOpenFactory.ReleaseId(3, 0, 2), 3, IPqChat.initialize.selector, type(IPqChat).interfaceId,
            type(PqChat).creationCode, _args());
    }

    function test_constructor_refusesOtherIds() public {
        new PqChat(IOpenFactory.ReleaseId(3, 0, 1), address(f), _args());
        vm.expectRevert(IPqChat.PqChatEnv.selector);
        new PqChat(IOpenFactory.ReleaseId(4, 0, 1), address(f), _args());
        vm.expectRevert(IPqChat.PqChatEnv.selector);
        new PqChat(IOpenFactory.ReleaseId(3, 1, 1), address(f), _args());
        vm.expectRevert(IPqChat.PqChatEnv.selector);
        new PqChat(IOpenFactory.ReleaseId(3, 0, 0), address(f), _args());
        vm.expectRevert(IPqChat.PqChatEnv.selector);
        new PqChat(IOpenFactory.ReleaseId(3, 0, 1), address(0), _args());
    }

    /// The factory checks the code hash of every library the class env pins (the module among them) when it deploys a
    /// release (`LibraryCodeHashMismatch`); the same env with the right hash is the control.
    function test_deployRelease_moduleCodeHashChecked() public {
        IFactoryToken.Env memory e = _classEnv(address(p), LIMIT);
        e.libCodeHashes[0] = keccak256("another code");
        vm.prank(REGISTRAR);
        f.publishClassEnv(3, 0, 2, e);
        vm.prank(REGISTRAR);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.LibraryCodeHashMismatch.selector, address(topics),
            keccak256("another code"), address(topics).codehash));
        f.deployRelease(IOpenFactory.ReleaseId(3, 0, 2), 2, IPqChat.initialize.selector, type(IPqChat).interfaceId,
            type(PqChat).creationCode, _args());
        vm.prank(REGISTRAR);
        f.publishClassEnv(3, 0, 3, _classEnv(address(p), LIMIT));
        vm.prank(REGISTRAR);
        f.deployRelease(IOpenFactory.ReleaseId(3, 0, 2), 3, IPqChat.initialize.selector, type(IPqChat).interfaceId,
            type(PqChat).creationCode, _args());
    }

    /// CTR-TOK-30 (owner 2026-11-10): the factory refuses a release whose `modules()` names a module its env does not pin
    /// (`ModuleNotPinned`), on the generic path as on the token path; the env that pins it is the control.
    function test_deployRelease_moduleNotPinnedRefused() public {
        IFactoryToken.Env memory e = _classEnv(address(p), LIMIT);
        (e.libs, e.libCodeHashes) = (new address[](0), new bytes32[](0));
        vm.prank(REGISTRAR);
        f.publishClassEnv(3, 0, 2, e);
        vm.prank(REGISTRAR);
        vm.expectRevert(abi.encodeWithSelector(IOpenFactory.ModuleNotPinned.selector, address(topics)));
        f.deployRelease(IOpenFactory.ReleaseId(3, 0, 2), 2, IPqChat.initialize.selector, type(IPqChat).interfaceId,
            type(PqChat).creationCode, _args());
        vm.prank(REGISTRAR);
        f.publishClassEnv(3, 0, 3, _classEnv(address(p), LIMIT));
        vm.prank(REGISTRAR);
        f.deployRelease(IOpenFactory.ReleaseId(3, 0, 2), 3, IPqChat.initialize.selector, type(IPqChat).interfaceId,
            type(PqChat).creationCode, _args());
    }

    /// CTR-TOK-30 (owner 2026-11-10): the factory reads `modules()` once, at the release, so the answer is fixed by code
    /// (immutables): an initialized clone answers the release's set, and still after a write to its state.
    function test_modules_fixedByCode() public {
        address[] memory want = new address[](1);
        want[0] = address(topics);
        bytes32 m = keccak256(abi.encode(PqChat(impl).modules()));
        assertEq(m, keccak256(abi.encode(want)), "the release");
        assertEq(keccak256(abi.encode(chat.modules())), m, "the initialized clone");
        (bytes32 sid,) = _newSession(3);
        assertTrue(chat.epochComplete(sid), "state written");
        assertEq(keccak256(abi.encode(chat.modules())), m, "after the write");
    }

    /// CTR-TOK-30, 3C-D2: `implArgs` names the body module of this factory; no code there, or another factory's module,
    /// refused. The module called directly has no env; through an instance it runs in the instance's state.
    function test_constructor_refusesAnotherModule() public {
        vm.expectRevert(IPqChat.PqChatEnv.selector);
        new PqChat(IOpenFactory.ReleaseId(3, 0, 1), address(f), abi.encode(address(0xBEEF)));
        PqChatTopics other = new PqChatTopics(address(0xFAC7));
        vm.expectRevert(IPqChat.PqChatEnv.selector);
        new PqChat(IOpenFactory.ReleaseId(3, 0, 1), address(f), abi.encode(address(other)));
        address[] memory m = PqChat(impl).modules();
        assertEq(m.length, 1);
        assertEq(m[0], address(topics), "the release names its module");
        IPqChat.PqTopic memory t;
        (t.owner, t.homeChain, t.homeChatContract, t.name) = (ids[0], bytes32(uint256(1)), address(chat), "t");
        IUARegistry.UASig memory sig;
        vm.expectRevert(IPqChat.PqChatEnv.selector);
        IPqChat(address(topics)).createTopic(t, sig); // no env on the module itself
    }

    /// Two instances share nothing: a session created in A is unknown in B.
    function test_instances_independent() public {
        (bytes32 sid,) = _newSession(3);
        assertTrue(chat.epochComplete(sid));
        assertFalse(chatB.epochComplete(sid));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatUnknown.selector, sid));
        chatB.sessionOf(sid);
    }

    // ----- createSession, addWraps -----

    function test_createSession_allWraps() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(3, 1, address(chat));
        bytes32 sid = PqChatTypes.sessionId(s.creator, 1);
        IUARegistry.UASig memory sig = _sig(s.creator, h.session(s));
        vm.expectEmit(address(chat));
        emit IPqChat.PqChatSessionCreated(sid, s.creator, chainUidA);
        vm.expectEmit(address(chat));
        emit IPqChat.PqChatWraps(sid, 0, 3);
        vm.expectEmit(address(chat));
        emit IPqChat.PqChatEpochComplete(sid);
        vm.prank(STRANGER);
        assertEq(chat.createSession(s, w, sig), sid);
        assertTrue(chat.epochComplete(sid));
        (IPqChat.PqChatSession memory got, bytes32 sigHash) = chat.sessionOf(sid);
        assertEq(keccak256(abi.encode(got)), keccak256(abi.encode(s)), "the record in state");
        assertEq(sigHash, keccak256(abi.encode(sig)));
        for (uint256 i; i < 3; ++i) assertEq(keccak256(abi.encode(chat.wrapAt(sid, i))), keccak256(abi.encode(w[i])));
        assertTrue(chat.nonceUsed(PqChatTypes.scopeSession(s.creator), 1));
        assertFalse(chat.nonceUsed(PqChatTypes.scopeSession(s.creator), 2));
        assertEq(chat.childOf(sid), bytes32(0));
    }

    /// Wraps in chunks: complete only when the last one lands, in any order, by anyone.
    function test_createSession_chunks() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(4, 1, address(chat));
        bytes32 sid = _create(chat, s, _slice(w, 0, 1));
        assertFalse(chat.epochComplete(sid));
        assertEq(chat.wrapAt(sid, 3).mlkemCt.length, 0, "not landed: empty");
        vm.recordLogs();
        vm.prank(STRANGER);
        chat.addWraps(sid, 3, _slice(w, 3, 4));
        vm.prank(STRANGER);
        chat.addWraps(sid, 1, _slice(w, 1, 2));
        assertFalse(chat.epochComplete(sid));
        assertEq(_completions(vm.getRecordedLogs()), 0);
        vm.recordLogs();
        chat.addWraps(sid, 2, _slice(w, 2, 3));
        assertTrue(chat.epochComplete(sid));
        assertEq(_completions(vm.getRecordedLogs()), 1);
        for (uint256 i; i < 4; ++i) assertEq(keccak256(abi.encode(chat.wrapAt(sid, i))), keccak256(abi.encode(w[i])));
    }

    function _completions(Vm.Log[] memory logs) internal pure returns (uint256 n) {
        for (uint256 i; i < logs.length; ++i) if (logs[i].topics[0] == IPqChat.PqChatEpochComplete.selector) ++n;
    }

    /// Wraps packed per call: more than one blob's worth in one call still reads back per index (14 per 24,576 B blob).
    function test_createSession_manyWrapsOnSmallLimit() public {
        vm.prank(REGISTRAR);
        f.publishClassEnv(3, 0, 2, _classEnv(address(p), 24_576));
        vm.prank(REGISTRAR);
        f.deployRelease(IOpenFactory.ReleaseId(3, 0, 2), 2, IPqChat.initialize.selector, type(IPqChat).interfaceId,
            type(PqChat).creationCode, _args());
        PqChat small = PqChat(f.createInstance(IOpenFactory.ReleaseId(3, 0, 2), "s", abi.encodeCall(IPqChat.initialize, (0))));
        for (uint8 i = 6; i <= 16; ++i) _member(i); // 16 members
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(16, 1, address(small));
        bytes32 sid = _create(small, s, w);
        assertTrue(small.epochComplete(sid));
        assertEq(keccak256(abi.encode(small.wrapAt(sid, 13))), keccak256(abi.encode(w[13])));
        assertEq(keccak256(abi.encode(small.wrapAt(sid, 14))), keccak256(abi.encode(w[14])));
        assertEq(keccak256(abi.encode(small.wrapAt(sid, 15))), keccak256(abi.encode(w[15])));
    }

    function test_addWraps_wrongWrapRefused() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(3, 1, address(chat));
        bytes32 sid = _create(chat, s, _slice(w, 0, 1));
        IPqChat.Wrap[] memory bad = _slice(w, 1, 2);
        bad[0].sealedKey[0] = bytes1(uint8(bad[0].sealedKey[0]) ^ 1);
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatWrapHash.selector, sid, 1));
        chat.addWraps(sid, 1, bad);
        // the wrap of another index
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatWrapHash.selector, sid, 1));
        chat.addWraps(sid, 1, _slice(w, 2, 3));
        (, w) = _session(3, 1, address(chat)); // `bad` shared w[1]'s bytes
        chat.addWraps(sid, 1, _slice(w, 1, 3)); // the control
        assertTrue(chat.epochComplete(sid));
    }

    function test_addWraps_storedOnceUnknownAndRange() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(3, 1, address(chat));
        bytes32 sid = _create(chat, s, _slice(w, 0, 2));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatWrapStored.selector, sid, 1));
        chat.addWraps(sid, 1, _slice(w, 1, 2));
        vm.expectRevert(IPqChat.PqChatShape.selector);
        chat.addWraps(sid, 3, _slice(w, 2, 3));
        bytes32 other = keccak256("other");
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatUnknown.selector, other));
        chat.addWraps(other, 2, _slice(w, 2, 3));
        chat.addWraps(sid, 2, _slice(w, 2, 3));
        assertTrue(chat.epochComplete(sid));
    }

    /// The wrap's own shape: the exact lengths, and the member and version of its index.
    function test_createSession_wrapShapes() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(2, 1, address(chat));
        // a short ciphertext, its hash signed
        w[1].mlkemCt = new bytes(1567);
        s.wrapHashes = _hashes(w);
        _refusedCreate(s, w, abi.encodeWithSelector(IPqChat.PqChatShape.selector));
        (s, w) = _session(2, 1, address(chat));
        w[1].sealedKey = new bytes(47);
        s.wrapHashes = _hashes(w);
        _refusedCreate(s, w, abi.encodeWithSelector(IPqChat.PqChatShape.selector));
        // a wrap naming another member at index 1, its hash signed
        (s, w) = _session(2, 1, address(chat));
        w[1].member = s.members[0].ua;
        s.wrapHashes = _hashes(w);
        _refusedCreate(s, w, abi.encodeWithSelector(IPqChat.PqChatShape.selector));
        (s, w) = _session(2, 1, address(chat));
        w[1].keyId = 1;
        s.wrapHashes = _hashes(w);
        _refusedCreate(s, w, abi.encodeWithSelector(IPqChat.PqChatShape.selector));
        (s, w) = _session(2, 1, address(chat));
        _create(chat, s, w); // the control
    }

    function _refusedCreate(IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w, bytes memory err) internal {
        IUARegistry.UASig memory sig = _sig(s.creator, h.session(s));
        vm.expectRevert(err);
        chat.createSession(s, w, sig);
    }

    function test_createSession_kemKeyRefusals() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(3, 1, address(chat));
        // version 1 is not stored for members[2]
        s.members[2].keyId = 1;
        w = _wraps(s.members, PqChatTypes.sessionId(s.creator, 1));
        s.wrapHashes = _hashes(w);
        _refusedCreate(s, w, abi.encodeWithSelector(IPqChat.PqChatKemKey.selector, s.members[2].ua, uint64(1)));
        // a classical kind holds no KEM key
        bytes32 classical = _register(p, 0x0101, _key(0x0101));
        (s, w) = _session(2, 1, address(chat));
        s.members[1] = IPqChat.MemberKey(classical, 0, 0);
        if (s.members[1].ua < s.members[0].ua) (s.members[0], s.members[1]) = (s.members[1], s.members[0]);
        w = _wraps(s.members, PqChatTypes.sessionId(s.creator, 1));
        s.wrapHashes = _hashes(w);
        _refusedCreate(s, w, abi.encodeWithSelector(IPqChat.PqChatKemKey.selector, classical, uint64(0)));
        (s, w) = _session(3, 1, address(chat));
        _create(chat, s, w); // the control
    }

    /// Each list rule of P8 and 3C-D6, one change at a time from a valid record.
    function test_createSession_shapes() public {
        for (uint256 k; k < 11; ++k) {
            (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(3, 1, address(chat));
            if (k == 0) (s.members[0], s.members[1]) = (s.members[1], s.members[0]); // unsorted
            if (k == 1) s.members[1] = s.members[0]; // a repeated member
            if (k == 2) { // one member only
                s.members = _members(1);
                w = _slice(w, 0, 1);
            }
            if (k == 3) { // the creator not a member
                s.members = new IPqChat.MemberKey[](2);
                (s.members[0], s.members[1]) = (IPqChat.MemberKey(ids[1], 0, 0), IPqChat.MemberKey(ids[2], 0, 0));
            }
            if (k == 4) s.admins = _list(ids[1]); // the creator not an admin
            if (k == 5) s.admins = _list(ids[2], ids[0]); // admins unsorted
            if (k == 6) { // an admin not registered, the list sorted
                bytes32 u = keccak256("unregistered");
                s.admins = u < ids[0] ? _list(u, ids[0]) : _list(ids[0], u);
            }
            if (k == 7) s.wrapHashes = _list(s.wrapHashes[0], s.wrapHashes[1]); // fewer hashes than members
            if (k == 8) s.homeChain = 0;
            if (k == 9) s.homeChatContract = address(0);
            if (k == 10) s.admins = new bytes32[](0);
            if (k <= 3) {
                w = _wraps(s.members, PqChatTypes.sessionId(s.creator, 1));
                s.wrapHashes = _hashes(w);
            }
            if (k == 7) w = _slice(w, 0, 2);
            _refusedCreate(s, w, abi.encodeWithSelector(IPqChat.PqChatShape.selector));
        }
        (IPqChat.PqChatSession memory c, IPqChat.Wrap[] memory cw) = _session(3, 1, address(chat));
        c.admins = _list(ids[0], ids[2]);
        _create(chat, c, cw); // the control, two admins
    }

    function test_createSession_nonceUsedOnce() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(2, 9, address(chat));
        _create(chat, s, w);
        s.sealedInfo = hex"0102"; // another record, the same (creator, nonce)
        bytes32 scope = PqChatTypes.scopeSession(s.creator);
        _refusedCreate(s, w, abi.encodeWithSelector(IPqChat.PqChatNonceUsed.selector, scope, uint64(9)));
        s.nonce = 10;
        w = _wraps(s.members, PqChatTypes.sessionId(s.creator, 10));
        s.wrapHashes = _hashes(w);
        _create(chat, s, w); // the control
    }

    /// The signature is checked before the nonce: a forged record cannot burn it.
    /// CTR-CHAT-04 (spec §4.3): the signature is checked before the nonce, so a used `(creator, nonce)` under a forged
    /// signature is the signature's refusal (`UAUnauthorized`), never `PqChatNonceUsed` (T91: the order is observable only
    /// there; the revert undoes a nonce either way).
    function test_createSession_signatureBeforeNonce() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(2, 4, address(chat));
        _create(chat, s, w);
        IUARegistry.UASig memory forged = _sig(ids[1], h.session(s));
        vm.expectRevert(_unauthorized(s.creator));
        chat.createSession(s, w, forged);
        _refusedCreate(s, w, abi.encodeWithSelector(IPqChat.PqChatNonceUsed.selector, PqChatTypes.scopeSession(s.creator),
            uint64(4))); // the control: its own signature meets the used nonce
    }

    function test_createSession_forgedRecordBurnsNoNonce() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(2, 3, address(chat));
        IUARegistry.UASig memory forged = _sig(ids[1], h.session(s)); // signed by another member's key
        vm.expectRevert(_unauthorized(s.creator));
        chat.createSession(s, w, forged);
        assertFalse(chat.nonceUsed(PqChatTypes.scopeSession(s.creator), 3));
        _create(chat, s, w);
    }

    function test_views_unknownIds() public {
        bytes32 x = keccak256("x");
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatUnknown.selector, x));
        chat.sessionOf(x);
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatUnknown.selector, x));
        chat.epochOf(x);
        assertFalse(chat.epochComplete(x));
        (bytes32 sid,) = _newSession(2);
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatUnknown.selector, sid));
        chat.epochOf(sid); // epoch 0 is the session
    }
}
