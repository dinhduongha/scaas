// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IOpenFactory} from "../../src/factory/IOpenFactory.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {PqChat} from "../../src/pqchat/PqChat.sol";
import {PqChatBase} from "./PqChatBase.sol";

/// CTR-CHAT-23 (owner 2026-11-23): the signature-storage setting of an instance, fixed at `initialize`. `none` (0) keeps a record
/// and its `sigHash` only, as before; `sstore2` (2) keeps the signature after them in the record's own blob, read by the `*Sig`
/// views; any other value is refused. The signature is checked at write in both modes, as before.
contract PqChatSigsTest is PqChatBase {
    PqChat internal none_;

    function setUp() public override {
        super.setUp();
        none_ = _instanceWith("none", bytes32(0), 0);
    }

    function _root() internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(uint256(keccak256("scaas.pqchat")) - 1))) & ~uint256(0xff);
    }

    function _map(bytes32 key, uint256 slot) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(key, slot)));
    }

    /// The bytes of a one-blob record: its runtime after the leading `STOP` and the flag byte 0.
    function _blob(address ptr) internal view returns (bytes memory b) {
        bytes memory code = ptr.code;
        assertEq(uint8(code[1]), 0, "one blob");
        b = new bytes(code.length - 2);
        for (uint256 i; i < b.length; ++i) {
            b[i] = code[i + 2];
        }
    }

    function _recordPtr(PqChat c, bytes32 id) internal view returns (address) {
        return address(uint160(uint256(vm.load(address(c), bytes32(_map(id, _root() + 2) + 1)))));
    }

    function _listPtr(PqChat c, bytes32 key, uint256 field, uint256 i) internal view returns (address) {
        uint256 l = _map(key, _root() + field);
        return address(uint160(uint256(vm.load(address(c), bytes32(uint256(keccak256(abi.encode(l))) + i)))));
    }

    /// The view's raw output is `abi.encode(sig)`: exactly the signature accepted (read raw: the compiler's memory decoder of a
    /// `UASig` runs out of stack in a test as in the contract).
    function _same(PqChat c, bytes memory call, IUARegistry.UASig memory sig) internal view {
        (bool ok, bytes memory ret) = address(c).staticcall(call);
        assertTrue(ok, "the signature view answers");
        assertEq(ret, abi.encode(sig), "the signed bytes");
    }

    function _refused(PqChat c, bytes memory call, bytes memory err) internal view {
        (bool ok, bytes memory ret) = address(c).staticcall(call);
        assertFalse(ok, "refused");
        assertEq(ret, err, "by name");
    }

    // the last `_flow`'s ids, the signatures each record was accepted with (session, leave, remove, epoch, message), its leave
    bytes32 internal sid_;
    bytes32 internal eid_;
    bytes[5] internal sigBytes_; // each `UASig`'s `signature` (no `keyData`, no members)
    IPqChat.PqChatLeave internal l_;

    function _sigAt(uint256 i) internal view returns (IUARegistry.UASig memory x) {
        x.signature = sigBytes_[i];
    }

    /// Every control-plane write and a posted message on `c`.
    function _flow(PqChat c) internal {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(3, 5, address(c));
        sigBytes_[0] = _sig(s.creator, h.session(s)).signature;
        sid_ = c.createSession(s, w, _sigAt(0));
        l_ = IPqChat.PqChatLeave(sid_, sid_, ids[1], 9);
        sigBytes_[1] = _sig(ids[1], h.leave(l_)).signature;
        c.leave(l_, _sigAt(1));
        IPqChat.PqChatRemove memory rm = IPqChat.PqChatRemove(sid_, sid_, 1, _list(ids[2]), ids[0], 7);
        sigBytes_[2] = _sig(ids[0], h.remove(rm)).signature;
        c.remove(rm, _sigAt(2));
        _flowEpoch(c, s);
    }

    function _flowEpoch(PqChat c, IPqChat.PqChatSession memory s) internal {
        IPqChat.MemberKey[] memory kept = _without(_without(s.members, ids[1]), ids[2]);
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory ew) = _epoch(sid_, ids[0], 8, 1, sid_, s.admins, kept);
        sigBytes_[3] = _sig(ids[0], h.epoch(e)).signature;
        eid_ = c.rekey(e, ew, _sigAt(3));
        IPqChat.PqChatMessage memory m;
        (m.sessionId, m.epochId, m.sender, m.device, m.counter) = (sid_, eid_, ids[0], bytes16(uint128(7)), 3);
        m.ciphertext = hex"c1c2c3";
        sigBytes_[4] = _sig(ids[0], h.message(m)).signature;
        c.postMessage(m, _sigAt(4));
    }

    function test_initializeTakesNoneOrSstore2Only() public {
        assertEq(chat.sigStore(), 2, "the tests' default instance: sstore2");
        assertEq(none_.sigStore(), 0, "none");
        for (uint8 v = 1; v != 0; v = v == 1 ? 3 : v == 3 ? 255 : 0) {
            vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatSigStore.selector, v));
            f.createInstance(
                IOpenFactory.ReleaseId(3, 0, 1),
                bytes32(uint256(v)),
                abi.encodeCall(IPqChat.initialize, (bytes32(0), v))
            );
        }
    }

    /// `none`: each blob is exactly `abi.encode(record, sigHash)`, no leave record, every signature view refuses.
    function test_noneHomeStoresNoSignature() public {
        _flow(none_);
        (IPqChat.PqChatSession memory s, bytes32 sh) = none_.sessionOf(sid_);
        assertEq(sh, keccak256(abi.encode(_sigAt(0))));
        assertEq(_blob(_recordPtr(none_, sid_)), abi.encode(s, sh), "session: record and sigHash only");
        (IPqChat.PqChatEpoch memory e, bytes32 eh) = none_.epochOf(eid_);
        assertEq(_blob(_recordPtr(none_, eid_)), abi.encode(e, eh), "epoch: record and sigHash only");
        _noneLists();
        assertTrue(none_.leftIn(sid_, ids[1]), "the leave flag as before");
        assertEq(none_.leaveCount(sid_), 0, "no leave record");
        bytes memory no = abi.encodeWithSelector(IPqChat.PqChatSigNotStored.selector);
        _refused(none_, abi.encodeCall(IPqChat.sessionSig, (sid_)), no);
        _refused(none_, abi.encodeCall(IPqChat.epochSig, (eid_)), no);
        _refused(none_, abi.encodeCall(IPqChat.removalSig, (sid_, 0)), no);
        _refused(none_, abi.encodeCall(IPqChat.messageSig, (sid_, 0)), no);
        _refused(none_, abi.encodeCall(IPqChat.leaveSig, (sid_, 0)), no);
    }

    function _noneLists() internal view {
        (IPqChat.PqChatRemove memory rm, bytes32 rh) = none_.removalAt(sid_, 0);
        assertEq(_blob(_listPtr(none_, sid_, 21, 0)), abi.encode(rm, rh), "removal: record and sigHash only");
        (IPqChat.PqChatMessage memory m, bytes32 mh) = none_.messageAt(sid_, 0);
        assertEq(_blob(_listPtr(none_, sid_, 5, 0)), abi.encode(m, mh), "message: record and sigHash only");
    }

    /// `sstore2`: each blob is `abi.encode(record, sigHash, sig)` and each view returns exactly the signature accepted.
    function test_sstore2HomeReturnsTheSignedBytes() public {
        _flow(chat);
        (IPqChat.PqChatSession memory s, bytes32 sh) = chat.sessionOf(sid_);
        assertEq(sh, keccak256(abi.encode(_sigAt(0))), "sigHash kept");
        assertEq(_blob(_recordPtr(chat, sid_)), abi.encode(s, sh, _sigAt(0)), "session blob");
        _same(chat, abi.encodeCall(IPqChat.sessionSig, (sid_)), _sigAt(0));
        (IPqChat.PqChatEpoch memory e, bytes32 eh) = chat.epochOf(eid_);
        assertEq(_blob(_recordPtr(chat, eid_)), abi.encode(e, eh, _sigAt(3)), "epoch blob");
        _same(chat, abi.encodeCall(IPqChat.epochSig, (eid_)), _sigAt(3));
        _keptLeave();
        _keptLists();
        // a session id is no epoch and an epoch id no session, as the record views
        bytes32 x = bytes32(uint256(1));
        _refused(
            chat, abi.encodeCall(IPqChat.epochSig, (sid_)), abi.encodeWithSelector(IPqChat.PqChatUnknown.selector, sid_)
        );
        _refused(
            chat,
            abi.encodeCall(IPqChat.sessionSig, (eid_)),
            abi.encodeWithSelector(IPqChat.PqChatUnknown.selector, eid_)
        );
        _refused(
            chat, abi.encodeCall(IPqChat.sessionSig, (x)), abi.encodeWithSelector(IPqChat.PqChatUnknown.selector, x)
        );
    }

    function _keptLeave() internal view {
        assertEq(chat.leaveCount(sid_), 1, "one leave record");
        (IPqChat.PqChatLeave memory lr, bytes32 lh) = chat.leaveAt(sid_, 0);
        assertEq(keccak256(abi.encode(lr)), keccak256(abi.encode(l_)), "the leave record");
        assertEq(lh, keccak256(abi.encode(_sigAt(1))), "its sigHash");
        assertEq(_blob(_listPtr(chat, sid_, 22, 0)), abi.encode(l_, lh, _sigAt(1)), "leave blob");
        _same(chat, abi.encodeCall(IPqChat.leaveSig, (sid_, 0)), _sigAt(1));
    }

    function _keptLists() internal view {
        (IPqChat.PqChatRemove memory rm, bytes32 rh) = chat.removalAt(sid_, 0);
        assertEq(_blob(_listPtr(chat, sid_, 21, 0)), abi.encode(rm, rh, _sigAt(2)), "removal blob");
        _same(chat, abi.encodeCall(IPqChat.removalSig, (sid_, 0)), _sigAt(2));
        (IPqChat.PqChatMessage memory m, bytes32 mh) = chat.messageAt(sid_, 0);
        assertEq(_blob(_listPtr(chat, sid_, 5, 0)), abi.encode(m, mh, _sigAt(4)), "message blob");
        _same(chat, abi.encodeCall(IPqChat.messageSig, (sid_, 0)), _sigAt(4));
    }

    /// The signature is checked at write in both modes: one over another record is refused and stores nothing.
    function test_aMismatchedSignatureIsRefusedInBothModes() public {
        PqChat[2] memory cs = [chat, none_];
        for (uint256 k; k < 2; ++k) {
            PqChat c = cs[k];
            (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(2, 11, address(c));
            bytes memory info = s.sealedInfo;
            IUARegistry.UASig memory good = _sig(s.creator, h.session(s));
            s.sealedInfo = hex"bad0"; // the signed sealedInfo substituted
            vm.expectRevert(_unauthorized(s.creator));
            c.createSession(s, w, good);
            s.sealedInfo = info;
            bytes32 sid = c.createSession(s, w, good);
            IPqChat.PqChatLeave memory l = IPqChat.PqChatLeave(sid, sid, ids[1], 3);
            IUARegistry.UASig memory other = _sig(ids[0], h.leave(l)); // another member's key
            vm.expectRevert(_unauthorized(ids[1]));
            c.leave(l, other);
            assertEq(c.leaveCount(sid), 0, "a refused leave stores nothing");
            assertFalse(c.leftIn(sid, ids[1]));
            (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory ew) =
                _epoch(sid, ids[0], 4, 1, sid, s.admins, s.members);
            IUARegistry.UASig memory es = _sig(ids[0], h.epoch(e));
            e.sealedInfo = hex"bad1";
            vm.expectRevert(_unauthorized(ids[0]));
            c.rekey(e, ew, es);
        }
    }
}
