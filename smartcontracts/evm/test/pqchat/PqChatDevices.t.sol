// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {PqChat} from "../../src/pqchat/PqChat.sol";
import {PqChatTypes} from "../../src/pqchat/PqChatTypes.sol";
import {PqChatBase} from "./PqChatBase.sol";

/// Owner ruling (M) of 2026-11-23 (CTR-CHAT-24): a member may sit in an epoch with several KEM keys, `members` strictly sorted
/// by `(ua, keyId)`, one wrap per entry, at most `KEYS_PER_UA_MAX` = 8 keys per UA; a single key behaves as before. Everything
/// else stays per UA: the minimum member count, `sessionsOf`, the plain-rekey rule, leave and removal.
contract PqChatDevicesTest is PqChatBase {
    function _mk(bytes32 ua, uint64 keyId) internal pure returns (IPqChat.MemberKey memory) {
        return IPqChat.MemberKey(ua, keyId, bytes32(0));
    }

    /// A session of `m` (as given), created by `ids[0]`, the only admin, homed at `chat`.
    function _sessionOf(IPqChat.MemberKey[] memory m, uint64 nonce)
        internal
        view
        returns (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w)
    {
        (s.creator, s.nonce, s.homeChain, s.homeChatContract) = (ids[0], nonce, chainUidA, address(chat));
        s.admins = _list(ids[0]);
        s.members = m;
        w = _wraps(m, PqChatTypes.sessionId(ids[0], nonce));
        s.wrapHashes = _hashes(w);
        s.sealedInfo = hex"5ea1ed";
    }

    function _three(bytes32 a, uint64 ka, bytes32 b, uint64 kb, bytes32 c, uint64 kc)
        internal
        pure
        returns (IPqChat.MemberKey[] memory m)
    {
        m = new IPqChat.MemberKey[](3);
        (m[0], m[1], m[2]) = (_mk(a, ka), _mk(b, kb), _mk(c, kc));
    }

    /// The creator with a device key beside its seed key: one wrap each, the session listed once per UA.
    function test_aMemberWithTwoKeysHasAWrapForEach() public {
        _devices(ids[0], 1);
        IPqChat.MemberKey[] memory m = _three(ids[0], 0, ids[0], 1, ids[1], 0);
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _sessionOf(m, 1);
        bytes32 sid = _create(chat, s, w);
        assertTrue(chat.epochComplete(sid), "three wraps landed");
        assertEq(chat.wrapAt(sid, 1).keyId, 1, "the device key's wrap");
        assertEq(chat.sessionCount(ids[0]), 1, "one entry per UA");
        assertEq(chat.sessionCount(ids[1]), 1);
    }

    /// `(ua, keyId)` strictly ascending; a KEM version the UA does not hold refused as before.
    function test_keysOfOneMemberStrictlyAscending() public {
        _devices(ids[0], 1);
        IPqChat.MemberKey[] memory m = _three(ids[0], 1, ids[0], 0, ids[1], 0);
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _sessionOf(m, 1);
        IUARegistry.UASig memory sig = _sig(s.creator, h.session(s));
        vm.expectRevert(IPqChat.PqChatShape.selector);
        chat.createSession(s, w, sig);
        (s, w) = _sessionOf(_three(ids[0], 0, ids[0], 0, ids[1], 0), 2);
        sig = _sig(s.creator, h.session(s));
        vm.expectRevert(IPqChat.PqChatShape.selector);
        chat.createSession(s, w, sig);
        (s, w) = _sessionOf(_three(ids[0], 0, ids[0], 2, ids[1], 0), 3);
        sig = _sig(s.creator, h.session(s));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatKemKey.selector, ids[0], uint64(2)));
        chat.createSession(s, w, sig);
    }

    /// At most 8 keys per UA (KEYS_PER_UA_MAX): 8 land, 9 refused.
    function test_atMostEightKeysPerMember() public {
        _devices(ids[0], 8);
        for (uint64 n = 8; n <= 9; ++n) {
            IPqChat.MemberKey[] memory m = new IPqChat.MemberKey[](n + 1);
            for (uint64 k; k < n; ++k) {
                m[k] = _mk(ids[0], k);
            }
            m[n] = _mk(ids[1], 0);
            (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _sessionOf(m, n);
            IUARegistry.UASig memory sig = _sig(s.creator, h.session(s));
            if (n == 9) vm.expectRevert(IPqChat.PqChatShape.selector);
            chat.createSession(s, w, sig);
        }
    }

    /// The minimum of 2 members counts UAs: the creator with two keys alone is no session.
    function test_twoKeysOfOneUaAreOneMember() public {
        _devices(ids[0], 1);
        IPqChat.MemberKey[] memory m = new IPqChat.MemberKey[](2);
        (m[0], m[1]) = (_mk(ids[0], 0), _mk(ids[0], 1));
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _sessionOf(m, 1);
        IUARegistry.UASig memory sig = _sig(s.creator, h.session(s));
        vm.expectRevert(IPqChat.PqChatShape.selector);
        chat.createSession(s, w, sig);
    }

    /// Adding or dropping a member's device key is a plain rekey (the UAs unchanged): a member who is no admin authors it;
    /// adding a UA is still a membership change.
    function test_aMembersKeysChangeInAPlainRekey() public {
        _devices(ids[1], 1);
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _sessionOf(_members(2), 1);
        bytes32 sid = _create(chat, s, w);
        IPqChat.MemberKey[] memory m = _three(ids[0], 0, ids[1], 0, ids[1], 1);
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory ew) = _epoch(sid, ids[1], 1, 1, sid, s.admins, m);
        bytes32 e1 = _rekey(chat, e, ew);
        assertTrue(chat.epochComplete(e1), "ids[1] adds its device key: plain");
        assertEq(chat.sessionCount(ids[1]), 1, "no new entry for a member's new key");
        (e, ew) = _epoch(sid, ids[1], 2, 2, e1, s.admins, _members(2));
        bytes32 e2 = _rekey(chat, e, ew);
        assertTrue(chat.epochComplete(e2), "and drops it again: plain");
        m = _three(ids[0], 0, ids[1], 0, ids[2], 0);
        (e, ew) = _epoch(sid, ids[1], 3, 3, e2, s.admins, m);
        IUARegistry.UASig memory sig = _sig(e.author, h.epoch(e));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatNotAdmin.selector, ids[1]));
        chat.rekey(e, ew, sig);
        // the admin adds a member with two keys: `sessionsOf` gains it once
        _devices(ids[2], 1);
        IPqChat.MemberKey[] memory m4 = new IPqChat.MemberKey[](4);
        (m4[0], m4[1], m4[2], m4[3]) = (_mk(ids[0], 0), _mk(ids[1], 0), _mk(ids[2], 0), _mk(ids[2], 1));
        (e, ew) = _epoch(sid, ids[0], 4, 3, e2, s.admins, m4);
        assertTrue(chat.epochComplete(_rekey(chat, e, ew)));
        assertEq(chat.sessionCount(ids[2]), 1, "the added member once, not per key");
    }

    /// Leave and removal stay per UA: a removed member's every key is out of the child, a leaver's keys may all go plainly.
    function test_removalAndLeaveTakeEveryKeyOfTheUa() public {
        _devices(ids[1], 1);
        _devices(ids[2], 1);
        IPqChat.MemberKey[] memory m = new IPqChat.MemberKey[](5);
        (m[0], m[1], m[2], m[3], m[4]) =
        (_mk(ids[0], 0), _mk(ids[1], 0), _mk(ids[1], 1), _mk(ids[2], 0), _mk(ids[2], 1));
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _sessionOf(m, 1);
        bytes32 sid = _create(chat, s, w);
        IPqChat.PqChatRemove memory rm = IPqChat.PqChatRemove(sid, sid, 1, _list(ids[2]), ids[0], 9);
        chat.remove(rm, _sig(ids[0], h.remove(rm)));
        IPqChat.PqChatLeave memory l = IPqChat.PqChatLeave(sid, sid, ids[1], 3);
        chat.leave(l, _sig(ids[1], h.leave(l)));
        // keeping one key of the removed UA: refused at completion
        IPqChat.MemberKey[] memory keep = _three(ids[0], 0, ids[1], 0, ids[2], 1);
        (IPqChat.PqChatEpoch memory e, IPqChat.Wrap[] memory ew) = _epoch(sid, ids[0], 1, 1, sid, s.admins, keep);
        IUARegistry.UASig memory sig = _sig(e.author, h.epoch(e));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatRemovedKept.selector, sid, ids[2]));
        chat.rekey(e, ew, sig);
        // dropping the removed UA's keys and the leaver's: a plain rekey
        IPqChat.MemberKey[] memory one = new IPqChat.MemberKey[](1);
        one[0] = _mk(ids[0], 0);
        (e, ew) = _epoch(sid, ids[0], 2, 1, sid, s.admins, one);
        assertTrue(chat.epochComplete(_rekey(chat, e, ew)));
    }
}
