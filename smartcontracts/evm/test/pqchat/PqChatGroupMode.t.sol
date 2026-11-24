// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {PqChatBase} from "./PqChatBase.sol";

/// CTR-CHAT-25, CTR-CHAT-26 (owner 2026-11-23): `PqChatSession.groupMode`, 0 flat wraps, 1 TreeKEM, fixed at creation; this
/// release accepts 0 and 1 and refuses 2-255 by name before anything else is checked. No epoch, leave or removal record names
/// a mode, so no child can change it. The tree mode's own checks: `PqChatTree.t.sol`.
contract PqChatGroupModeTest is PqChatBase {
    function test_onlyFlatWrapsAndTreeKemAccepted() public {
        for (uint8 mode = 2; mode != 0; mode = mode == 2 ? 3 : mode == 3 ? 255 : 0) {
            (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(2, mode, address(chat));
            s.groupMode = mode;
            IUARegistry.UASig memory sig = _sig(s.creator, h.session(s));
            vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatModeUnsupported.selector, mode));
            chat.createSession(s, w, sig);
        }
        // the control: mode 0 lands and the session view returns it
        (IPqChat.PqChatSession memory s0, IPqChat.Wrap[] memory w0) = _session(2, 9, address(chat));
        bytes32 sid = _create(chat, s0, w0);
        (IPqChat.PqChatSession memory got,) = chat.sessionOf(sid);
        assertEq(got.groupMode, 0);
    }

    /// The vector row `sessionTreeKem` (groupMode 1, signed by its creator) is no longer refused by its mode: its members
    /// are not registered here, so it stops at their keys (P3) after the mode check.
    function test_theTreeKemVectorPassesTheModeCheck() public {
        string memory rec = vm.readFile("../vectors/pqchat/records.json");
        string memory p = ".sessionTreeKem.record";
        IPqChat.PqChatSession memory s;
        s.creator = vm.parseJsonBytes32(rec, string.concat(p, ".creator"));
        s.nonce = uint64(vm.parseJsonUint(rec, string.concat(p, ".nonce")));
        s.homeChain = vm.parseJsonBytes32(rec, string.concat(p, ".homeChain"));
        s.homeChatContract = vm.parseJsonAddress(rec, string.concat(p, ".homeChatContract"));
        s.groupMode = uint8(vm.parseJsonUint(rec, string.concat(p, ".groupMode")));
        s.admins = vm.parseJsonBytes32Array(rec, string.concat(p, ".admins"));
        s.wrapHashes = vm.parseJsonBytes32Array(rec, string.concat(p, ".wrapHashes"));
        s.sealedInfo = vm.parseJsonBytes(rec, string.concat(p, ".sealedInfo"));
        s.members = new IPqChat.MemberKey[](s.wrapHashes.length);
        for (uint256 i; i < s.members.length; ++i) {
            string memory q = string.concat(p, ".members[", vm.toString(i), "]");
            s.members[i].ua = vm.parseJsonBytes32(rec, string.concat(q, ".ua"));
            s.members[i].keyId = uint64(vm.parseJsonUint(rec, string.concat(q, ".keyId")));
        }
        IUARegistry.UASig memory sig;
        sig.signature = vm.parseJsonBytes(rec, ".sessionTreeKem.uaSig.signature");
        assertEq(s.groupMode, 1);
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatKemKey.selector, s.members[0].ua, s.members[0].keyId));
        chat.createSession(s, new IPqChat.Wrap[](0), sig);
    }

    /// The refusal comes first: a mode-2 record with a signature of nobody and unregistered members is refused by its mode.
    function test_theModeIsCheckedFirst() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(2, 3, address(chat));
        s.groupMode = 2;
        s.members[0].keyId = 77; // a KEM version nobody holds
        IUARegistry.UASig memory nobody;
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatModeUnsupported.selector, uint8(2)));
        chat.createSession(s, w, nobody);
    }
}
