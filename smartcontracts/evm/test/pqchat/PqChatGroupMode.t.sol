// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {PqChatBase} from "./PqChatBase.sol";

/// CTR-CHAT-25 (owner 2026-11-23): `PqChatSession.groupMode`, 0 flat wraps, 1 TreeKEM, fixed at creation; this release accepts
/// 0 only and refuses every other value by name before anything else is checked (a later catalogued release accepts 1 with
/// the same struct and typehash). No epoch, leave or removal record names a mode, so no child can change it.
contract PqChatGroupModeTest is PqChatBase {
    function test_onlyFlatWrapsAccepted() public {
        for (uint8 mode = 1; mode != 0; mode = mode == 1 ? 2 : mode == 2 ? 255 : 0) {
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

    /// The vector row `sessionTreeKem` (groupMode 1, signed by its creator) is refused by name, as the row says.
    function test_theTreeKemVectorIsRefused() public {
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
        IUARegistry.UASig memory sig;
        sig.signature = vm.parseJsonBytes(rec, ".sessionTreeKem.uaSig.signature");
        assertEq(vm.parseJsonString(rec, ".sessionTreeKem.error"), "PqChatModeUnsupported(1)");
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatModeUnsupported.selector, uint8(1)));
        chat.createSession(s, new IPqChat.Wrap[](0), sig);
    }

    /// The refusal comes first: a mode-1 record with a signature of nobody and unregistered members is refused by its mode.
    function test_theModeIsCheckedFirst() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(2, 3, address(chat));
        s.groupMode = 1;
        s.members[0].keyId = 77; // a KEM version nobody holds
        IUARegistry.UASig memory nobody;
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatModeUnsupported.selector, uint8(1)));
        chat.createSession(s, w, nobody);
    }
}
