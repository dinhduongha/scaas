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
        (IPqChat.PqChatSession memory s, IUARegistry.UASig memory sig) = _vectorSession(".sessionTreeKem");
        assertEq(s.groupMode, 1);
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatKemKey.selector, s.members[0].ua, s.members[0].keyId));
        chat.createSession(s, new IPqChat.Wrap[](0), sig);
    }

    /// Review C-5: the vector row `sessionMode2` (groupMode 2, reserved for after the freeze, signed by its creator) is
    /// refused by its mode, the row's error, before its unregistered members are read (the control: the row above, the
    /// same record in mode 1, stops at the members).
    function test_theMode2VectorIsRefusedByItsMode() public {
        string memory rec = vm.readFile("../vectors/pqchat/records.json");
        assertEq(vm.parseJsonString(rec, ".sessionMode2.error"), "PqChatModeUnsupported");
        (IPqChat.PqChatSession memory s, IUARegistry.UASig memory sig) = _vectorSession(".sessionMode2");
        assertEq(s.groupMode, 2);
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatModeUnsupported.selector, uint8(2)));
        chat.createSession(s, new IPqChat.Wrap[](0), sig);
    }

    /// The path-less delta §3.1, §13 row 8 (C41, C43): in mode 0 a `pathRefreshBound` or a `confirmTag` that is not 0 is
    /// `PqChatShape`, both 0 the control; the vector rows: `sessionBound0`, `sessionBound24`, `sessionBound510` pass the
    /// bound and stop at their unregistered members (`PqChatKemKey`), `sessionBound511`, `sessionMode0Bound1`,
    /// `sessionMode0Tag` are `PqChatShape`, the rows' error, before them.
    function test_pathRefreshBoundAndTagAtCreation() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(2, 21, address(chat));
        s.pathRefreshBound = 1;
        IUARegistry.UASig memory sig = _sig(s.creator, h.session(s));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatShape.selector));
        chat.createSession(s, w, sig);
        (s.pathRefreshBound, s.confirmTag) = (0, keccak256("a tag in mode 0"));
        sig = _sig(s.creator, h.session(s));
        vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatShape.selector));
        chat.createSession(s, w, sig);
        s.confirmTag = 0;
        _create(chat, s, w);
        string memory rec = vm.readFile("../vectors/pqchat/records.json");
        string[6] memory rows = [
            ".sessionBound0", ".sessionBound24", ".sessionBound510", ".sessionBound511", ".sessionMode0Bound1", ".sessionMode0Tag"
        ];
        for (uint256 i; i < rows.length; ++i) {
            (IPqChat.PqChatSession memory v, IUARegistry.UASig memory vs) = _vectorSession(rows[i]);
            if (i < 3) {
                assertFalse(vm.keyExistsJson(rec, string.concat(rows[i], ".error")), rows[i]);
                vm.expectRevert(
                    abi.encodeWithSelector(IPqChat.PqChatKemKey.selector, v.members[0].ua, v.members[0].keyId)
                );
            } else {
                assertEq(vm.parseJsonString(rec, string.concat(rows[i], ".error")), "PqChatShape", rows[i]);
                vm.expectRevert(abi.encodeWithSelector(IPqChat.PqChatShape.selector));
            }
            chat.createSession(v, new IPqChat.Wrap[](0), vs);
        }
    }

    /// A session row of `records.json` (`row` its key) with its signature.
    function _vectorSession(string memory row)
        internal
        view
        returns (IPqChat.PqChatSession memory s, IUARegistry.UASig memory sig)
    {
        string memory rec = vm.readFile("../vectors/pqchat/records.json");
        string memory p = string.concat(row, ".record");
        s.creator = vm.parseJsonBytes32(rec, string.concat(p, ".creator"));
        s.nonce = uint64(vm.parseJsonUint(rec, string.concat(p, ".nonce")));
        s.homeChain = vm.parseJsonBytes32(rec, string.concat(p, ".homeChain"));
        s.homeChatContract = vm.parseJsonAddress(rec, string.concat(p, ".homeChatContract"));
        s.groupMode = uint8(vm.parseJsonUint(rec, string.concat(p, ".groupMode")));
        s.pathRefreshBound = uint32(vm.parseJsonUint(rec, string.concat(p, ".pathRefreshBound")));
        s.confirmTag = vm.parseJsonBytes32(rec, string.concat(p, ".confirmTag"));
        s.admins = vm.parseJsonBytes32Array(rec, string.concat(p, ".admins"));
        s.wrapHashes = vm.parseJsonBytes32Array(rec, string.concat(p, ".wrapHashes"));
        s.sealedInfo = vm.parseJsonBytes(rec, string.concat(p, ".sealedInfo"));
        s.members = new IPqChat.MemberKey[](s.wrapHashes.length);
        for (uint256 i; i < s.members.length; ++i) {
            string memory q = string.concat(p, ".members[", vm.toString(i), "]");
            s.members[i].ua = vm.parseJsonBytes32(rec, string.concat(q, ".ua"));
            s.members[i].keyId = uint64(vm.parseJsonUint(rec, string.concat(q, ".keyId")));
        }
        sig.signature = vm.parseJsonBytes(rec, string.concat(row, ".uaSig.signature"));
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
