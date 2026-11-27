// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {stdJson} from "forge-std/StdJson.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {PqChatRecordLib} from "../../src/pqchat/PqChatRecordLib.sol";
import {PqChatBase} from "./PqChatBase.sol";

/// CTR-CHAT-32 (owner 2026-11-28): `PqChat`'s size split is the external library `PqChatRecordLib`, linked (a verified
/// source shows its address): the release links it, the library holds no state opcode and does nothing on its own, and the
/// three entries that use it keep their checks (their own suites: `PqChat.t.sol`, `PqChatEpochs.t.sol`,
/// `PqChatMessages.t.sol`). **UNAUDITED.**
contract PqChatRecordLibTest is PqChatBase {
    using stdJson for string;

    function _art(string memory name) internal view returns (string memory) {
        return
            vm.readFile(string.concat("./", vm.envOr("FOUNDRY_OUT", string("out")), "/", name, ".sol/", name, ".json"));
    }

    function _has(bytes memory code, address a) internal pure returns (bool) {
        bytes20 w = bytes20(a);
        for (uint256 i; i + 20 <= code.length; ++i) {
            bool eq = true;
            for (uint256 j; j < 20 && eq; ++j) {
                eq = code[i + j] == w[j];
            }
            if (eq) return true;
        }
        return false;
    }

    /// The artifact's link references name the library, and the release's runtime holds its linked address.
    function test_pqchatLinksTheLibrary() public view {
        string[] memory refs = vm.parseJsonKeys(_art("PqChat"), ".deployedBytecode.linkReferences");
        assertEq(refs.length, 1, "one linked source");
        assertEq(refs[0], "src/pqchat/PqChatRecordLib.sol");
        assertTrue(_has(address(impl).code, address(PqChatRecordLib)), "the release holds the library's address");
        assertTrue(address(PqChatRecordLib).code.length > 0, "linked and deployed");
    }

    /// The first opcode of `code` that reads or writes state, logs, reads the caller or the value, makes code, or calls
    /// other than by STATICCALL (SLOAD, SSTORE, TLOAD, TSTORE, LOG0-4, ORIGIN, CALLER, CALLVALUE, CREATE, CALL, CALLCODE,
    /// DELEGATECALL, CREATE2, SELFDESTRUCT); PUSH data skipped and the CBOR tail cut. 0 when there is none.
    function _stateOp(bytes memory code) internal pure returns (uint8) {
        uint256 end = code.length - 2 - (uint256(uint8(code[code.length - 2])) << 8 | uint8(code[code.length - 1]));
        for (uint256 i; i < end; ++i) {
            uint8 o = uint8(code[i]);
            if (o >= 0x60 && o <= 0x7f) {
                i += o - 0x5f;
            } else if (
                o == 0x54 || o == 0x55 || o == 0x5c || o == 0x5d || (o >= 0xa0 && o <= 0xa4) || o == 0x32 || o == 0x33
                    || o == 0x34 || o == 0xf0 || o == 0xf1 || o == 0xf2 || o == 0xf4 || o == 0xf5 || o == 0xff
            ) {
                return o;
            }
        }
        return 0;
    }

    /// The library's runtime holds none of those opcodes (its one call, the registry's `requirePortable`, is a STATICCALL);
    /// the scan finds `PqChat`'s SSTORE (positive control).
    function test_libraryHoldsNoStateOpcode() public view {
        assertEq(_stateOp(address(PqChatRecordLib).code), 0, "PqChatRecordLib: no state opcode");
        assertTrue(_stateOp(address(impl).code) != 0, "the scan finds PqChat's");
    }

    /// Called on its own (not by an instance's DELEGATECALL) the library has no env: its code is no clone, so it names no
    /// registry and refuses; the same record through an instance lands (the control).
    function test_libraryAloneHasNoEnv() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(2, 41, address(chat));
        IUARegistry.UASig memory sig = _sig(s.creator, h.session(s));
        (bool ok,) =
            address(PqChatRecordLib).call(abi.encodeWithSelector(PqChatRecordLib.sessionRecord.selector, s, w, sig));
        assertFalse(ok, "no env, no record");
        assertTrue(chat.createSession(s, w, sig) != 0, "through the instance");
    }
}
