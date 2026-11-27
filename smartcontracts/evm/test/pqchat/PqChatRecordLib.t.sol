// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {stdJson} from "forge-std/StdJson.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {PqChatRecordLib} from "../../src/pqchat/PqChatRecordLib.sol";
import {PqChatTypes} from "../../src/pqchat/PqChatTypes.sol";
import {PqChat} from "../../src/pqchat/PqChat.sol";
import {IFactoryToken} from "../../src/factory/IFactoryToken.sol";
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
        (bool ok, bytes memory ret) =
            address(PqChatRecordLib).call(abi.encodeWithSelector(PqChatRecordLib.sessionRecord.selector, s, w, sig));
        assertFalse(ok, "no env, no record");
        assertEq(ret.length, 0, "the registry it names (none) has no code: an empty revert");
        assertTrue(chat.createSession(s, w, sig) != 0, "through the instance");
    }
    // ----- the review's negatives (Fable A-3, E-2, E-3, D-5, A-1) -----

    function _root() internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(uint256(keccak256("scaas.pqchat")) - 1))) & ~uint256(0xff);
    }

    /// The linked address holds no code: every entry that forwards to it reverts (an empty return decodes to nothing) and
    /// burns no nonce; with the code back the same records land (the control).
    function test_libraryWithoutCodeFailsClosed() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(2, 61, address(chat));
        IUARegistry.UASig memory sig = _sig(s.creator, h.session(s));
        bytes memory code = address(PqChatRecordLib).code;
        vm.etch(address(PqChatRecordLib), "");
        vm.expectRevert();
        chat.createSession(s, w, sig);
        assertFalse(chat.nonceUsed(PqChatTypes.scopeSession(s.creator), 61), "no nonce used");
        vm.etch(address(PqChatRecordLib), code);
        bytes32 sid = chat.createSession(s, w, sig);
        IPqChat.PqChatMessage memory m;
        (m.sessionId, m.epochId, m.sender, m.device, m.counter, m.ciphertext) =
        (sid, sid, ids[1], bytes16(uint128(3)), 9, hex"0102");
        IUARegistry.UASig memory ms = _sig(m.sender, h.message(m));
        vm.etch(address(PqChatRecordLib), "");
        vm.expectRevert();
        chat.postMessage(m, ms);
        assertFalse(chat.nonceUsed(PqChatTypes.scopeMessage(sid, m.sender, m.device), 9), "no message nonce used");
        vm.etch(address(PqChatRecordLib), code);
        assertEq(chat.postMessage(m, ms), 0, "the control");
    }

    /// The ABI path of the function `name` in `art`.
    function _fn(string memory art, string memory name) internal view returns (string memory at) {
        for (uint256 i;; ++i) {
            at = string.concat(".abi[", vm.toString(i), "]");
            require(vm.keyExistsJson(art, at), string.concat("no function ", name));
            if (!vm.keyExistsJson(art, string.concat(at, ".name"))) continue;
            if (keccak256(bytes(art.readString(string.concat(at, ".name")))) == keccak256(bytes(name))) return at;
        }
    }

    /// `_record` forwards an entry's calldata to a library function: the compiler does not tie their inputs, so this pins
    /// them: the same number of inputs, each of the same `internalType` (the same struct, the same array).
    function test_entriesAndLibraryTakeTheSameInputs() public view {
        (string memory chatArt, string memory libArt) = (_art("PqChat"), _art("PqChatRecordLib"));
        string[2][3] memory pairs =
            [["createSession", "sessionRecord"], ["rekey", "epochRecord"], ["postMessage", "messageRecord"]];
        for (uint256 k; k < 3; ++k) {
            string memory a = string.concat(_fn(chatArt, pairs[k][0]), ".inputs");
            string memory b = string.concat(_fn(libArt, pairs[k][1]), ".inputs");
            uint256 n;
            while (vm.keyExistsJson(chatArt, string.concat(a, "[", vm.toString(n), "]"))) ++n;
            assertFalse(vm.keyExistsJson(libArt, string.concat(b, "[", vm.toString(n), "]")), "no extra library input");
            assertGt(n, 1);
            for (uint256 j; j < n; ++j) {
                string memory ia = string.concat(a, "[", vm.toString(j), "].internalType");
                string memory ib = string.concat(b, "[", vm.toString(j), "].internalType");
                assertEq(chatArt.readString(ia), libArt.readString(ib), pairs[k][0]);
            }
        }
    }

    /// The release links one library, and none of its four body modules links any: the class env's closure is the library
    /// then the modules (Fable D-5: a module that later links a library fails here until the env pins it).
    function test_envIsTheLinkClosure() public view {
        string[4] memory mods = ["PqChatTopics", "PqChatTree", "PqChatTreeViews", "PqChatTreeMembers"];
        for (uint256 i; i < 4; ++i) {
            assertEq(vm.parseJsonKeys(_art(mods[i]), ".deployedBytecode.linkReferences").length, 0, mods[i]);
        }
        IFactoryToken.Env memory e = f.classEnvOf(3, 0, 1);
        assertEq(e.libs.length, 5);
        assertEq(e.libs[0], address(PqChatRecordLib), "the closure first");
        address[] memory m = PqChat(impl).modules();
        for (uint256 i; i < 4; ++i) {
            assertEq(e.libs[1 + i], m[i], "then the modules, in order");
        }
    }

    function _word(bytes memory b, uint256 at) internal pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(b, 32), at))
        }
    }

    /// A non-canonical encoding of `createSession` (32 bytes between the head and the record, every head offset moved, 64
    /// trailing bytes) lands, and the library decodes the record `PqChat` decodes: the stored blob is the canonical form's,
    /// byte for byte (Fable E-3).
    function test_nonCanonicalCalldataStoresTheCanonicalRecord() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(2, 71, address(chat));
        IUARegistry.UASig memory sig = _sig(s.creator, h.session(s));
        bytes memory c = abi.encodeCall(PqChat.createSession, (s, w, sig));
        bytes memory head = new bytes(100); // the selector and the three offsets, each moved by 32
        for (uint256 i; i < 100; ++i) {
            head[i] = c[i];
        }
        for (uint256 k; k < 3; ++k) {
            bytes32 off = bytes32(uint256(_word(c, 4 + 32 * k)) + 32);
            for (uint256 b; b < 32; ++b) {
                head[4 + 32 * k + b] = off[b];
            }
        }
        bytes memory tail = new bytes(c.length - 100);
        for (uint256 i; i < tail.length; ++i) {
            tail[i] = c[100 + i];
        }
        (bool ok,) =
            address(chat).call(bytes.concat(head, keccak256("a gap"), tail, keccak256("trail"), keccak256("ing")));
        assertTrue(ok, "the non-canonical call lands");
        bytes32 sid = PqChatTypes.sessionId(s.creator, 71);
        uint256 slot = uint256(keccak256(abi.encode(sid, _root() + 2))) + 1;
        address rec = address(uint160(uint256(vm.load(address(chat), bytes32(slot)))));
        bytes memory want = bytes.concat(hex"0000", abi.encode(s, keccak256(abi.encode(sig)), sig));
        assertEq(rec.code, want, "the canonical blob");
    }

    /// A flat session's message (the library's path) is stored as `abi.encode(m, sigHash, sig)` behind the code's STOP
    /// byte and the flag; the tree path's own copy of the step (`PqChatCore._post`) is pinned to the same form in
    /// `PqChatTreeViews.t.sol` (Fable A-1, E-5).
    function test_flatMessageBlobForm() public {
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(2, 81, address(chat));
        bytes32 sid = chat.createSession(s, w, _sig(s.creator, h.session(s)));
        IPqChat.PqChatMessage memory m;
        (m.sessionId, m.epochId, m.sender, m.device, m.counter, m.ciphertext) =
        (sid, sid, ids[1], bytes16(uint128(4)), 1, hex"0a0b0c");
        IUARegistry.UASig memory sig = _sig(m.sender, h.message(m));
        chat.postMessage(m, sig);
        uint256 list = uint256(keccak256(abi.encode(sid, _root() + 5)));
        address at = address(uint160(uint256(vm.load(address(chat), keccak256(abi.encode(list))))));
        assertEq(at.code, bytes.concat(hex"0000", abi.encode(m, keccak256(abi.encode(sig)), sig)), "the flat form");
    }
}
