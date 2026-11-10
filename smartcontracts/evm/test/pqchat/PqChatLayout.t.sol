// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {stdJson} from "forge-std/StdJson.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {PqChatTypes} from "../../src/pqchat/PqChatTypes.sol";
import {PqChatBase} from "./PqChatBase.sol";

/// Plan 3c T85: `PqChat`'s storage is the ERC-7201 namespace `scaas.pqchat` only (no plain slot: `test/v2/layout/PqChat.json`
/// is empty), each field at its pinned slot inside it, read with `vm.load` after a write through the entries.
contract PqChatLayoutTest is PqChatBase {
    using stdJson for string;

    function _root() internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(uint256(keccak256("scaas.pqchat")) - 1))) & ~uint256(0xff);
    }

    function test_storageLayoutIsPinned() public view {
        string memory art = vm.readFile(string.concat("./", vm.envOr("FOUNDRY_OUT", string("out")), "/PqChat.sol/PqChat.json"));
        string memory pin = vm.readFile("./test/v2/layout/PqChat.json");
        assertEq(pin.readStringArray(".labels").length, 0);
        assertFalse(vm.keyExistsJson(art, ".storageLayout.storage[0]"), "no plain slot");
        string memory mod = vm.readFile(string.concat("./", vm.envOr("FOUNDRY_OUT", string("out")),
            "/PqChatTopics.sol/PqChatTopics.json"));
        assertFalse(vm.keyExistsJson(mod, ".storageLayout.storage[0]"), "the body module: no plain slot either (CTR-TOK-30)");
        assertEq(_root(), 0xc7b36804b17476e9a19a6ebc690cd7b9326d322c515fd7dc91373f9bc6dc3000);
    }

    function _at(uint256 slot) internal view returns (uint256) {
        return uint256(vm.load(address(chat), bytes32(slot)));
    }

    function _map(bytes32 key, uint256 slot) internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(key, slot)));
    }

    /// The namespace's fields: owner +0, initialized +1, epochs +2 (sessionId; record | epoch << 160 | wraps << 224;
    /// landed | home << 32; parent; wrapAt; left), childOf +3, nonces +4, messages +5, stored +6.
    function test_namespaceFieldsArePinned() public {
        uint256 r = _root();
        assertEq(bytes32(_at(r)), OWNER_UA);
        assertEq(_at(r + 1), 1);
        (IPqChat.PqChatSession memory s, IPqChat.Wrap[] memory w) = _session(3, 5, address(chat));
        bytes32 sid = _create(chat, s, _slice(w, 0, 2));
        uint256 e = _map(sid, r + 2);
        assertEq(bytes32(_at(e)), sid);
        uint256 packed = _at(e + 1);
        assertTrue(address(uint160(packed)).code.length > 0, "the record blob");
        assertEq(packed >> 160 & type(uint64).max, 0, "epoch 0");
        assertEq(packed >> 224, 3, "wraps");
        assertEq(_at(e + 2), 2 | 1 << 32, "landed 2, home");
        assertEq(_at(e + 3), 0, "no parent");
        uint256 w0 = _at(_map(bytes32(0), e + 4));
        assertTrue(address(uint160(w0)).code.length > 0 && w0 >> 160 == 0, "wrap 0 at offset 0");
        assertEq(_at(_map(bytes32(uint256(1)), e + 4)) >> 160, 1688, "wrap 1 at offset 1,688 of the same blob");
        uint256 nw = _map(bytes32(0), _map(PqChatTypes.scopeSession(s.creator), r + 4));
        assertEq(_at(nw), 1 << 5, "nonce 5");
    }
}
