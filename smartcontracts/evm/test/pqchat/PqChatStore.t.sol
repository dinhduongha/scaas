// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {stdError} from "forge-std/StdError.sol";
import {IPqChat} from "../../src/pqchat/IPqChat.sol";
import {IPqChatStore} from "../../src/pqchat/IPqChatStore.sol";

/// A contract that reads `msg.sender`: the positive control of the CALLER scan.
contract ReadsSender {
    function who() external view returns (address) {
        return msg.sender;
    }
}

/// CTR-CHAT-22 (plan T5; spec 2026-11-21-avax-polkadot-arweave §5.3): `PqChatStore`, the store part of `PqChat` alone,
/// with CTR-CHAT-13's behaviour. The store is deployed from its compiled artifact with no constructor argument, and every
/// case is one call with fixed inputs, so a run on another fork can replay it as (calldata, expected) pairs.
contract PqChatStoreTest is Test {
    using stdJson for string;

    bytes8 internal constant H = 0x0102030405060708;
    bytes8 internal constant H2 = 0x1112131415161718;
    /// The largest `env`: `abi.encode(v, hint, env)` is 128 B + `env` padded to 32 B; with the leading STOP at most 24,576 B.
    uint256 internal constant ENV_MAX = 24_416;

    IPqChatStore internal store;

    function setUp() public {
        store = IPqChatStore(deployCode("PqChatStore.sol:PqChatStore"));
    }

    function _payload(uint8 v, bytes8 hint, bytes memory env) internal pure returns (bytes memory) {
        return abi.encode(v, hint, env);
    }

    /// C23 (review P3-7): the build is the release data's: the init code and the runtime hash to the pinned values, and the
    /// address is the deterministic deployer's CREATE2 of that init code at salt 0, so a change that moves the bytes fails
    /// here, not at a deploy (`CHATSTORE_INIT_HASH`) or in the node (`CHATSTORE_CODE_HASH`).
    function test_releaseDataPinsTheBuild() public view {
        string memory r = vm.readFile("./release-data/PqChatStore.json");
        bytes32 init = keccak256(vm.getCode("PqChatStore.sol:PqChatStore"));
        assertEq(init, r.readBytes32(".initCodeHash"), "init code hash");
        assertEq(
            keccak256(vm.getDeployedCode("PqChatStore.sol:PqChatStore")), r.readBytes32(".runtimeCodeHash"), "runtime"
        );
        address deployer = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
        assertEq(vm.computeCreate2Address(bytes32(0), init, deployer), r.readAddress(".address"), "CREATE2 address");
        assertEq(address(store).codehash, r.readBytes32(".runtimeCodeHash"), "deployed code");
    }

    // ------------------------------------------------------------------ CTR-CHAT-13's behaviour

    function test_storeMessage_appendsAndEmits() public {
        vm.expectEmit(true, false, false, true, address(store));
        emit IPqChatStore.PqChatStored(H, 0);
        assertEq(store.storeMessage(1, H, hex"abcdef"), 0);
        vm.expectEmit(true, false, false, true, address(store));
        emit IPqChatStore.PqChatStored(H, 1);
        assertEq(store.storeMessage(1, H, hex""), 1);
        assertEq(store.storedCount(H), 2);
        assertEq(store.storedAt(H, 0), _payload(1, H, hex"abcdef"));
        assertEq(store.storedAt(H, 1), _payload(1, H, hex""));
    }

    function test_listsArePerHint() public {
        store.storeMessage(1, H, hex"01");
        store.storeMessage(1, H2, hex"02");
        store.storeMessage(1, H, hex"03");
        assertEq(store.storedCount(H), 2);
        assertEq(store.storedCount(H2), 1);
        assertEq(store.storedCount(bytes8(0)), 0);
        assertEq(store.storedAt(H, 1), _payload(1, H, hex"03"));
        assertEq(store.storedAt(H2, 0), _payload(1, H2, hex"02"));
    }

    function test_storedAt_pastTheEndReverts() public {
        store.storeMessage(1, H, hex"01");
        vm.expectRevert(stdError.indexOOBError);
        store.storedAt(H, 1);
    }

    function test_storedRange_clampsTo16() public {
        for (uint256 i; i < 18; ++i) {
            store.storeMessage(1, H, abi.encode(i));
        }
        assertEq(PqChatStoreView(address(store)).STORED_RANGE_MAX(), 16);
        bytes[] memory page = store.storedRange(H, 0, 100);
        assertEq(page.length, 16, "clamped to 16");
        for (uint256 i; i < 16; ++i) {
            assertEq(page[i], _payload(1, H, abi.encode(i)));
        }
        page = store.storedRange(H, 1, type(uint256).max);
        assertEq(page.length, 16, "clamped to 16 from offset 1");
        assertEq(page[15], _payload(1, H, abi.encode(uint256(16))));
        page = store.storedRange(H, 16, 100);
        assertEq(page.length, 2, "the tail");
        assertEq(page[1], _payload(1, H, abi.encode(uint256(17))));
        page = store.storedRange(H, 2, 3);
        assertEq(page.length, 3, "a limit below 16 kept");
        assertEq(page[0], _payload(1, H, abi.encode(uint256(2))));
        assertEq(page[2], _payload(1, H, abi.encode(uint256(4))));
    }

    function test_storedRange_offsetPastTheEndIsEmpty() public {
        store.storeMessage(1, H, hex"01");
        store.storeMessage(1, H, hex"02");
        assertEq(store.storedRange(H, 1, 16).length, 1, "control: offset 1 of 2");
        assertEq(store.storedRange(H, 2, 16).length, 0);
        assertEq(store.storedRange(H, 3, 16).length, 0);
        assertEq(store.storedRange(H, type(uint256).max, type(uint256).max).length, 0);
        assertEq(store.storedRange(H2, 0, 16).length, 0, "an unknown hint");
        assertEq(store.storedRange(H, 0, 0).length, 0, "limit 0");
    }

    // ------------------------------------------------------------------ PqChatShape: v and the blob bound

    function test_v1Accepted() public {
        assertEq(store.storeMessage(1, H, hex"01"), 0);
        assertEq(store.storedCount(H), 1);
    }

    function test_vNot1Refused() public {
        vm.expectRevert(IPqChatStore.PqChatShape.selector);
        store.storeMessage(2, H, hex"01");
        vm.expectRevert(IPqChatStore.PqChatShape.selector);
        store.storeMessage(0, H, hex"01");
        vm.expectRevert(IPqChatStore.PqChatShape.selector);
        store.storeMessage(255, H, hex"01");
        assertEq(store.storedCount(H), 0);
    }

    function test_env24416Accepted() public {
        bytes memory env = new bytes(ENV_MAX);
        env[0] = 0x5a;
        env[ENV_MAX - 1] = 0xa5;
        assertEq(store.storeMessage(1, H, env), 0);
        bytes memory p = store.storedAt(H, 0);
        assertEq(p.length + 1, 24_545, "the blob: STOP + 128 + 24,416 (24,417 pads to 24,448: a 24,577-B blob)");
        assertEq(p, _payload(1, H, env));
    }

    function test_env24417Refused() public {
        vm.expectRevert(IPqChatStore.PqChatShape.selector);
        store.storeMessage(1, H, new bytes(ENV_MAX + 1));
        assertEq(store.storedCount(H), 0);
    }

    // ------------------------------------------------------------------ the ABI equals IPqChat's

    function test_abiEqualsIPqChat() public pure {
        assertEq(IPqChatStore.storeMessage.selector, IPqChat.storeMessage.selector);
        assertEq(IPqChatStore.storedCount.selector, IPqChat.storedCount.selector);
        assertEq(IPqChatStore.storedAt.selector, IPqChat.storedAt.selector);
        assertEq(IPqChatStore.storedRange.selector, IPqChat.storedRange.selector);
        assertEq(PqChatStoreView.STORED_RANGE_MAX.selector, IPqChat.STORED_RANGE_MAX.selector);
        assertEq(IPqChatStore.PqChatStored.selector, IPqChat.PqChatStored.selector);
        assertEq(IPqChatStore.PqChatShape.selector, IPqChat.PqChatShape.selector);
    }

    function test_erc165() public view {
        PqChatStoreView s = PqChatStoreView(address(store));
        bytes4 id = type(IPqChatStore).interfaceId;
        assertEq(
            id,
            IPqChat.storeMessage.selector ^ IPqChat.storedCount.selector ^ IPqChat.storedAt.selector
                ^ IPqChat.storedRange.selector
        );
        assertTrue(s.supportsInterface(0x01ffc9a7), "ERC-165");
        assertTrue(s.supportsInterface(id), "IPqChatStore");
        assertFalse(s.supportsInterface(0xffffffff));
        assertFalse(s.supportsInterface(type(IPqChat).interfaceId));
    }

    // ------------------------------------------------------------------ nothing else

    function test_noConstructorArgument() public {
        bytes memory init = vm.getCode("PqChatStore.sol:PqChatStore");
        address a;
        assembly ("memory-safe") {
            a := create(0, add(init, 32), mload(init))
        }
        assertTrue(a != address(0), "the creation code alone deploys");
        assertEq(a.code, address(store).code);
        assertEq(IPqChatStore(a).storeMessage(1, H, hex"01"), 0);
    }

    function test_noSenderRead_twoSendersSameResult() public {
        vm.prank(address(0xA11CE));
        assertEq(store.storeMessage(1, H, hex"01"), 0);
        vm.prank(address(0xB0B));
        assertEq(store.storeMessage(1, H, hex"01"), 1);
        assertEq(store.storedAt(H, 0), store.storedAt(H, 1));
    }

    /// No CALLER (0x33) or ORIGIN (0x32) in code position: PUSH data skipped, the CBOR metadata trailer cut off.
    function test_noSenderRead_noCallerOpcode() public {
        assertTrue(_hasOp(address(new ReadsSender()).code, 0x33), "control: a sender read is found");
        assertFalse(_hasOp(address(store).code, 0x33), "CALLER");
        assertFalse(_hasOp(address(store).code, 0x32), "ORIGIN");
    }

    function _hasOp(bytes memory c, uint8 op) internal pure returns (bool) {
        uint256 end = c.length;
        if (end >= 2) {
            uint256 m = uint16(uint8(c[end - 2])) << 8 | uint8(c[end - 1]);
            if (m + 2 <= end && uint8(c[end - 2 - m]) & 0xf0 == 0xa0) end -= m + 2;
        }
        for (uint256 i; i < end; ++i) {
            uint8 b = uint8(c[i]);
            if (b == op) return true;
            if (b >= 0x60 && b <= 0x7f) i += b - 0x5f;
        }
        return false;
    }

    function test_runtimeFitsEip170() public view {
        assertLe(address(store).code.length, 24_576);
    }

    // ------------------------------------------------------------------ the layout

    function _root() internal pure returns (uint256) {
        return uint256(keccak256(abi.encode(uint256(keccak256("scaas.pqchatstore")) - 1))) & ~uint256(0xff);
    }

    /// The ERC-7201 namespace `scaas.pqchatstore` only (no plain slot: `test/v2/layout/PqChatStore.json` is empty).
    function test_storageLayoutIsPinned() public view {
        string memory art = vm.readFile(
            string.concat("./", vm.envOr("FOUNDRY_OUT", string("out")), "/PqChatStore.sol/PqChatStore.json")
        );
        string memory pin = vm.readFile("./test/v2/layout/PqChatStore.json");
        assertEq(pin.readStringArray(".labels").length, 0);
        assertFalse(vm.keyExistsJson(art, ".storageLayout.storage[0]"), "no plain slot");
        assertEq(_root(), 0x7630d0958f4274daf6d8adae2ad04ff897d6b0652b48853655813d9a20374b00);
    }

    /// The namespace's one field: `stored` (bytes8 => address[]) at +0.
    function test_namespaceFieldsArePinned() public {
        store.storeMessage(1, H, hex"01");
        store.storeMessage(1, H, hex"02");
        uint256 list = uint256(keccak256(abi.encode(H, _root())));
        assertEq(uint256(vm.load(address(store), bytes32(list))), 2, "stored[H].length");
        address blob = address(uint160(uint256(vm.load(address(store), keccak256(abi.encode(list))))));
        assertEq(blob.code, bytes.concat(hex"00", _payload(1, H, hex"01")), "stored[H][0]: STOP, then the payload");
    }
}

/// The getters of `PqChatStore` outside `IPqChatStore`.
interface PqChatStoreView {
    function STORED_RANGE_MAX() external view returns (uint256);
    function supportsInterface(bytes4 id) external view returns (bool);
}
