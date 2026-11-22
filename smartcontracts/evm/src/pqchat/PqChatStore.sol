// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IPqChatStore} from "./IPqChatStore.sol";
import {SSTORE2} from "../common/SSTORE2.sol";

/// @title `PqChatStore` (CTR-CHAT-22): the store part of `PqChat` alone, for chains whose code-size limit is 24,576 B.
/// @notice CTR-CHAT-13's behaviour: anyone stores, unsigned; each payload `abi.encode(v, hint, env)` is one SSTORE2 blob in
///         state (CTR-CHAT-05), appended to the list of its hint. No constructor argument, owner, admin, pause, upgrade,
///         registry, `chainUid` or fee; no `msg.sender` read. State in the ERC-7201 namespace `scaas.pqchatstore`.
///         **UNAUDITED.**
contract PqChatStore is IPqChatStore {
    /// @notice The largest `storedRange` page, as `IPqChat.STORED_RANGE_MAX`.
    uint256 public constant STORED_RANGE_MAX = 16;
    /// @dev The largest blob, its leading STOP included: EIP-170's 24,576 B, a constant, not a chain value (so `env` is at
    ///      most 24,416 B).
    uint256 internal constant BLOB_MAX = 24_576;

    /// @custom:storage-location erc7201:scaas.pqchatstore
    struct S {
        mapping(bytes8 => address[]) stored;
    }

    /// @dev `keccak256(abi.encode(uint256(keccak256("scaas.pqchatstore")) - 1)) & ~bytes32(uint256(0xff))`.
    bytes32 internal constant SLOT = 0x7630d0958f4274daf6d8adae2ad04ff897d6b0652b48853655813d9a20374b00;

    function _s() internal pure returns (S storage s) {
        assembly ("memory-safe") {
            s.slot := SLOT
        }
    }

    function supportsInterface(bytes4 id) external pure returns (bool) {
        return id == 0x01ffc9a7 || id == type(IPqChatStore).interfaceId;
    }

    /// @inheritdoc IPqChatStore
    function storeMessage(uint8 v, bytes8 hint, bytes calldata env) external returns (uint256 index) {
        bytes memory payload = abi.encode(v, hint, env);
        if (v != 1 || payload.length + 1 > BLOB_MAX) revert PqChatShape();
        address[] storage list = _s().stored[hint];
        index = list.length;
        list.push(SSTORE2.write(payload));
        emit PqChatStored(hint, index);
    }

    function storedCount(bytes8 hint) external view returns (uint256) {
        return _s().stored[hint].length;
    }

    function storedAt(bytes8 hint, uint256 index) external view returns (bytes memory) {
        return SSTORE2.read(_s().stored[hint][index]);
    }

    function storedRange(bytes8 hint, uint256 offset, uint256 limit) external view returns (bytes[] memory page) {
        address[] storage l = _s().stored[hint];
        uint256 n = l.length;
        if (offset >= n) return page;
        if (limit > STORED_RANGE_MAX) limit = STORED_RANGE_MAX;
        uint256 end = n - offset > limit ? offset + limit : n;
        page = new bytes[](end - offset);
        for (uint256 i; i < page.length; ++i) {
            page[i] = SSTORE2.read(l[offset + i]);
        }
    }
}
