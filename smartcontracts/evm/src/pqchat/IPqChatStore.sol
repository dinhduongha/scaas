// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title The store part of `IPqChat` alone (CTR-CHAT-22): the same selectors, event and error (CTR-CHAT-13), so a client
///        reads a `PqChatStore` with the code it reads a `PqChat` store with.
interface IPqChatStore {
    /// @notice The same event as `IPqChat.PqChatStored`.
    event PqChatStored(bytes8 indexed hint, uint256 index);

    /// @notice The same error as `IPqChat.PqChatShape`: `v != 1`, or the payload and its leading `STOP` above 24,576 B.
    error PqChatShape();

    /// @notice Anyone, unsigned: keeps `abi.encode(v, hint, env)` in one SSTORE2 blob, appended to the list of `hint`.
    function storeMessage(uint8 v, bytes8 hint, bytes calldata env) external returns (uint256 index);
    function storedCount(bytes8 hint) external view returns (uint256);
    /// @notice The stored bytes, `abi.encode(v, hint, env)`.
    function storedAt(bytes8 hint, uint256 index) external view returns (bytes memory);
    /// @notice The payloads `[offset, min(offset + min(limit, 16), count))` of `hint`; an offset past the end is an empty
    ///         page, never a revert.
    function storedRange(bytes8 hint, uint256 offset, uint256 limit) external view returns (bytes[] memory);
}
