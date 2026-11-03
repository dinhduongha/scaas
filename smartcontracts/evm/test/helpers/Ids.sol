// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @notice A native account's UA id (CTR-GOV-01 Change, owner 2026-11-04): its address, zero-padded to 32 bytes. Written
///         out here, not read from `MetaTxLib.pad`, so a test of the governed contracts does not share their helper.
function nid(address a) pure returns (bytes32) {
    return bytes32(uint256(uint160(a)));
}
