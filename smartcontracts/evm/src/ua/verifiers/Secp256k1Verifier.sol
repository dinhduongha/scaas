// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUAPopVerifier} from "../IUAVerifier.sol";

/// @title UA verifier for `secp256k1` (0x0108, accounts.md §1.9): ECDSA on secp256k1 as a derived kind, so a secp256k1
///        key has the same UA id on every chain (owner 2026-10-17; its native EVM address stays a separate id).
/// @notice keyData = `x ‖ y` (64, validated on curve at registration), sig = `r ‖ s ‖ v` (65), ECDSA over the 32-byte
///         `ua_msg` as the message hash (no prehash, no EIP-191 prefix): `ecrecover` must return
///         `address(keccak256(x ‖ y))`. Low-s only (`s ≤ n/2`), `v ∈ {27, 28}`, `r, s ≠ 0`; anything else returns false.
contract Secp256k1Verifier is IUAPopVerifier {
    uint256 private constant HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) public view returns (bool) {
        if (keyData.length != 64 || sig.length != 65) return false;
        bytes32 r = bytes32(sig[0:32]);
        bytes32 s = bytes32(sig[32:64]);
        uint8 v = uint8(sig[64]);
        if (r == 0 || s == 0 || uint256(s) > HALF_N || (v != 27 && v != 28)) return false;
        address signer = ecrecover(message, v, r, s);
        return signer != address(0) && signer == address(uint160(uint256(keccak256(keyData))));
    }

    function verifyPop(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool) {
        return verify(keyData, message, sig);
    }
}
