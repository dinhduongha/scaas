// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUAPopVerifier} from "../IUAVerifier.sol";
import {P256Precompile} from "./P256Precompile.sol";

/// @title UA verifier for `p256` (0x0101, accounts.md §1.9).
/// @notice keyData = `x ‖ y` (64), sig = `r ‖ s` (64), low-s ECDSA-P256 over `sha256(ua_msg)`
///         (`P256Precompile`: P256VERIFY when probed, else the OpenZeppelin Solidity verifier).
contract P256Verifier is IUAPopVerifier, P256Precompile {
    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) public view returns (bool) {
        if (keyData.length != 64 || sig.length != 64) return false;
        return _p256Verify(
            sha256(abi.encodePacked(message)),
            bytes32(sig[0:32]),
            bytes32(sig[32:64]),
            bytes32(keyData[0:32]),
            bytes32(keyData[32:64])
        );
    }

    function verifyPop(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool) {
        return verify(keyData, message, sig);
    }
}
