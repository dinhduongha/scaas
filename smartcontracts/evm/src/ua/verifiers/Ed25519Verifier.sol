// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {IUAPopVerifier} from "../IUAVerifier.sol";
import {Ed25519} from "../../common/Ed25519.sol";

/// @title UA verifier for `ed25519` (0x0102, accounts.md §1.9).
/// @notice keyData = `A` (32), sig = `R ‖ S` (64), RFC 8032 strict verify (ed25519-dalek `verify_strict`: canonical
///         `S`, canonical and not small-order `A` and `R`, cofactorless equation) of the 32-byte `ua_msg` as the
///         message, no prehash. `verifyPop == verify`. Wrong lengths and every malformed encoding return false.
contract Ed25519Verifier is IUAPopVerifier {
    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) public view returns (bool) {
        return verifyRaw(keyData, abi.encodePacked(message), sig);
    }

    function verifyPop(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool) {
        return verify(keyData, message, sig);
    }

    /// The same check over a message of any length (RFC 8032 §7.1 vectors; not used by the registry).
    function verifyRaw(bytes calldata keyData, bytes memory message, bytes calldata sig) public view returns (bool) {
        if (keyData.length != 32 || sig.length != 64) return false;
        return Ed25519.verify(bytes32(keyData), message, bytes32(sig[0:32]), bytes32(sig[32:64]));
    }
}
