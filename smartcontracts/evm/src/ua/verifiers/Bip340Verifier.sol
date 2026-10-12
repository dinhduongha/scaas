// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUAPopVerifier} from "../IUAVerifier.sol";
import {Bip340} from "./Bip340.sol";

/// @title UA verifier for `bip340` (0x0103, accounts.md §1.9).
/// @notice keyData = x-only `P` (32), sig = `r ‖ s` (64), BIP-340 verify of the 32-byte `ua_msg` (`Bip340.verify`:
///         the `ecrecover` trick, `R` lifted with one MODEXP). Off-curve `P` or `r`, `P ≥ p`, `r ≥ p`, `s ≥ n` and
///         wrong lengths return false.
contract Bip340Verifier is IUAPopVerifier {
    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) public view returns (bool) {
        return keyData.length == 32 && Bip340.verify(uint256(bytes32(keyData)), message, sig);
    }

    function verifyPop(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool) {
        return verify(keyData, message, sig);
    }
}
