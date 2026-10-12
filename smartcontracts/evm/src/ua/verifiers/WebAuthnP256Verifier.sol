// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {WebAuthnClientData} from "../../common/WebAuthnClientData.sol";
import {IUAPopVerifier} from "../IUAVerifier.sol";
import {P256Precompile} from "./P256Precompile.sol";

/// @title UA verifier for `webauthn-p256` (0x0100, accounts.md §1.9).
/// @notice keyData = `x ‖ y ‖ rpIdHash` (96); sig = `abi.encode(bytes authenticatorData, string clientDataJSON,
///         uint256 r, uint256 s)` (the `SmartKeyAccount` encoding). Checks: authenticatorData[0:32] == rpIdHash, flags
///         UP and UV, the strict clientDataJSON grammar with challenge = base64url(`ua_msg`) and any origin, then low-s
///         P-256 over `sha256(authenticatorData ‖ sha256(clientDataJSON))` (`P256Precompile`). The
///         ABI blob is decoded by hand with bounds checks: a malformed blob returns false, never reverts.
contract WebAuthnP256Verifier is IUAPopVerifier, P256Precompile {
    uint8 private constant _FLAG_UP = 0x01;
    uint8 private constant _FLAG_UV = 0x04;

    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) public view returns (bool) {
        if (keyData.length != 96 || sig.length < 128) return false;
        (bool ok, bytes32 h) = _signedHash(bytes32(keyData[64:96]), message, sig);
        if (!ok) return false;
        return
            _p256Verify(h, bytes32(sig[64:96]), bytes32(sig[96:128]), bytes32(keyData[0:32]), bytes32(keyData[32:64]));
    }

    function verifyPop(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool) {
        return verify(keyData, message, sig);
    }

    /// Checks authenticatorData and clientDataJSON; returns `sha256(authenticatorData ‖ sha256(clientDataJSON))`.
    function _signedHash(bytes32 rpIdHash, bytes32 message, bytes calldata sig) private pure returns (bool, bytes32) {
        (bool okA, bytes calldata authData) = _bytesAt(sig, 0);
        (bool okC, bytes calldata clientData) = _bytesAt(sig, 32);
        if (!okA || !okC || authData.length < 37 || bytes32(authData[0:32]) != rpIdHash) return (false, 0);
        if (uint8(authData[32]) & (_FLAG_UP | _FLAG_UV) != (_FLAG_UP | _FLAG_UV)) return (false, 0);
        (bool okJ,,) = WebAuthnClientData.parse(clientData, message);
        if (!okJ) return (false, 0);
        return (true, sha256(abi.encodePacked(authData, sha256(clientData))));
    }

    /// The dynamic `bytes` whose ABI offset is the head word at `head`; false when offset or length leave `b`.
    function _bytesAt(bytes calldata b, uint256 head) private pure returns (bool, bytes calldata) {
        uint256 off = uint256(bytes32(b[head:head + 32]));
        if (off > b.length || b.length - off < 32) return (false, b[0:0]);
        uint256 len = uint256(bytes32(b[off:off + 32]));
        if (len > b.length - off - 32) return (false, b[0:0]);
        return (true, b[off + 32:off + 32 + len]);
    }
}
