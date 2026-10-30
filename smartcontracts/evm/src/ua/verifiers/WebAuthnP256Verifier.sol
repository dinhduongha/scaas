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
///         ABI blob is accepted only in its canonical encoding (owner 2026-10-30, CTR-UA-33): byte-equal to
///         `abi.encode(authenticatorData, clientDataJSON, r, s)` — heads 0x80 and 0x80 + 32 + pad32(len(authenticatorData)),
///         each field its length word ‖ data ‖ zero padding, no trailing bytes — checked first, before any field or the
///         signature; so a `pop` (and its `popHash`) and an `msig` member slot have one byte string per signature. Every
///         other blob returns false, never reverts. Both entry points share it: `verifyPop` (register, and the portable
///         msig member records) and `verify` (`requireAuthorized`: tokens, msig member slots).
contract WebAuthnP256Verifier is IUAPopVerifier, P256Precompile {
    uint8 private constant _FLAG_UP = 0x01;
    uint8 private constant _FLAG_UV = 0x04;

    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) public view returns (bool) {
        if (keyData.length != 96) return false;
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
        (bool canonical, bytes calldata authData, bytes calldata clientData) = _fields(sig);
        if (!canonical || authData.length < 37 || bytes32(authData[0:32]) != rpIdHash) return (false, 0);
        if (uint8(authData[32]) & (_FLAG_UP | _FLAG_UV) != (_FLAG_UP | _FLAG_UV)) return (false, 0);
        (bool okJ,,) = WebAuthnClientData.parse(clientData, message);
        if (!okJ) return (false, 0);
        return (true, sha256(abi.encodePacked(authData, sha256(clientData))));
    }

    /// The two dynamic fields of `sig`, and whether `sig` is their canonical encoding with its `r`, `s` (owner
    /// 2026-10-30): the lengths are read at their canonical places (0x80, and 0xa0 + pad32(lenA)), the total length must
    /// be the canonical one, and `sig` must hash to the re-encoding (offsets, zero padding).
    function _fields(bytes calldata sig) private pure returns (bool ok, bytes calldata a, bytes calldata c) {
        (a, c) = (sig[0:0], sig[0:0]);
        uint256 n = sig.length;
        if (n < 0xc0) return (false, a, c);
        uint256 la = uint256(bytes32(sig[0x80:0xa0]));
        if (la > n) return (false, a, c);
        uint256 oc = 0xa0 + (la + 31) / 32 * 32; // the clientDataJSON length word
        if (oc + 32 > n) return (false, a, c);
        uint256 lc = uint256(bytes32(sig[oc:oc + 32]));
        if (lc > n || n != oc + 32 + (lc + 31) / 32 * 32) return (false, a, c);
        (a, c) = (sig[0xa0:0xa0 + la], sig[oc + 32:oc + 32 + lc]);
        ok = keccak256(sig) == keccak256(abi.encode(a, c, bytes32(sig[64:96]), bytes32(sig[96:128])));
    }
}
