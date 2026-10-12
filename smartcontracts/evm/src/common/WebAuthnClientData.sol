// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";

/// @title The strict clientDataJSON grammar shared by `SmartKeyAccount` (CTR-ACC-08) and the UA `webauthn-p256`
///        verifier (accounts.md §1.9).
library WebAuthnClientData {
    /// @dev The bounded WebAuthn L3 §5.8.1.2 check: the fixed prefix with type and challenge, the origin up to the
    ///      next `"`, then exactly one of: `}` as the last character (Safari, L2), or `,"crossOrigin":false` followed
    ///      by `}` or `,` (Chrome, Firefox, L3). Everything else (`crossOrigin:true`, a member before crossOrigin,
    ///      whitespace) fails closed. The origin is returned as `cd[originStart .. originStart + originLen)` and not
    ///      judged here: the account compares its hash, the UA verifier accepts any origin.
    function parse(bytes memory cd, bytes32 challenge)
        internal
        pure
        returns (bool ok, uint256 originStart, uint256 originLen)
    {
        bytes memory prefix = abi.encodePacked(
            '{"type":"webauthn.get","challenge":"', Base64.encodeURL(abi.encodePacked(challenge)), '","origin":"'
        );
        uint256 p = prefix.length;
        uint256 n = cd.length;
        if (n < p + 2 || hashSlice(cd, 0, p) != keccak256(prefix)) return (false, 0, 0);
        uint256 end = p;
        while (end < n && cd[end] != '"') ++end;
        if (end + 1 >= n) return (false, 0, 0);
        (originStart, originLen) = (p, end - p);
        if (cd[end + 1] == "}") return (end + 2 == n, originStart, originLen);
        bytes memory crossFalse = ',"crossOrigin":false';
        uint256 after_ = end + 1 + crossFalse.length;
        if (after_ >= n || hashSlice(cd, end + 1, crossFalse.length) != keccak256(crossFalse)) return (false, 0, 0);
        if (cd[after_] == "}") return (after_ + 1 == n, originStart, originLen);
        return (cd[after_] == ",", originStart, originLen);
    }

    /// @dev `keccak256(b[start .. start + len))`; the caller keeps the range inside `b`.
    function hashSlice(bytes memory b, uint256 start, uint256 len) internal pure returns (bytes32 h) {
        assembly ("memory-safe") {
            h := keccak256(add(add(b, 32), start), len)
        }
    }
}
