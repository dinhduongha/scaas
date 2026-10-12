// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title BIP-340 verify on the EVM (accounts.md §1.9 `bip340` / `musig2-secp256k1` row), shared by `Bip340Verifier`
///        and `Musig2Secp256k1Verifier`.
/// @notice `e = int(sha256(T ‖ T ‖ r ‖ P ‖ m)) mod n` with `T = sha256("BIP0340/challenge")`, accept iff
///         `R = s·G − e·P` is not infinity, has even y and `x(R) == r`. EVM: `ecrecover(−s·P_x, 27, P_x, −e·P_x)`
///         returns `address(P_x⁻¹·(−e·P_x·P + s·P_x·G)) = address(R)` (v = 27 selects P's even-y lift); the expected
///         `R` is `r` lifted to even y with one MODEXP (`p ≡ 3 mod 4`). Off-curve `P` or `r`, `P ≥ p`, `r ≥ p`, `s ≥ n`
///         and a wrong signature length return false. Not covered (probability ~2⁻¹²⁸ each, fail closed): `P_x ≥ n`
///         (ecrecover refuses r ≥ n) and `e == 0`. **UNAUDITED — NOT FOR PRODUCTION FUNDS.**
library Bip340 {
    uint256 internal constant P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 internal constant N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    /// sha256("BIP0340/challenge"), pinned by the tests.
    bytes32 internal constant CHALLENGE_TAG = 0x7bb52d7a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48d37c;

    /// BIP-340 verify of the 32-byte `message` under the x-only key `px`.
    function verify(uint256 px, bytes32 message, bytes calldata sig) internal view returns (bool) {
        if (sig.length != 64) return false;
        uint256 rx = uint256(bytes32(sig[0:32]));
        uint256 s = uint256(bytes32(sig[32:64]));
        if (px >= P || rx >= P || s >= N) return false;
        uint256 e = uint256(sha256(abi.encodePacked(CHALLENGE_TAG, CHALLENGE_TAG, rx, px, message))) % N;
        address got = ecrecover(bytes32(mulmod(N - s, px, N)), 27, bytes32(px), bytes32(mulmod(N - e, px, N)));
        if (got == address(0)) return false;
        (bool ok, uint256 ry) = liftX(rx);
        return ok && got == address(uint160(uint256(keccak256(abi.encodePacked(rx, ry)))));
    }

    /// The even-y point with x-coordinate `x < p`; `ok` false if `x³ + 7` is not a square (or MODEXP failed).
    function liftX(uint256 x) internal view returns (bool ok, uint256 y) {
        uint256 rhs = addmod(mulmod(mulmod(x, x, P), x, P), 7, P);
        (ok, y) = _sqrtCandidate(rhs);
        if (!ok || mulmod(y, y, P) != rhs) return (false, 0);
        if (y & 1 == 1) y = P - y;
    }

    /// `a^((p+1)/4) mod p` via MODEXP (0x05); false if the call fails (out of gas), never reverts.
    function _sqrtCandidate(uint256 a) private view returns (bool ok, uint256 r) {
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, 32)
            mstore(add(m, 0x20), 32)
            mstore(add(m, 0x40), 32)
            mstore(add(m, 0x60), a)
            mstore(add(m, 0x80), 0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c) // (p + 1) / 4
            mstore(add(m, 0xa0), P)
            let success := staticcall(gas(), 0x05, m, 0xc0, m, 0x20)
            ok := and(success, eq(returndatasize(), 0x20))
            r := mload(m)
        }
    }
}
