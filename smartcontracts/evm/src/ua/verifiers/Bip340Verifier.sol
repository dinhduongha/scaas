// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {IUAPopVerifier} from "../IUAVerifier.sol";

/// @title UA verifier for `bip340` (0x0103, accounts.md §1.9).
/// @notice keyData = x-only `P` (32), sig = `r ‖ s` (64), BIP-340 verify of the 32-byte `ua_msg`:
///         `e = int(sha256(T ‖ T ‖ r ‖ P ‖ m)) mod n` with `T = sha256("BIP0340/challenge")`, accept iff
///         `R = s·G − e·P` is not infinity, has even y and `x(R) == r`. EVM: `ecrecover(−s·P_x, 27, P_x, −e·P_x)`
///         returns `address(P_x⁻¹·(−e·P_x·P + s·P_x·G)) = address(R)` (v = 27 selects P's even-y lift); the expected
///         `R` is `r` lifted to even y with one MODEXP (`p ≡ 3 mod 4`). Off-curve `P` or `r`, `P ≥ p`, `r ≥ p`, `s ≥ n`
///         and wrong lengths return false. Not covered (probability ~2⁻¹²⁸ each, fail closed): `P_x ≥ n`
///         (ecrecover refuses r ≥ n) and `e == 0`.
contract Bip340Verifier is IUAPopVerifier {
    uint256 private constant _P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F;
    uint256 private constant _N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    /// sha256("BIP0340/challenge"), pinned by the tests.
    bytes32 internal constant CHALLENGE_TAG = 0x7bb52d7a9fef58323eb1bf7a407db382d2f3f2d81bb1224f49fe518f6d48d37c;

    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) public view returns (bool) {
        if (keyData.length != 32 || sig.length != 64) return false;
        uint256 px = uint256(bytes32(keyData));
        uint256 rx = uint256(bytes32(sig[0:32]));
        uint256 s = uint256(bytes32(sig[32:64]));
        if (px >= _P || rx >= _P || s >= _N) return false;
        uint256 e = uint256(sha256(abi.encodePacked(CHALLENGE_TAG, CHALLENGE_TAG, rx, px, message))) % _N;
        address got = ecrecover(bytes32(mulmod(_N - s, px, _N)), 27, bytes32(px), bytes32(mulmod(_N - e, px, _N)));
        if (got == address(0)) return false;
        uint256 rhs = addmod(mulmod(mulmod(rx, rx, _P), rx, _P), 7, _P);
        (bool ok, uint256 ry) = _sqrtCandidate(rhs);
        if (!ok || mulmod(ry, ry, _P) != rhs) return false;
        if (ry & 1 == 1) ry = _P - ry;
        return got == address(uint160(uint256(keccak256(abi.encodePacked(rx, ry)))));
    }

    function verifyPop(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool) {
        return verify(keyData, message, sig);
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
            mstore(add(m, 0xa0), _P)
            ok := and(staticcall(gas(), 0x05, m, 0xc0, m, 0x20), eq(returndatasize(), 0x20))
            r := mload(m)
        }
    }
}
