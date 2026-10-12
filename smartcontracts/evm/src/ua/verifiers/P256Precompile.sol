// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {P256} from "@openzeppelin/contracts/utils/cryptography/P256.sol";

/// @title Low-s ECDSA-P256 through P256VERIFY (0x100, EIP-7951) when the constructor's probe proves it, else the
///        OpenZeppelin Solidity verifier.
/// @notice The probe asks 0x100 one fixed valid vector (key = G, `h = sha256("scaas.ua.p256.probe")`) and the same
///         vector with `h` flipped: present iff exactly the 32-byte word 1, then anything but 1. An empty account, a
///         contract answering 1 to everything or another precompile fails the probe and the verifier stays on the
///         Solidity path. With the precompile an invalid signature costs one precompile call, not the Solidity
///         verifier (OZ `P256.verify` reads the precompile's empty "invalid" answer as "absent" and falls back).
abstract contract P256Precompile {
    uint256 private constant _HALF_N = P256.N / 2;
    /// sha256("scaas.ua.p256.probe") and its low-s signature under the private key 1 (forge `vm.signP256`).
    bytes32 internal constant PROBE_H = 0x8708b9c1b15ea4b9eceaf938fc2b0ac2f8643b92d02c9c9d202a540a97c0f1e9;
    bytes32 internal constant PROBE_R = 0xb73892af0c08dbba796b57346b43b924c690fa3c5e70a70904ce3285b2f4ca89;
    bytes32 internal constant PROBE_S = 0x6da50c09d4911f559acd8c1bfbdb1e82b16a9ed0f53ed7f9ed3e56e1d793bef1;

    /// True iff this chain's 0x100 passed the constructor probe.
    bool public immutable PRECOMPILE;

    constructor() {
        bytes32 gx = bytes32(P256.GX);
        bytes32 gy = bytes32(P256.GY);
        PRECOMPILE =
            _call(PROBE_H, PROBE_R, PROBE_S, gx, gy) && !_call(PROBE_H ^ bytes32(uint256(1)), PROBE_R, PROBE_S, gx, gy);
    }

    function _p256Verify(bytes32 h, bytes32 r, bytes32 s, bytes32 x, bytes32 y) internal view returns (bool) {
        if (!PRECOMPILE) return P256.verifySolidity(h, r, s, x, y);
        if (uint256(r) == 0 || uint256(r) >= P256.N || uint256(s) == 0 || uint256(s) > _HALF_N) return false;
        if (!P256.isValidPublicKey(x, y)) return false;
        return _call(h, r, s, x, y);
    }

    /// One P256VERIFY call: true only on success with exactly 32 bytes equal to 1.
    function _call(bytes32 h, bytes32 r, bytes32 s, bytes32 x, bytes32 y) private view returns (bool ok) {
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, h)
            mstore(add(m, 0x20), r)
            mstore(add(m, 0x40), s)
            mstore(add(m, 0x60), x)
            mstore(add(m, 0x80), y)
            mstore(0, 0)
            let success := staticcall(gas(), 0x100, m, 0xa0, 0, 0x20)
            ok := and(and(success, eq(returndatasize(), 0x20)), eq(mload(0), 1))
        }
    }
}
