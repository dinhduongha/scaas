// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

/// @title Negacyclic NTT over Z_q[X]/(X^n + 1) on memory polynomials (one coefficient per 32-byte word).
/// @notice `ntt` / `intt` are FIPS 204 Algorithms 41 / 42 for any n, q with `zetas[k] = root^brv(k)`, root a
///         primitive 2n-th root of unity, brv over log2 n bits (ML-DSA: n = 256, q = 8380417, root 1753; Falcon:
///         n = 512, q = 12289, root 10302 = 11^12); the callers keep the tables as constants (`test/ua/PqVerifiers.t.sol`
///         recomputes them). Inputs must be reduced (< q).
library PqNtt {
    /// A new polynomial of `n` zero coefficients (memory pointer to its first word).
    function alloc(uint256 n) internal pure returns (uint256 p) {
        assembly ("memory-safe") {
            p := mload(0x40)
            mstore(0x40, add(p, shl(5, n)))
            calldatacopy(p, calldatasize(), shl(5, n)) // zero fill
        }
    }

    /// The zeta table `zetas[k] = root^brv(k)` from its packed big-endian form (`width` bytes per entry), one word each.
    function table(bytes memory packed, uint256 width) internal pure returns (uint256 z) {
        uint256 n = packed.length / width;
        z = alloc(n);
        assembly ("memory-safe") {
            let sh := sub(256, shl(3, width))
            let src := add(packed, 32)
            for { let i := 0 } lt(i, n) { i := add(i, 1) } {
                mstore(add(z, shl(5, i)), shr(sh, mload(add(src, mul(i, width)))))
            }
        }
    }

    /// Forward NTT with lazy reduction: outputs are congruent mod q but only bounded by (1 + log2 n)·q. Every consumer
    /// reduces (mulmod / addmod / `reduce`).
    function ntt(uint256 a, uint256 n, uint256 q, uint256 z) internal pure {
        assembly ("memory-safe") {
            let k := 0
            for { let len := shr(1, n) } gt(len, 0) { len := shr(1, len) } {
                let off := shl(5, len)
                for { let start := 0 } lt(start, n) { start := add(start, shl(1, len)) } {
                    k := add(k, 1)
                    let zeta := mload(add(z, shl(5, k)))
                    let e := add(a, shl(5, add(start, len)))
                    for { let p := add(a, shl(5, start)) } lt(p, e) { p := add(p, 32) } {
                        let t := mulmod(zeta, mload(add(p, off)), q)
                        let x := mload(p)
                        mstore(add(p, off), add(x, sub(q, t)))
                        mstore(p, add(x, t))
                    }
                }
            }
        }
    }

    /// Inverse NTT (any input below 2^200); outputs reduced (< q).
    function intt(uint256 a, uint256 n, uint256 q, uint256 z) internal pure {
        assembly ("memory-safe") {
            let big := shl(220, q) // above every intermediate, keeps t − u + big positive
            let k := n
            for { let len := 1 } lt(len, n) { len := shl(1, len) } {
                let off := shl(5, len)
                for { let start := 0 } lt(start, n) { start := add(start, shl(1, len)) } {
                    k := sub(k, 1)
                    let zeta := sub(q, mload(add(z, shl(5, k))))
                    let e := add(a, shl(5, add(start, len)))
                    for { let p := add(a, shl(5, start)) } lt(p, e) { p := add(p, 32) } {
                        let t := mload(p)
                        let u := mload(add(p, off))
                        mstore(p, add(t, u))
                        mstore(add(p, off), mulmod(zeta, add(t, sub(big, u)), q))
                    }
                }
            }
            // n^-1 mod q (q prime): n^(q-2) by square-and-multiply
            let f := 1
            let b := n
            for { let x := sub(q, 2) } gt(x, 0) { x := shr(1, x) } {
                if and(x, 1) { f := mulmod(f, b, q) }
                b := mulmod(b, b, q)
            }
            let e := add(a, shl(5, n))
            for { let p := a } lt(p, e) { p := add(p, 32) } { mstore(p, mulmod(mload(p), f, q)) }
        }
    }

    /// a[i] mod q, in place.
    function reduce(uint256 a, uint256 n, uint256 q) internal pure {
        assembly ("memory-safe") {
            let e := add(a, shl(5, n))
            for { let p := a } lt(p, e) { p := add(p, 32) } { mstore(p, mod(mload(p), q)) }
        }
    }

    /// c[i] = a[i] · b[i] mod q (pointwise, in place into `a`).
    function mulPoint(uint256 a, uint256 b, uint256 n, uint256 q) internal pure {
        assembly ("memory-safe") {
            for { let i := 0 } lt(i, shl(5, n)) { i := add(i, 32) } {
                mstore(add(a, i), mulmod(mload(add(a, i)), mload(add(b, i)), q))
            }
        }
    }
}
