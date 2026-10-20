// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title PQZ ciphertext arithmetic (pq-zero-knowledge.md §4.2, §8.1 "Objects"): `ct = u ‖ v`, 16,512 bytes = 2,064 coefficients
///        `< q`, each `be8`, coefficient 0 first; `pk` / `u` 16,384 B, `v` 128 B (16 coefficients).
/// @notice **UNAUDITED.** Pure Solidity, no precompile (pq-zero-knowledge.md §9.4). A 32-byte word holds four coefficients in
///         64-bit lanes (the first coefficient in the top lane). Sums run lane-wise without reduction — every input lane
///         is `< q < 2^42`, so up to 2^22 terms never carry into the next lane — and `reduce` takes one `mod q` per
///         lane at the end. `minus` adds `q − x` per lane (no borrow, `x < q`). Callers pass only canonical ciphertexts
///         (hash-matched to state, or checked with `isCanonical`).
library PqzCt {
    uint256 internal constant Q = 4_398_046_510_889; // 2^42 − 215
    uint256 internal constant DELTA = 67_108_863; // 2^26 − 1 = ⌊q / 2^16⌋
    uint256 internal constant PK = 16_384;
    uint256 internal constant V = 128;
    uint256 internal constant CT = 16_512;
    /// @notice `keccak256` of the zero ciphertext `Trivial(0)` (a new account's `acc`, P6g plan D10).
    bytes32 internal constant ZERO_HASH = 0xe21fb1ce17769d3b97b60b85064a46819cef2ccaede8163ddc683cf730e37e97;

    uint256 private constant Q4 = 0x000003ffffffff29000003ffffffff29000003ffffffff29000003ffffffff29; // q in each lane
    uint256 private constant M64 = 0xffffffffffffffff;

    /// @notice Every 8-byte coefficient `< q`; the length a multiple of 32 (every PQZ object is).
    function isCanonical(bytes calldata b) internal pure returns (bool ok) {
        ok = b.length % 32 == 0;
        assembly ("memory-safe") {
            let q := Q
            let end := add(b.offset, b.length)
            for { let p := b.offset } and(ok, lt(p, end)) { p := add(p, 32) } {
                let w := calldataload(p)
                ok := and(and(lt(shr(192, w), q), lt(and(shr(128, w), M64), q)),
                    and(lt(and(shr(64, w), M64), q), lt(and(w, M64), q)))
            }
        }
    }

    /// @notice A memory copy of the calldata ciphertext `x` (its length is the caller's check).
    function load(bytes calldata x) internal pure returns (bytes memory c) {
        c = x;
    }

    /// @notice `a += x` lane-wise, unreduced (`a.length` words of `x` from the start).
    function plus(bytes memory a, bytes calldata x) internal pure {
        assembly ("memory-safe") {
            let d := add(a, 32)
            let n := mload(a)
            for { let i := 0 } lt(i, n) { i := add(i, 32) } {
                mstore(add(d, i), add(mload(add(d, i)), calldataload(add(x.offset, i))))
            }
        }
    }

    /// @notice `a −= x` lane-wise, as `a += (q − x)` (unreduced; `x` canonical).
    function minus(bytes memory a, bytes calldata x) internal pure {
        assembly ("memory-safe") {
            let d := add(a, 32)
            let n := mload(a)
            for { let i := 0 } lt(i, n) { i := add(i, 32) } {
                mstore(add(d, i), add(mload(add(d, i)), sub(Q4, calldataload(add(x.offset, i)))))
            }
        }
    }

    /// @notice `a += Trivial(amount)`: `v[i] += Δ·digit_i(amount)` for the 16 base-16 digits (`amount < 2^64`); `u`
    ///         unchanged. `a` is a ciphertext (16,512 B).
    function addTrivial(bytes memory a, uint256 amount) internal pure {
        _trivial(a, amount, false);
    }

    /// @notice `a −= Trivial(amount)` as `v[i] += q − Δ·digit_i(amount)` (unreduced; `Δ·15 < q`, no borrow).
    function subTrivial(bytes memory a, uint256 amount) internal pure {
        _trivial(a, amount, true);
    }

    function _trivial(bytes memory a, uint256 amount, bool neg) private pure {
        assembly ("memory-safe") {
            let v := add(add(a, 32), PK)
            for { let j := 0 } lt(j, 4) { j := add(j, 1) } {
                let t := 0
                for { let k := 0 } lt(k, 4) { k := add(k, 1) } {
                    let digit := and(shr(mul(4, add(mul(4, j), k)), amount), 15)
                    t := or(t, shl(mul(64, sub(3, k)), mul(DELTA, digit)))
                }
                if neg { t := sub(Q4, t) }
                let p := add(v, mul(32, j))
                mstore(p, add(mload(p), t))
            }
        }
    }

    /// @notice `t = u ‖ v` of a stored entry (plan 5h D1): `u` (16,384 B) at byte `uOff`, `v` (128 B) at `vOff` of the
    ///         SSTORE2 data at `blob` (code offset + 1, after the STOP byte). `t` is a ciphertext buffer.
    function loadBlob(address blob, uint256 uOff, uint256 vOff, bytes memory t) internal view {
        assembly ("memory-safe") {
            let d := add(t, 32)
            extcodecopy(blob, d, add(uOff, 1), PK)
            extcodecopy(blob, add(d, PK), add(vOff, 1), V)
        }
    }

    /// @notice `a += x` lane-wise, unreduced, both in memory (`a.length` words; a multiple of 4 words, as `CT`).
    function addMem(bytes memory a, bytes memory x) internal pure {
        assembly ("memory-safe") {
            let p := add(a, 32)
            let q := add(x, 32)
            let e := add(p, mload(a))
            for {} lt(p, e) {} {
                mstore(p, add(mload(p), mload(q)))
                mstore(add(p, 32), add(mload(add(p, 32)), mload(add(q, 32))))
                mstore(add(p, 64), add(mload(add(p, 64)), mload(add(q, 64))))
                mstore(add(p, 96), add(mload(add(p, 96)), mload(add(q, 96))))
                p := add(p, 128)
                q := add(q, 128)
            }
        }
    }

    /// @notice `a −= x` lane-wise as `a += (q − x)`, both in memory (unreduced; `x` canonical).
    function subMem(bytes memory a, bytes memory x) internal pure {
        assembly ("memory-safe") {
            let p := add(a, 32)
            let q := add(x, 32)
            let e := add(p, mload(a))
            for {} lt(p, e) {} {
                mstore(p, add(mload(p), sub(Q4, mload(q))))
                p := add(p, 32)
                q := add(q, 32)
            }
        }
    }

    /// @notice Every byte of `b` zero (D24).
    function isZero(bytes calldata b) internal pure returns (bool z) {
        assembly ("memory-safe") {
            let acc := 0
            let end := add(b.offset, b.length)
            for { let p := b.offset } lt(p, end) { p := add(p, 32) } { acc := or(acc, calldataload(p)) }
            z := iszero(acc)
        }
    }

    /// @notice One `mod q` per lane (every lane `< 2^64` before).
    function reduce(bytes memory a) internal pure {
        assembly ("memory-safe") {
            let q := Q
            let d := add(a, 32)
            let n := mload(a)
            for { let i := 0 } lt(i, n) { i := add(i, 32) } {
                let p := add(d, i)
                let w := mload(p)
                mstore(p, or(or(shl(192, mod(shr(192, w), q)), shl(128, mod(and(shr(128, w), M64), q))),
                    or(shl(64, mod(and(shr(64, w), M64), q)), mod(and(w, M64), q))))
            }
        }
    }

    /// @notice `keccak256(ct)` of a stored hash: 0 (never written) is the zero ciphertext's.
    function stored(bytes32 h) internal pure returns (bytes32) {
        return h == bytes32(0) ? ZERO_HASH : h;
    }
}
