// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {PqzSet, PQZ_ACC_WORDS} from "./PqzSet.sol";

/// @title PQZ ciphertext arithmetic (pq-zero-knowledge.md §4.2, §8.1 "Objects") at the build's parameter set (`PqzSet`,
///        generated per set; one set per build): `ct = u ‖ v`, `CT` bytes = `CT / 8` coefficients `< q`, each `be8`,
///        coefficient 0 first; `pk` / `u` `PK` bytes, `v` 128 B (16 coefficients).
/// @notice **UNAUDITED.** Pure Solidity, no precompile (pq-zero-knowledge.md §9.4). In memory and calldata a 32-byte word
///         holds four coefficients in 64-bit lanes (the first coefficient in the top lane). Sums run lane-wise without
///         reduction — every input lane is `< q < 2^LOG2Q`, so up to `2^(64 − LOG2Q)` terms never carry into the next
///         lane (2^10 at `n2816-kmax65536`; a rollover adds at most `ROLL_MAX + 1`) — and `reduce` takes one `mod q` per
///         lane at the end. `minus` adds `q − x` per lane (no borrow, `x < q`). Callers pass only canonical ciphertexts
///         (hash-matched to state, or checked with `isCanonical`).
///
///         **Stored form (P46, owner 2026-10-21; plan 5h Task 8d part 2).** What the token stores — the op blobs (SSTORE2)
///         and a materialised `acc` — holds each coefficient in `B = PACK_BITS = ⌈log2 q⌉` bits: one 64-bit-lane word
///         (four coefficients `c0 ‖ c1 ‖ c2 ‖ c3`, big-endian) becomes `GROUP = B / 2` bytes, so the stream stays
///         byte-aligned and `u` / `v` pack apart (`PKP`, `VP`, `CTP` bytes). Calldata, the statement and the precompile
///         input keep the 64-bit lanes: the token packs `out` into the blob and expands what it reads.
library PqzCt {
    uint256 internal constant Q = PqzSet.Q;
    uint256 internal constant DELTA = PqzSet.DELTA;
    uint256 internal constant PK = PqzSet.PK;
    uint256 internal constant V = PqzSet.V;
    uint256 internal constant CT = PqzSet.CT;
    /// @notice `keccak256` of the packed zero ciphertext `Trivial(0)` (`CTP` zero bytes; a new account's `acc`).
    bytes32 internal constant ZERO_HASH = PqzSet.ZERO_HASH;

    /// @notice P46: bits per stored coefficient, bytes per stored 64-bit-lane word (four coefficients), stored sizes.
    uint256 internal constant B = PqzSet.PACK_BITS;
    uint256 internal constant GROUP = B / 2;
    uint256 internal constant PKP = PK / 32 * GROUP;
    uint256 internal constant VP = V / 32 * GROUP;
    uint256 internal constant CTP = PKP + VP;
    /// @notice The slots of a materialised `acc`: `⌈CTP / 32⌉`, each `not(stream word)`, so never 0:
    ///         a full window holds at least one whole `B`-bit field (`2^B − 1 ≥ q`, so the stream word is not all ones),
    ///         and the last slot's slack (`CTP mod 32` bytes, 4 at `n2560-kmax16384`, less than one field) is stored as
    ///         ones (`not` of the zero padding), which keeps that slot non-zero too.
    uint256 internal constant ACC_WORDS = PQZ_ACC_WORDS;

    uint256 private constant M64 = 0xffffffffffffffff;
    uint256 private constant Q4 = Q << 192 | Q << 128 | Q << 64 | Q; // q in each lane
    uint256 private constant MB = (1 << B) - 1;
    uint256 private constant M2B = (1 << (2 * B)) - 1;
    uint256 private constant SH = 256 - 4 * B; // a group's record `c0 ‖ c1 ‖ c2 ‖ c3` sits in bits SH..255 as loaded
    uint256 private constant MLO = MB << 128 | MB; // c1, c3 of a word / the low field of each half of a record
    // the rollover accumulators: c1, c3 of a group as loaded; c0, c2 after `shr(B)`; each field keeps B bits above it
    uint256 private constant MEA = MB << (256 - 2 * B) | MB << SH;
    // pack:   w = c0 ‖ c1 ‖ c2 ‖ c3 (64-bit lanes) → h = or(shl(B, and(shr(64, w), MLO)), and(w, MLO)) (two halves of
    //         c_{2i} ‖ c_{2i+1} at bits 128 and 0) → r = or(shl(2B, shr(128, h)), and(h, M2B)) (4B bits) → shl(SH, r)
    // expand: the inverse, h = or(shl(128, shr(2B, r)), and(r, M2B)), w = or(shl(64, and(shr(B, h), MLO)), and(h, MLO))

    /// @notice Every 8-byte coefficient `< q`; the length a multiple of 32 (every PQZ object is).
    function isCanonical(bytes calldata b) internal pure returns (bool ok) {
        ok = b.length % 32 == 0;
        uint256 q = Q;
        assembly ("memory-safe") {
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
        uint256 q4 = Q4;
        assembly ("memory-safe") {
            let d := add(a, 32)
            let n := mload(a)
            for { let i := 0 } lt(i, n) { i := add(i, 32) } {
                mstore(add(d, i), add(mload(add(d, i)), sub(q4, calldataload(add(x.offset, i)))))
            }
        }
    }

    /// @notice `a += Trivial(amount)`: `v[i] += Δ·digit_i(amount)` for the 16 base-16 digits (`amount < 2^64`); `u`
    ///         unchanged. `a` is a ciphertext (`CT` bytes).
    function addTrivial(bytes memory a, uint256 amount) internal pure {
        _trivial(a, amount, false);
    }

    /// @notice `a −= Trivial(amount)` as `v[i] += q − Δ·digit_i(amount)` (unreduced; `Δ·15 < q`, no borrow).
    function subTrivial(bytes memory a, uint256 amount) internal pure {
        _trivial(a, amount, true);
    }

    function _trivial(bytes memory a, uint256 amount, bool neg) private pure {
        (uint256 pk, uint256 delta, uint256 q4) = (PK, DELTA, Q4);
        assembly ("memory-safe") {
            let v := add(add(a, 32), pk)
            for { let j := 0 } lt(j, 4) { j := add(j, 1) } {
                let t := 0
                for { let k := 0 } lt(k, 4) { k := add(k, 1) } {
                    let digit := and(shr(mul(4, add(mul(4, j), k)), amount), 15)
                    t := or(t, shl(mul(64, sub(3, k)), mul(delta, digit)))
                }
                if neg { t := sub(q4, t) }
                let p := add(v, mul(32, j))
                mstore(p, add(mload(p), t))
            }
        }
    }

    /// @notice `t = u ‖ v` (64-bit lanes) of a stored entry (plan 5h D1): the packed `u` (`PKP` bytes) at byte `uOff`,
    ///         `v` (`VP`) at `vOff` of the SSTORE2 data at `blob` (code offset + 1, after the STOP byte), expanded in
    ///         place. `t` is a ciphertext buffer.
    function loadBlob(address blob, uint256 uOff, uint256 vOff, bytes memory t) internal view {
        expandAt(fetch(t, blob, uOff, vOff), CT / 32);
    }

    /// @notice The packed `u ‖ v` of a stored entry copied to the start of `x` (≥ `CTP + 32` bytes); its address.
    function fetch(bytes memory x, address blob, uint256 uOff, uint256 vOff) internal view returns (uint256 s) {
        (uint256 pkp, uint256 vp) = (PKP, VP);
        assembly ("memory-safe") {
            s := add(x, 32)
            extcodecopy(blob, s, add(uOff, 1), pkp)
            extcodecopy(blob, add(s, pkp), add(vOff, 1), vp)
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
        uint256 q4 = Q4;
        assembly ("memory-safe") {
            let p := add(a, 32)
            let q := add(x, 32)
            let e := add(p, mload(a))
            for {} lt(p, e) {} {
                mstore(p, add(mload(p), sub(q4, mload(q))))
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
        uint256 q = Q;
        assembly ("memory-safe") {
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

    /// @notice `keccak256` of a stored (packed) ciphertext: 0 (never written) is the zero ciphertext's.
    function stored(bytes32 h) internal pure returns (bytes32) {
        return h == bytes32(0) ? ZERO_HASH : h;
    }

    // ------------------------------------------------------------------ the stored form (P46)

    /// @notice `dst[dOff ..] = pack(src)` (each 32-byte word of canonical lanes → `GROUP` bytes); writes `32 − GROUP`
    ///         zero bytes past the packed end, so callers write fields in ascending order and leave that slack.
    function packCd(bytes memory dst, uint256 dOff, bytes calldata src) internal pure {
        (uint256 mlo, uint256 m2b, uint256 b, uint256 sh, uint256 g) = (MLO, M2B, B, SH, GROUP);
        assembly ("memory-safe") {
            let d := add(add(dst, 32), dOff)
            let end := add(src.offset, src.length)
            for { let p := src.offset } lt(p, end) { p := add(p, 32) } {
                let w := calldataload(p)
                w := or(shl(b, and(shr(64, w), mlo)), and(w, mlo))
                mstore(d, shl(sh, or(shl(add(b, b), shr(128, w)), and(w, m2b))))
                d := add(d, g)
            }
        }
    }

    /// @notice The packed form of a 64-bit-lane buffer (`src.length / 32 · GROUP` bytes; 32 bytes of slack allocated).
    function packMem(bytes memory src) internal pure returns (bytes memory r) {
        uint256 n = src.length / 32;
        r = new bytes(n * GROUP + 32);
        (uint256 mlo, uint256 m2b, uint256 b, uint256 sh, uint256 g) = (MLO, M2B, B, SH, GROUP);
        assembly ("memory-safe") {
            let s := add(src, 32)
            let d := add(r, 32)
            mstore(r, mul(n, g))
            for { let e := add(s, shl(5, n)) } lt(s, e) { s := add(s, 32) } {
                let w := mload(s)
                w := or(shl(b, and(shr(64, w), mlo)), and(w, mlo))
                mstore(d, shl(sh, or(shl(add(b, b), shr(128, w)), and(w, m2b))))
                d := add(d, g)
            }
        }
    }

    /// @notice In place: the `k` packed groups at memory `p` become `k` 64-bit-lane words at `p` (descending, so no
    ///         unread group is overwritten).
    function expandAt(uint256 p, uint256 k) internal pure {
        (uint256 mlo, uint256 m2b, uint256 b, uint256 sh, uint256 g) = (MLO, M2B, B, SH, GROUP);
        assembly ("memory-safe") {
            let b2 := add(b, b)
            for { let i := k } i {} {
                i := sub(i, 1)
                let x := shr(sh, mload(add(p, mul(g, i))))
                x := or(shl(128, shr(b2, x)), and(x, m2b))
                mstore(add(p, shl(5, i)), or(shl(64, and(shr(b, x), mlo)), and(x, mlo)))
            }
        }
    }

    /// @notice The 64-bit-lane ciphertext of a packed one (`CTP` bytes).
    function unpackCt(bytes memory packed) internal pure returns (bytes memory c) {
        c = new bytes(CT);
        uint256 d;
        uint256 ctp = CTP;
        assembly ("memory-safe") {
            d := add(c, 32)
            mcopy(d, add(packed, 32), ctp)
        }
        expandAt(d, CT / 32);
    }

    /// @notice `c ±= u ‖ v` of a stored entry, expanded on the fly (`x` scratch of ≥ `CTP + 32` bytes; `c` a ciphertext).
    ///         The debit path (≤ `INLINE_MAX` entries).
    function addBlob(bytes memory c, bytes memory x, address blob, uint256 uOff, uint256 vOff, bool neg) internal view {
        uint256 s = fetch(x, blob, uOff, vOff);
        uint256 d;
        uint256 e;
        assembly ("memory-safe") {
            d := add(c, 32)
            e := add(d, mload(c))
        }
        _addPacked(d, e, s, neg);
    }

    /// @dev Memory words `[d, e)` `+= y` (`neg`: `+= q − y`) for `y` the expanded groups from `s` on, four per iteration
    ///      (`e − d` a multiple of 128: every ciphertext is a multiple of four words).
    function _addPacked(uint256 d, uint256 e, uint256 s, bool neg) private pure {
        (uint256 mlo, uint256 m2b, uint256 b, uint256 sh, uint256 g) = (MLO, M2B, B, SH, GROUP);
        uint256 q4 = neg ? Q4 : 0;
        assembly ("memory-safe") {
            function spread(r, b_, mlo_, m2b_) -> w {
                r := or(shl(128, shr(add(b_, b_), r)), and(r, m2b_))
                w := or(shl(64, and(shr(b_, r), mlo_)), and(r, mlo_))
            }
            switch q4
            case 0 {
                for {} lt(d, e) { d := add(d, 128) } {
                    mstore(d, add(mload(d), spread(shr(sh, mload(s)), b, mlo, m2b)))
                    s := add(s, g)
                    mstore(add(d, 32), add(mload(add(d, 32)), spread(shr(sh, mload(s)), b, mlo, m2b)))
                    s := add(s, g)
                    mstore(add(d, 64), add(mload(add(d, 64)), spread(shr(sh, mload(s)), b, mlo, m2b)))
                    s := add(s, g)
                    mstore(add(d, 96), add(mload(add(d, 96)), spread(shr(sh, mload(s)), b, mlo, m2b)))
                    s := add(s, g)
                }
            }
            default {
                for {} lt(d, e) { d := add(d, 128) } {
                    mstore(d, add(mload(d), sub(q4, spread(shr(sh, mload(s)), b, mlo, m2b))))
                    s := add(s, g)
                    mstore(add(d, 32), add(mload(add(d, 32)), sub(q4, spread(shr(sh, mload(s)), b, mlo, m2b))))
                    s := add(s, g)
                    mstore(add(d, 64), add(mload(add(d, 64)), sub(q4, spread(shr(sh, mload(s)), b, mlo, m2b))))
                    s := add(s, g)
                    mstore(add(d, 96), add(mload(add(d, 96)), sub(q4, spread(shr(sh, mload(s)), b, mlo, m2b))))
                    s := add(s, g)
                }
            }
        }
    }

    /// @notice Rollover accumulation without the spread: the stored entry's groups summed as they are, `c1`, `c3` into
    ///         `A` and `c0`, `c2` into `B_` (each field keeps a `B`-bit gap above it for the carries: ≤ 2^B terms).
    ///         `combineEO` adds the sums into `c` once at the end. `A`, `B_` zeroed ciphertext-size buffers, `x` scratch.
    function addBlobEO(bytes memory A, bytes memory B_, bytes memory x, address blob, uint256 uOff, uint256 vOff)
        internal view
    {
        uint256 s = fetch(x, blob, uOff, vOff);
        uint256 a;
        uint256 bb;
        assembly ("memory-safe") {
            a := add(A, 32)
            bb := add(B_, 32)
        }
        _addEO(a, bb, a + A.length, s);
    }

    /// @dev `[a, e) += and(z, MEA)`, `[bb, ..) += and(shr(B, z), MEA)` for `z` the groups from `s` on as loaded.
    function _addEO(uint256 a, uint256 bb, uint256 e, uint256 s) private pure {
        (uint256 mea, uint256 b, uint256 g) = (MEA, B, GROUP);
        assembly ("memory-safe") {
            for {} lt(a, e) {} {
                let z := mload(s)
                mstore(a, add(mload(a), and(z, mea)))
                mstore(bb, add(mload(bb), and(shr(b, z), mea)))
                z := mload(add(s, g))
                mstore(add(a, 32), add(mload(add(a, 32)), and(z, mea)))
                mstore(add(bb, 32), add(mload(add(bb, 32)), and(shr(b, z), mea)))
                s := add(s, add(g, g))
                z := mload(s)
                mstore(add(a, 64), add(mload(add(a, 64)), and(z, mea)))
                mstore(add(bb, 64), add(mload(add(bb, 64)), and(shr(b, z), mea)))
                z := mload(add(s, g))
                mstore(add(a, 96), add(mload(add(a, 96)), and(z, mea)))
                mstore(add(bb, 96), add(mload(add(bb, 96)), and(shr(b, z), mea)))
                s := add(s, add(g, g))
                a := add(a, 128)
                bb := add(bb, 128)
            }
        }
    }

    /// @notice `c += spread(A, B_)` lane-wise (each field sum `< 2^64`: `(ROLL_MAX + 1) · q < 2^64`; `c` then `reduce`d).
    function combineEO(bytes memory c, bytes memory A, bytes memory B_) internal pure {
        (uint256 hi, uint256 sh, uint256 m2b) = (256 - 2 * B, SH, M2B);
        assembly ("memory-safe") {
            let d := add(c, 32)
            let pa := add(A, 32)
            let pb := add(B_, 32)
            let n := mload(c)
            for { let i := 0 } lt(i, n) { i := add(i, 32) } {
                let a := mload(add(pa, i))
                let b := mload(add(pb, i))
                let p := add(d, i)
                mstore(p, add(mload(p), or(or(shl(192, shr(hi, b)), shl(128, shr(hi, a))),
                    or(shl(64, and(shr(sh, b), m2b)), and(shr(sh, a), m2b)))))
            }
        }
    }
}
