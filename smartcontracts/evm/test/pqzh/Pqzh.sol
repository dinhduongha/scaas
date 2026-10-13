// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title PQZH verifier pieces for the Solidity gas study (test-only, never deployed)
/// @notice Goldilocks p = 2^64 - 2^32 + 1, its extensions Fp2 (u^2 = 7) and Fp3 (x^3 = x + 1) as in Plonky3 0.8,
///         Keccak-256 Merkle paths, FRI folds, a LogUp public sum and a Horner fingerprint. Reference values:
///         pqz-core/pqzh/sol/ref.py; study: docs/research/pqzh-solidity-verifier.md.
/// @dev An extension element is packed in one word, coefficient i at bits 64 i (E = 2 or 3). Field elements in
///      calldata are 8-byte big-endian. Straightforward Yul, not hand-scheduled: a tuned verifier is cheaper.
library Pqzh {
    uint256 internal constant P = 0xffffffff00000001;
    uint256 internal constant M = 0xffffffffffffffff;
    uint256 internal constant INV2 = 0x7fffffff80000001;

    /// a^(p - 2): p - 2 = (2^32 - 2) 2^32 + (2^32 - 1), via e31 = a^(2^31 - 1) (64 squarings, 9 multiplications).
    function inv(uint256 a) internal pure returns (uint256 r) {
        assembly ("memory-safe") {
            function sq(x, n) -> y {
                y := x
                for { } n { n := sub(n, 1) } { y := mulmod(y, y, 0xffffffff00000001) }
            }
            let p := 0xffffffff00000001
            let e2 := mulmod(mulmod(a, a, p), a, p)
            let e3 := mulmod(mulmod(e2, e2, p), a, p)
            let e6 := mulmod(sq(e3, 3), e3, p)
            let e12 := mulmod(sq(e6, 6), e6, p)
            let e24 := mulmod(sq(e12, 12), e12, p)
            let e30 := mulmod(sq(e24, 6), e6, p)
            let e31 := mulmod(mulmod(e30, e30, p), a, p)
            let e32 := mulmod(mulmod(e31, e31, p), a, p)
            r := mulmod(sq(e31, 33), e32, p)
        }
    }

    function emul(uint256 a, uint256 b, uint256 E) internal pure returns (uint256 r) {
        assembly ("memory-safe") {
            let p := 0xffffffff00000001
            let m := 0xffffffffffffffff
            let a0 := and(a, m)
            let a1 := and(shr(64, a), m)
            let b0 := and(b, m)
            let b1 := and(shr(64, b), m)
            switch E
            case 2 {
                r := or(mod(add(mul(a0, b0), mul(7, mul(a1, b1))), p), shl(64, mod(add(mul(a0, b1), mul(a1, b0)), p)))
            }
            default {
                let a2 := shr(128, a)
                let b2 := shr(128, b)
                let c3 := add(mul(a1, b2), mul(a2, b1))
                let c4 := mul(a2, b2)
                let c0 := mod(add(mul(a0, b0), c3), p)
                let c1 := mod(add(add(add(mul(a0, b1), mul(a1, b0)), c3), c4), p)
                let c2 := mod(add(add(add(mul(a0, b2), mul(a1, b1)), mul(a2, b0)), c4), p)
                r := or(or(c0, shl(64, c1)), shl(128, c2))
            }
        }
    }

    function eadd(uint256 a, uint256 b) internal pure returns (uint256 r) {
        assembly ("memory-safe") {
            let p := 0xffffffff00000001
            let m := 0xffffffffffffffff
            r := or(or(addmod(and(a, m), and(b, m), p), shl(64, addmod(and(shr(64, a), m), and(shr(64, b), m), p))),
                shl(128, addmod(shr(128, a), shr(128, b), p)))
        }
    }

    function esub(uint256 a, uint256 b) internal pure returns (uint256 r) {
        assembly ("memory-safe") {
            let p := 0xffffffff00000001
            let m := 0xffffffffffffffff
            r := or(
                or(addmod(and(a, m), sub(p, and(b, m)), p), shl(64, addmod(and(shr(64, a), m), sub(p, and(shr(64, b), m)), p))),
                shl(128, addmod(shr(128, a), sub(p, shr(128, b)), p))
            )
        }
    }

    /// base x ext
    function escale(uint256 a, uint256 s) internal pure returns (uint256 r) {
        assembly ("memory-safe") {
            let p := 0xffffffff00000001
            let m := 0xffffffffffffffff
            r := or(or(mulmod(and(a, m), s, p), shl(64, mulmod(and(shr(64, a), m), s, p))), shl(128, mulmod(shr(128, a), s, p)))
        }
    }

    function einv(uint256 a, uint256 E) internal pure returns (uint256 r) {
        uint256 a0 = a & M;
        uint256 a1 = (a >> 64) & M;
        if (E == 2) {
            uint256 n = inv(addmod(mulmod(a0, a0, P), P - mulmod(7, mulmod(a1, a1, P), P), P));
            return mulmod(a0, n, P) | (mulmod(P - a1, n, P) << 64);
        }
        uint256 a2 = a >> 128;
        // multiplication matrix by a (columns a, a.x, a.x^2), first column of its adjugate over the determinant
        uint256 m11 = addmod(a0, a2, P);
        uint256 m12 = addmod(a1, a2, P);
        uint256 c0 = addmod(mulmod(m11, m11, P), P - mulmod(m12, a1, P), P); // m22 = m11, m21 = a1
        uint256 c1 = addmod(mulmod(m12, a2, P), P - mulmod(a1, m11, P), P); // m20 = a2, m10 = a1
        uint256 c2 = addmod(mulmod(a1, a1, P), P - mulmod(m11, a2, P), P);
        uint256 d = inv(addmod(addmod(mulmod(a0, c0, P), mulmod(a2, c1, P), P), mulmod(a1, c2, P), P));
        return mulmod(c0, d, P) | (mulmod(c1, d, P) << 64) | (mulmod(c2, d, P) << 128);
    }

    /// Root of a Merkle path: siblings (32 bytes each, leaf level first) at calldata `ptr`.
    function merkle(bytes32 node, uint256 idx, uint256 depth, uint256 ptr) internal pure returns (bytes32 r) {
        assembly ("memory-safe") {
            for { let end := add(ptr, shl(5, depth)) } lt(ptr, end) { ptr := add(ptr, 32) } {
                let b := shl(5, and(idx, 1))
                mstore(b, node)
                mstore(xor(b, 32), calldataload(ptr))
                node := keccak256(0, 64)
                idx := shr(1, idx)
            }
            r := node
        }
    }

    /// Root of a mixed-height opening (p3-merkle-tree verify_batch): leaf = keccak of the tallest group's row
    /// (`w[0]` values at calldata `rows`), the shorter groups' rows follow and are injected as
    /// keccak(node || keccak(row)) once the walk reaches their height `lh[g]`; siblings at calldata `sib`.
    function walk(uint256[] memory lh, uint256[] memory w, uint256 i, uint256 rows, uint256 sib)
        internal
        pure
        returns (bytes32 node)
    {
        assembly ("memory-safe") {
            let f := mload(0x40)
            let depth := mload(add(lh, 32))
            let len := shl(3, mload(add(w, 32)))
            calldatacopy(f, rows, len)
            node := keccak256(f, len)
            let rp := add(rows, len)
            let g := 1
            let ng := mload(lh)
            let nextH := 0x100
            if lt(g, ng) { nextH := mload(add(lh, 64)) }
            for { let l := 0 } lt(l, depth) { l := add(l, 1) } {
                let b := shl(5, and(i, 1))
                mstore(b, node)
                mstore(xor(b, 32), calldataload(add(sib, shl(5, l))))
                node := keccak256(0, 64)
                i := shr(1, i)
                if eq(nextH, sub(sub(depth, l), 1)) {
                    let wl := shl(3, mload(add(w, shl(5, add(g, 1)))))
                    calldatacopy(f, rp, wl)
                    mstore(32, keccak256(f, wl))
                    mstore(0, node)
                    node := keccak256(0, 64)
                    rp := add(rp, wl)
                    g := add(g, 1)
                    nextH := 0x100
                    if lt(g, ng) { nextH := mload(add(lh, shl(5, add(g, 1)))) }
                }
            }
        }
    }

    /// Calldata offset of a `bytes calldata` argument.
    function off(bytes calldata x) internal pure returns (uint256 o) {
        assembly ("memory-safe") {
            o := x.offset
        }
    }

    /// keccak256 of `len` calldata bytes at `ptr` (copied to free memory, not allocated).
    function hashCd(uint256 ptr, uint256 len) internal pure returns (bytes32 h) {
        assembly ("memory-safe") {
            let f := mload(0x40)
            calldatacopy(f, ptr, len)
            h := keccak256(f, len)
        }
    }

    /// Tables G[t] = g^(2^t), GI[t] = g^(-2^t) for g of order 2^32 (Plonky3 TWO_ADIC_GENERATORS[32]).
    function tables() internal pure returns (uint256[64] memory t) {
        assembly ("memory-safe") {
            mstore(t, 0x185629dcda58878c)
            mstore(add(t, 0x20), 0x400a7f755588e659)
            mstore(add(t, 0x40), 0x7e9bd009b86a0845)
            mstore(add(t, 0x60), 0xdfa8c93ba46d2666)
            mstore(add(t, 0x80), 0x59049500004a4485)
            mstore(add(t, 0xa0), 0x10d78dd8915a171d)
            mstore(add(t, 0xc0), 0xed41d05b78d6e286)
            mstore(add(t, 0xe0), 0x4bbaf5976ecfefd8)
            mstore(add(t, 0x100), 0x86cdcc31c307e171)
            mstore(add(t, 0x120), 0xea9d5a1336fbc98b)
            mstore(add(t, 0x140), 0x4b2a18ade67246b5)
            mstore(add(t, 0x160), 0xf502aef532322654)
            mstore(add(t, 0x180), 0x30ba2ecd5e93e76d)
            mstore(add(t, 0x1a0), 0xfbd41c6b8caa3302)
            mstore(add(t, 0x1c0), 0x81281a7b05f9beac)
            mstore(add(t, 0x1e0), 0xabd0a6e8aa3d8a0e)
            mstore(add(t, 0x200), 0x54df9630bf79450e)
            mstore(add(t, 0x220), 0xf6b2cffe2306baac)
            mstore(add(t, 0x240), 0xe0ee099310bba1e2)
            mstore(add(t, 0x260), 0x1544ef2335d17997)
            mstore(add(t, 0x280), 0xf2c35199959dfcb6)
            mstore(add(t, 0x2a0), 0x653b4801da1c8cf)
            mstore(add(t, 0x2c0), 0x9d8f2ad78bfed972)
            mstore(add(t, 0x2e0), 0x1905d02a5c411f4e)
            mstore(add(t, 0x300), 0xbf79143ce60ca966)
            mstore(add(t, 0x320), 0xf80007ff08000001)
            mstore(add(t, 0x340), 0x8000000000)
            mstore(add(t, 0x360), 0x3fffffffc000)
            mstore(add(t, 0x380), 0xefffffff00000001)
            mstore(add(t, 0x3a0), 0xfffffffeff000001)
            mstore(add(t, 0x3c0), 0x1000000000000)
            mstore(add(t, 0x3e0), 0xffffffff00000000)
            mstore(add(t, 0x400), 0x76b6b635b6fc8719)
            mstore(add(t, 0x420), 0x95c0ec9a7ab50701)
            mstore(add(t, 0x440), 0xe2434909eec4f00b)
            mstore(add(t, 0x460), 0xe4d14a114454645d)
            mstore(add(t, 0x480), 0x3ea7eab8d8857184)
            mstore(add(t, 0x4a0), 0x91f3853f38e675d9)
            mstore(add(t, 0x4c0), 0xea52f593bb20759a)
            mstore(add(t, 0x4e0), 0xc01f93fc71bb0b9b)
            mstore(add(t, 0x500), 0x10eb845263814db7)
            mstore(add(t, 0x520), 0x4bb9aee372cf655e)
            mstore(add(t, 0x540), 0xd46e5a4c36458c11)
            mstore(add(t, 0x560), 0xa52008ac564a2368)
            mstore(add(t, 0x580), 0xef8856969fe6ed7b)
            mstore(add(t, 0x5a0), 0x46a23c48234c7df9)
            mstore(add(t, 0x5c0), 0x22e1fbf03f8b95d6)
            mstore(add(t, 0x5e0), 0xcc9e5a57b8343b3f)
            mstore(add(t, 0x600), 0x6d341b1c9a04ed19)
            mstore(add(t, 0x620), 0x158ee068c8241329)
            mstore(add(t, 0x640), 0x409730a1895adfb6)
            mstore(add(t, 0x660), 0x3712791d9eb0314a)
            mstore(add(t, 0x680), 0x9af01e431fbd6ea0)
            mstore(add(t, 0x6a0), 0x76a40e0866a8e50d)
            mstore(add(t, 0x6c0), 0x3b9ae9d1d8d87589)
            mstore(add(t, 0x6e0), 0x3de19c67cf496a74)
            mstore(add(t, 0x700), 0x1d62e30fa4a4eeb0)
            mstore(add(t, 0x720), 0xffefffff00000011)
            mstore(add(t, 0x740), 0xfdffffff00000001)
            mstore(add(t, 0x760), 0xfffffffefffc0001)
            mstore(add(t, 0x780), 0x1000000000)
            mstore(add(t, 0x7a0), 0xffffffff00)
            mstore(add(t, 0x7c0), 0xfffeffff00000001)
            mstore(add(t, 0x7e0), 0xffffffff00000000)
        }
    }

    /// prod over the set bits j < n of `bits` of T[off - j] (T = G for off < 32, GI for off >= 32): the point
    /// g(h)^rev_n(bits) is pw(t, i, n, 31) with n = h; the coset start inverse of fold_row is pw(t, li, h - a, 63 - a).
    function pw(uint256[64] memory t, uint256 bits, uint256 n, uint256 off) internal pure returns (uint256 r) {
        assembly ("memory-safe") {
            r := 1
            for { let j := 0 } lt(j, n) { j := add(j, 1) } {
                if and(shr(j, bits), 1) { r := mulmod(r, mload(add(t, shl(5, sub(off, j)))), 0xffffffff00000001) }
            }
        }
    }

    /// FRI fold_row (p3-fri): `ev[j]` at s w^rev(j), w of order k = 2^a, `sInv` = 1 / s. Arity 2 in closed form;
    /// otherwise an inverse DFT of the bit-reversed row (DIT, base twiddles) and Horner at beta / s. Overwrites ev.
    function fold(uint256[] memory ev, uint256 a, uint256 beta, uint256 sInv, uint256 E, uint256[64] memory t)
        internal
        pure
        returns (uint256 r)
    {
        if (a == 1) {
            uint256 lo = ev[0];
            uint256 hi = ev[1];
            return eadd(escale(eadd(lo, hi), INV2), emul(escale(esub(lo, hi), mulmod(sInv, INV2, P)), beta, E));
        }
        uint256 k = 1 << a;
        _idft(ev, a, t);
        unchecked {
            uint256 z = escale(beta, sInv);
            r = ev[k - 1];
            for (uint256 j = k - 1; j > 0; --j) r = eadd(emul(r, z, E), ev[j - 1]);
            r = escale(r, P - (P - 1) / k); // 1 / k, as k divides p - 1
        }
    }

    /// In-place inverse DFT (unscaled) of the 2^a ext values of `ev` given in bit-reversed order: radix-2 DIT
    /// with base twiddles, natural-order output.
    function _idft(uint256[] memory ev, uint256 a, uint256[64] memory t) private pure {
        assembly ("memory-safe") {
            function bf(pu, pv, w) {
                let u := mload(pu)
                let v := mload(pv)
                let v0 := mulmod(and(v, 0xffffffffffffffff), w, 0xffffffff00000001)
                let v1 := mulmod(and(shr(64, v), 0xffffffffffffffff), w, 0xffffffff00000001)
                let v2 := mulmod(shr(128, v), w, 0xffffffff00000001)
                let u0 := and(u, 0xffffffffffffffff)
                let u1 := and(shr(64, u), 0xffffffffffffffff)
                u := shr(128, u)
                mstore(pu, or(or(addmod(u0, v0, 0xffffffff00000001), shl(64, addmod(u1, v1, 0xffffffff00000001))),
                    shl(128, addmod(u, v2, 0xffffffff00000001))))
                mstore(pv, or(or(addmod(u0, sub(0xffffffff00000001, v0), 0xffffffff00000001),
                    shl(64, addmod(u1, sub(0xffffffff00000001, v1), 0xffffffff00000001))),
                    shl(128, addmod(u, sub(0xffffffff00000001, v2), 0xffffffff00000001))))
            }
            let k := shl(a, 1)
            let base := add(ev, 32)
            for { let s := 1 } iszero(gt(s, a)) { s := add(s, 1) } {
                let half := shl(sub(s, 1), 1)
                let wl := mload(add(t, shl(5, sub(64, s)))) // GI[32 - s]: the inverse root of order 2^s
                for { let i := 0 } lt(i, k) { i := add(i, shl(s, 1)) } {
                    let w := 1
                    for { let j := 0 } lt(j, half) { j := add(j, 1) } {
                        let pu := add(base, shl(5, add(i, j)))
                        bf(pu, add(pu, shl(5, half)), w)
                        w := mulmod(w, wl, 0xffffffff00000001)
                    }
                }
            }
        }
    }

    /// LogUp public side: sum m_i / (beta - k_i), batched inversion (prefix products, one inverse, back pass).
    function logup(uint256[] memory keys, uint256[] memory mults, uint256 beta, uint256 E) internal pure returns (uint256 acc) {
        uint256 n = keys.length;
        uint256[] memory pre = new uint256[](n + 1);
        pre[0] = 1;
        unchecked {
            for (uint256 i; i < n; ++i) pre[i + 1] = emul(pre[i], esub(beta, keys[i]), E);
            uint256 iv = einv(pre[n], E);
            for (uint256 i = n; i > 0; --i) {
                uint256 d = esub(beta, keys[i - 1]);
                acc = eadd(acc, escale(emul(iv, pre[i - 1], E), mults[i - 1]));
                iv = emul(iv, d, E);
            }
        }
    }

    /// Horner fingerprint sum c_i gamma^(n - 1 - i) of the 8-byte big-endian coefficients at calldata [ptr, end);
    /// `ok` = every coefficient < q = 2^42 - 215 (the statement's canonical check).
    function horner(uint256 ptr, uint256 end, uint256 gamma, uint256 E) internal pure returns (uint256 acc, bool ok) {
        assembly ("memory-safe") {
            let p := 0xffffffff00000001
            let m := 0xffffffffffffffff
            let g0 := and(gamma, m)
            let g1 := and(shr(64, gamma), m)
            let g2 := shr(128, gamma)
            let a0 := 0
            let a1 := 0
            let a2 := 0
            let bad := 0
            switch E
            case 2 {
                for { } lt(ptr, end) { ptr := add(ptr, 8) } {
                    let c := shr(192, calldataload(ptr))
                    bad := or(bad, gt(c, 0x3ffffffff28))
                    let n0 := mod(add(add(mul(a0, g0), mul(7, mul(a1, g1))), c), p)
                    a1 := mod(add(mul(a0, g1), mul(a1, g0)), p)
                    a0 := n0
                }
            }
            default {
                for { } lt(ptr, end) { ptr := add(ptr, 8) } {
                    let c := shr(192, calldataload(ptr))
                    bad := or(bad, gt(c, 0x3ffffffff28))
                    let c3 := add(mul(a1, g2), mul(a2, g1))
                    let c4 := mul(a2, g2)
                    let n0 := mod(add(add(mul(a0, g0), c3), c), p)
                    let n1 := mod(add(add(add(mul(a0, g1), mul(a1, g0)), c3), c4), p)
                    a2 := mod(add(add(add(mul(a0, g2), mul(a1, g1)), mul(a2, g0)), c4), p)
                    a1 := n1
                    a0 := n0
                }
            }
            acc := or(or(a0, shl(64, a1)), shl(128, a2))
            ok := iszero(bad)
        }
    }

    /// sum_c apow[c] * v_c over the `w` 8-byte base values at calldata `ptr` (apow unpacked: E words per power);
    /// `bad` = some value is not canonical (>= p).
    function rowsum(uint256 ptr, uint256 w, uint256[] memory apow, uint256 E) internal pure returns (uint256 r, bool bad) {
        assembly ("memory-safe") {
            let p := 0xffffffff00000001
            let q := add(apow, 32)
            let s0 := 0
            let s1 := 0
            let s2 := 0
            let b := 0
            let end := add(ptr, shl(3, w))
            switch E
            case 2 {
                for { } lt(ptr, end) { ptr := add(ptr, 8) } {
                    let v := shr(192, calldataload(ptr))
                    b := or(b, iszero(lt(v, p)))
                    s0 := add(s0, mul(v, mload(q)))
                    s1 := add(s1, mul(v, mload(add(q, 32))))
                    q := add(q, 64)
                }
            }
            default {
                for { } lt(ptr, end) { ptr := add(ptr, 8) } {
                    let v := shr(192, calldataload(ptr))
                    b := or(b, iszero(lt(v, p)))
                    s0 := add(s0, mul(v, mload(q)))
                    s1 := add(s1, mul(v, mload(add(q, 32))))
                    s2 := add(s2, mul(v, mload(add(q, 64))))
                    q := add(q, 96)
                }
            }
            r := or(or(mod(s0, p), shl(64, mod(s1, p))), shl(128, mod(s2, p)))
            bad := b
        }
    }

    /// Ext element (E coefficients, 8-byte big-endian) at calldata `ptr`.
    function ldExt(uint256 ptr, uint256 E) internal pure returns (uint256 r) {
        assembly ("memory-safe") {
            let w := calldataload(ptr)
            r := or(shr(192, w), shl(64, and(shr(128, w), 0xffffffffffffffff)))
            if eq(E, 3) { r := or(r, shl(128, and(shr(64, w), 0xffffffffffffffff))) }
        }
    }
}

/// End-to-end PQZH verifier skeleton for the gas study: the work of a Plonky3-style FRI verifier on a given proof
/// shape (trees, widths, heights, FRI schedule), with every Merkle path and the proof of work enforced. The
/// constraint check at the out-of-domain point is a stand-in loop of the estimated size (`oodMuls` extension
/// multiplications, `perBf` base-twiddle butterflies); the final-polynomial values and the statement fingerprint are
/// computed but not enforced (the synthetic proof of ref.py has random values there). Query indices come from the
/// statement digest (synthetic shortcut, same gas). Not a verifier: never deploy.
contract PqzhSkeleton {
    using Pqzh for uint256;

    uint256 private constant P = 0xffffffff00000001;

    error MerkleMismatch(uint256 tree, uint256 query);
    error PowFailed();
    error NonCanonical();
    error ProofLength();

    struct Tree {
        bool fixedRoot;
        bytes32 root;
        uint256 npts;
        uint256[] lh;
        uint256[] w;
    }

    struct Ctx {
        uint256 E;
        uint256 Q;
        uint256 pow;
        uint256 H0;
        uint256 lb;
        Tree[] trees;
        uint256[] arity;
        uint256 finalLen;
        uint256 oodMuls;
        uint256 perBf;
        uint256 stmtOff;
        uint256 op;
        bytes32 seed;
        bytes32 st;
        uint256 gamma;
        uint256 alpha;
        uint256 zeta;
        uint256 ad;
        uint256 oodPtr;
        bytes32[] friRoots;
        uint256[] betas;
        uint256[] betaK;
        uint256 finalPtr;
        uint256[] apow;
        uint256[] lam;
        uint256[] O;
        uint256[] z1; // zeta * g(lh - lb) per log height
        uint256[] ro; // per log height, per query
        uint256[] num; // per (log height, point), per query
        bool[] used; // log heights present
        uint256[] ev; // fold scratch
        uint256[] den; // batched inversion scratch
        uint256[] pre;
        uint256[] key;
        uint256[64] tbl;
        uint256 out;
        uint256[12] prof; // gas per stage, see `profile`
    }

    function verify(bytes calldata shape, bytes calldata stmt, bytes calldata proof) external view returns (bytes32) {
        return bytes32(_run(shape, stmt, proof).out);
    }

    /// Gas per stage: 0 seed (keccak of the statement), 1 roots / challenges / out-of-domain / FRI roots / proof of
    /// work, 2 Horner fingerprint, 3 DEEP precomputation, 4 constraint stand-in, 5 per-query opened rows (DEEP
    /// numerators), 6 trace Merkle openings, 7 DEEP inversions, 8 FRI rows and Merkle paths, 9 FRI folds,
    /// 10 final polynomial and query overhead (the rest of the query loop), 11 total.
    function profile(bytes calldata shape, bytes calldata stmt, bytes calldata proof) external view returns (uint256[12] memory) {
        return _run(shape, stmt, proof).prof;
    }

    function _run(bytes calldata shape, bytes calldata stmt, bytes calldata proof) private view returns (Ctx memory c) {
        uint256 g0 = gasleft();
        c = _shape(shape);
        c.tbl = Pqzh.tables();
        uint256 g = gasleft();
        _seed(c, stmt);
        c.prof[0] = g - gasleft();
        g = gasleft();
        uint256 p = _commit(c, proof);
        c.prof[1] = g - gasleft();
        g = gasleft();
        (uint256 h, bool ok) = Pqzh.horner(Pqzh.off(stmt) + c.stmtOff, Pqzh.off(stmt) + stmt.length, c.gamma, c.E);
        if (!ok) revert NonCanonical();
        c.out ^= h;
        c.prof[2] = g - gasleft();
        _pre(c);
        bytes32 qs = keccak256(abi.encodePacked(c.seed, "QUERY"));
        g = gasleft();
        for (uint256 q; q < c.Q; ++q) {
            uint256 idx;
            assembly ("memory-safe") {
                mstore(0, qs)
                mstore(32, q)
                idx := keccak256(0, 64)
            }
            idx &= (1 << c.H0) - 1;
            p = _query(c, idx, p, q);
        }
        g -= gasleft();
        c.prof[10] = g - c.prof[5] - c.prof[6] - c.prof[7] - c.prof[8] - c.prof[9];
        if (p != Pqzh.off(proof) + proof.length) revert ProofLength();
        c.prof[11] = g0 - gasleft();
    }

    function _shape(bytes calldata s) private view returns (Ctx memory c) {
        uint256 i;
        c.E = _w(s, i++);
        c.Q = _w(s, i++);
        c.pow = _w(s, i++);
        c.H0 = _w(s, i++);
        c.lb = _w(s, i++);
        c.trees = new Tree[](_w(s, i++));
        c.used = new bool[](c.H0 + 1);
        for (uint256 t; t < c.trees.length; ++t) {
            Tree memory tr = c.trees[t];
            tr.fixedRoot = _w(s, i++) == 1;
            tr.root = bytes32(_w(s, i++));
            tr.npts = _w(s, i++);
            uint256 ng = _w(s, i++);
            tr.lh = new uint256[](ng);
            tr.w = new uint256[](ng);
            for (uint256 g; g < ng; ++g) {
                tr.lh[g] = _w(s, i++);
                tr.w[g] = _w(s, i++);
                c.used[tr.lh[g]] = true;
            }
        }
        c.arity = new uint256[](_w(s, i++));
        for (uint256 r; r < c.arity.length; ++r) c.arity[r] = _w(s, i++);
        c.finalLen = _w(s, i++);
        c.oodMuls = _w(s, i++);
        c.perBf = _w(s, i++);
        c.stmtOff = _w(s, i++);
        c.op = _w(s, i++);
    }

    function _w(bytes calldata s, uint256 i) private view returns (uint256 v) {
        assembly ("memory-safe") {
            v := calldataload(add(s.offset, shl(5, i)))
        }
    }

    /// seed = keccak256(TAG || u8(op) || be32(len) || stmt): the Keccak-256 transcript seed (the EVM keccak opcode).
    function _seed(Ctx memory c, bytes calldata stmt) private view {
        c.seed = keccak256(abi.encodePacked("SCAAS-PQZH-TRANSCRIPT-V1", uint8(c.op), uint32(stmt.length), stmt));
        c.st = c.seed;
    }

    function _observe(Ctx memory c, uint256 ptr, uint256 len) private view {
        bytes32 st = c.st;
        assembly ("memory-safe") {
            let f := mload(0x40)
            mstore(f, st)
            calldatacopy(add(f, 32), ptr, len)
            st := keccak256(f, add(len, 32))
        }
        c.st = st;
    }

    function _sample(Ctx memory c) private view returns (uint256 r) {
        bytes32 st = c.st;
        assembly ("memory-safe") {
            mstore(0, st)
            st := keccak256(0, 32)
            let p := 0xffffffff00000001
            let m := 0xffffffffffffffff
            r := or(mod(and(st, m), p), shl(64, mod(and(shr(64, st), m), p)))
        }
        if (c.E == 3) r |= (((uint256(st) >> 128) & Pqzh.M) % P) << 128;
        c.st = st;
    }

    /// Roots and challenges, out-of-domain values, FRI roots, final polynomial, proof of work.
    function _commit(Ctx memory c, bytes calldata proof) private view returns (uint256 p) {
        p = Pqzh.off(proof);
        uint256 k;
        for (uint256 t; t < c.trees.length; ++t) {
            Tree memory tr = c.trees[t];
            if (tr.fixedRoot) continue;
            tr.root = bytes32(_cd(p));
            _observe(c, p, 32);
            p += 32;
            if (k == 0) {
                _sample(c); // LogUp challenge (unused by the skeleton)
                c.gamma = _sample(c);
            } else if (k == 1) {
                c.alpha = _sample(c);
            } else {
                c.zeta = _sample(c);
            }
            ++k;
        }
        uint256 n;
        for (uint256 t; t < c.trees.length; ++t) {
            for (uint256 g; g < c.trees[t].lh.length; ++g) n += c.trees[t].w[g] * c.trees[t].npts;
        }
        c.oodPtr = p;
        _observe(c, p, n * c.E * 8);
        p += n * c.E * 8;
        c.ad = _sample(c);
        uint256 R = c.arity.length;
        c.friRoots = new bytes32[](R);
        c.betas = new uint256[](R);
        c.betaK = new uint256[](R);
        for (uint256 r; r < R; ++r) {
            c.friRoots[r] = bytes32(_cd(p));
            _observe(c, p, 32);
            p += 32;
            uint256 b = _sample(c);
            c.betas[r] = b;
            for (uint256 j; j < c.arity[r]; ++j) b = b.emul(b, c.E);
            c.betaK[r] = b;
        }
        c.finalPtr = p;
        _observe(c, p, c.finalLen * c.E * 8);
        p += c.finalLen * c.E * 8;
        bytes32 st = c.st;
        uint256 bits = c.pow;
        bool ok;
        assembly ("memory-safe") {
            mstore(0, st)
            mstore(32, shl(192, shr(192, calldataload(p))))
            ok := iszero(shr(sub(256, bits), keccak256(0, 40)))
        }
        if (!ok) revert PowFailed();
        p += 8;
    }

    function _cd(uint256 p) private view returns (uint256 v) {
        assembly ("memory-safe") {
            v := calldataload(p)
        }
    }

    /// Once per proof: DEEP alpha powers, per (tree, group, point) lambda = ad^offset and the combined
    /// out-of-domain value O = sum_c ad^c ood_c; zeta * g per height; the constraint-check stand-in.
    function _alphaPowers(Ctx memory c) private view returns (uint256[] memory packed) {
        uint256 E = c.E;
        uint256 maxw;
        for (uint256 t; t < c.trees.length; ++t) {
            for (uint256 g; g < c.trees[t].w.length; ++g) {
                if (c.trees[t].w[g] > maxw) maxw = c.trees[t].w[g];
            }
        }
        packed = new uint256[](maxw);
        c.apow = new uint256[](maxw * E);
        uint256 a = 1;
        for (uint256 i; i < maxw; ++i) {
            packed[i] = a;
            for (uint256 j; j < E; ++j) c.apow[i * E + j] = (a >> (64 * j)) & Pqzh.M;
            a = a.emul(c.ad, E);
        }
    }

    function _oodCombine(Ctx memory c, uint256[] memory packed) private view {
        uint256 terms;
        for (uint256 t; t < c.trees.length; ++t) terms += c.trees[t].w.length * c.trees[t].npts;
        c.lam = new uint256[](terms);
        c.O = new uint256[](terms);
        uint256 lam = 1;
        uint256 ti;
        uint256 ptr = c.oodPtr;
        for (uint256 t; t < c.trees.length; ++t) {
            Tree memory tr = c.trees[t];
            for (uint256 g; g < tr.w.length; ++g) {
                for (uint256 pt; pt < tr.npts; ++pt) {
                    (c.O[ti], ptr) = _combine(packed, ptr, tr.w[g], c.E);
                    c.lam[ti] = lam;
                    ++ti;
                    for (uint256 j; j < tr.w[g]; ++j) lam = lam.emul(c.ad, c.E); // ad^w
                }
            }
        }
    }

    function _combine(uint256[] memory packed, uint256 ptr, uint256 w, uint256 E) private view returns (uint256 o, uint256) {
        for (uint256 col; col < w; ++col) {
            o = o.eadd(packed[col].emul(Pqzh.ldExt(ptr, E), E));
            ptr += 8 * E;
        }
        return (o, ptr);
    }

    function _pre(Ctx memory c) private view {
        uint256 g = gasleft();
        uint256[] memory packed = _alphaPowers(c);
        _oodCombine(c, packed);
        c.z1 = new uint256[](c.H0 + 1);
        for (uint256 h = c.lb; h <= c.H0; ++h) {
            if (c.used[h]) c.z1[h] = c.zeta.escale(c.tbl[32 - (h - c.lb)]);
        }
        c.ro = new uint256[](c.H0 + 1);
        c.num = new uint256[](2 * (c.H0 + 1));
        c.ev = new uint256[](16);
        c.den = new uint256[](2 * (c.H0 + 1));
        c.pre = new uint256[](2 * (c.H0 + 1) + 1);
        c.key = new uint256[](2 * (c.H0 + 1));
        c.prof[3] = g - gasleft();
        g = gasleft();
        // constraint-check stand-in: oodMuls extension multiplications over the out-of-domain values (folded with
        // alpha), perBf base-twiddle butterflies (the 64 period-64 NTT-weight columns at once: a 64-point transform
        // of their Lagrange weights)
        uint256 E = c.E;
        uint256 acc;
        uint256 n = (c.finalPtr - c.oodPtr) / (8 * E);
        uint256 ptr = c.oodPtr;
        for (uint256 i; i < c.oodMuls; ++i) {
            acc = acc.emul(c.alpha, E).eadd(Pqzh.ldExt(ptr + 8 * E * (i % n), E));
        }
        uint256 z = c.zeta;
        for (uint256 i; i < c.perBf; ++i) {
            uint256 v = z.escale(((i + 1) * 0x9e3779b97f4a7c15) % P);
            acc = acc.eadd(v);
            z = z.esub(v);
        }
        c.out ^= acc;
        c.prof[4] = g - gasleft();
    }

    function _query(Ctx memory c, uint256 idx, uint256 p, uint256 q) private view returns (uint256) {
        uint256 x = mulmod(7, Pqzh.pw(c.tbl, idx, c.H0, 31), P);
        for (uint256 h; h <= c.H0; ++h) {
            c.ro[h] = 0;
            c.num[2 * h] = 0;
            c.num[2 * h + 1] = 0;
        }
        uint256 ti;
        for (uint256 t; t < c.trees.length; ++t) (p, ti) = _tree(c, t, idx, p, q, ti);
        uint256 g2 = gasleft();
        _deep(c, x);
        c.prof[7] += g2 - gasleft();
        return _fri(c, idx, p, q);
    }

    function _tree(Ctx memory c, uint256 t, uint256 idx, uint256 p, uint256 q, uint256 ti) private view returns (uint256, uint256) {
        Tree memory tr = c.trees[t];
        uint256 rowsBytes;
        uint256 g = gasleft();
        (rowsBytes, ti) = _rows(c, tr, p, ti);
        c.prof[5] += g - gasleft();
        g = gasleft();
        if (Pqzh.walk(tr.lh, tr.w, idx >> (c.H0 - tr.lh[0]), p, p + rowsBytes) != tr.root) revert MerkleMismatch(t, q);
        c.prof[6] += g - gasleft();
        return (p + rowsBytes + 32 * tr.lh[0], ti);
    }

    /// DEEP numerators of one tree's opened rows: num[h, point] += lambda (sum_c ad^c v_c - O).
    function _rows(Ctx memory c, Tree memory tr, uint256 p, uint256 ti) private view returns (uint256 rowsBytes, uint256) {
        for (uint256 g; g < tr.w.length; ++g) {
            (uint256 R, bool bad) = Pqzh.rowsum(p + rowsBytes, tr.w[g], c.apow, c.E);
            if (bad) revert NonCanonical();
            for (uint256 pt; pt < tr.npts; ++pt) {
                uint256 k = 2 * tr.lh[g] + pt;
                c.num[k] = c.num[k].eadd(c.lam[ti].emul(R.esub(c.O[ti]), c.E));
                ++ti;
            }
            rowsBytes += 8 * tr.w[g];
        }
        return (rowsBytes, ti);
    }

    /// ro[h] = sum over points of num[h, point] / (x^(2^(H0 - h)) - z_point), one batched inversion per query.
    function _deep(Ctx memory c, uint256 x) private view {
        uint256 E = c.E;
        uint256 n;
        uint256[] memory den = c.den;
        uint256[] memory pre = c.pre;
        uint256[] memory key = c.key;
        pre[0] = 1;
        uint256 xh = x;
        for (uint256 h = c.H0 + 1; h > 0; --h) {
            uint256 lh = h - 1;
            if (c.used[lh]) {
                for (uint256 pt; pt < 2; ++pt) {
                    if (c.num[2 * lh + pt] == 0) continue;
                    uint256 d = xh.esub(pt == 0 ? c.zeta : c.z1[lh]);
                    den[n] = d;
                    key[n] = 2 * lh + pt;
                    pre[n + 1] = pre[n].emul(d, E);
                    ++n;
                }
            }
            xh = mulmod(xh, xh, P);
        }
        uint256 iv = pre[n].einv(E);
        for (uint256 i = n; i > 0; --i) {
            uint256 k = key[i - 1];
            c.ro[k >> 1] = c.ro[k >> 1].eadd(c.num[k].emul(iv.emul(pre[i - 1], E), E));
            iv = iv.emul(den[i - 1], E);
        }
    }

    function _fri(Ctx memory c, uint256 i, uint256 p, uint256 q) private view returns (uint256) {
        uint256[4] memory st = [i, c.H0, p, c.ro[c.H0]]; // index, log height, proof pointer, folded value
        for (uint256 r; r < c.arity.length; ++r) _round(c, r, st, q);
        // final polynomial at the query point (computed, not enforced: synthetic proof)
        uint256 xf = Pqzh.pw(c.tbl, st[0], st[1], 31);
        uint256 v;
        for (uint256 j = c.finalLen; j > 0; --j) v = v.escale(xf).eadd(Pqzh.ldExt(c.finalPtr + (j - 1) * 8 * c.E, c.E));
        c.out ^= v ^ st[3];
        return st[2];
    }

    function _round(Ctx memory c, uint256 r, uint256[4] memory st, uint256 q) private view {
        uint256 g = gasleft();
        uint256 a = c.arity[r];
        uint256 h = st[1];
        uint256 s = _gather(c.ev, 1 << a, st[0] & ((1 << a) - 1), st[3], st[2], c.E);
        uint256 li = st[0] >> a;
        if (Pqzh.merkle(_leaf(c.ev, 1 << a, c.E), li, h - a, st[2] + s) != c.friRoots[r]) revert MerkleMismatch(100 + r, q);
        st[2] += s + 32 * (h - a);
        c.prof[8] += g - gasleft();
        g = gasleft();
        uint256 folded = Pqzh.fold(c.ev, a, c.betas[r], Pqzh.pw(c.tbl, li, h - a, 63 - a), c.E, c.tbl);
        c.prof[9] += g - gasleft();
        h -= a;
        if (c.used[h]) folded = folded.eadd(c.betaK[r].emul(c.ro[h], c.E));
        (st[0], st[1], st[3]) = (li, h, folded);
    }

    /// The row of k values: the verifier's own at `pos`, the k - 1 siblings from calldata `p`; returns their bytes.
    function _gather(uint256[] memory ev, uint256 k, uint256 pos, uint256 folded, uint256 p, uint256 E)
        private
        view
        returns (uint256 s)
    {
        for (uint256 j; j < k; ++j) {
            if (j == pos) {
                ev[j] = folded;
            } else {
                ev[j] = Pqzh.ldExt(p + s, E);
                s += 8 * E;
            }
        }
    }

    /// keccak256 of k ext values as E 8-byte big-endian coefficients each.
    function _leaf(uint256[] memory ev, uint256 k, uint256 E) private view returns (bytes32 h) {
        assembly ("memory-safe") {
            let f := mload(0x40)
            let o := f
            for { let j := 0 } lt(j, k) { j := add(j, 1) } {
                let v := mload(add(ev, shl(5, add(j, 1))))
                for { let i := 0 } lt(i, E) { i := add(i, 1) } {
                    mstore(o, shl(192, and(shr(shl(6, i), v), 0xffffffffffffffff)))
                    o := add(o, 8)
                }
            }
            h := keccak256(f, sub(o, f))
        }
    }
}
