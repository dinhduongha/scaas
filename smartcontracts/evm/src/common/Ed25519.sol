// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {Sha512} from "./Sha512.sol";

/// @title Ed25519 signature verification, strict RFC 8032 = ed25519-dalek `verify_strict`.
/// @notice Accepts iff `S < L`; `A` and `R` encode `y < p`; neither `A` nor `R` is a small-order point (y ∈ {0, 1,
///         p − 1, ±y₈}: this also covers `x = 0`, i.e. y = ±1, with the sign bit set); `A` decompresses; and the
///         cofactorless equation holds as dalek checks it: `encode([S]B + [k](−A)) == R` byte for byte, with
///         `k = SHA-512(R ‖ A ‖ M) mod L`. Comparing encodings rejects a non-canonical or off-curve `R` without
///         decompressing it. Never reverts on any input (out of gas aside): malformed input returns false.
///         One deviation from dalek, unreachable by honest keys: dalek's `verify_strict` does not require `A`'s `y < p`;
///         this library does (RFC 8032 §5.1.3, and the registry's key-data rule).
///
///         Arithmetic: field mod p = 2^255 − 19 with `mulmod`/`addmod` (2p < 2^256, so a sum of two reduced values is
///         added without reduction where it only feeds a `mulmod`); extended twisted Edwards coordinates (a = −1),
///         dbl-2008-hwcd / add-2008-hwcd-3 (hyperelliptic.org EFD); `[S]B + [k](−A)` by Straus–Shamir with 4-bit fixed
///         windows: one shared chain of 252 doublings, `jB` (j = 1..15) precomputed as affine (y + x, y − x, 2dxy)
///         constants, `j(−A)` computed per call in projective (Y + X, Y − X, 2dT, 2Z). Square root and inversion are
///         one MODEXP each. Scratch memory past the free memory pointer. UNAUDITED.
library Ed25519 {
    uint256 internal constant P = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed;
    uint256 internal constant L = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed;
    uint256 internal constant D = 0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3;
    uint256 internal constant D2 = 0x2406d9dc56dffce7198e80f2eef3d13000e0149a8283b156ebd69b9426b2f159;
    uint256 internal constant SQRT_M1 = 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0;
    /// y of the order-8 points (the others are ±y₈ with either x sign; order 4: y = 0; order 2: y = p − 1; identity: 1).
    uint256 internal constant Y8 = 0x05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826;
    uint256 private constant R256_MOD_L = 0x0ffffffffffffffffffffffffffffffec6ef5bf4737dcf70d6ec31748d98951d; // 2^256 mod L
    uint256 private constant MASK255 = (1 << 255) - 1;

    /// @param pk `A` (32 bytes, RFC 8032 encoding), @param message `M`, any length, @param r `R`, @param s `S` (the
    ///        signature is `r ‖ s`, `S` little-endian).
    function verify(bytes32 pk, bytes memory message, bytes32 r, bytes32 s) internal view returns (bool) {
        uint256 sv = _rev(uint256(s));
        if (sv >= L) return false;
        uint256 a = _rev(uint256(pk));
        uint256 ya = a & MASK255;
        uint256 rr = _rev(uint256(r));
        uint256 yr = rr & MASK255;
        if (ya >= P || yr >= P || smallOrderY(ya) || smallOrderY(yr)) return false;
        (bool ok, uint256 xa) = _recoverX(ya, a >> 255);
        if (!ok) return false;
        (bytes32 hhi, bytes32 hlo) = Sha512.hash(abi.encodePacked(r, pk, message));
        uint256 k = addmod(mulmod(_rev(uint256(hlo)), R256_MOD_L, L), _rev(uint256(hhi)), L);
        (uint256 x, uint256 y, uint256 z) = _straus(sv, k, P - xa, ya, P); // xa ≠ 0: x = 0 is small order
        uint256 zi;
        (ok, zi) = _modexp(z, P - 2);
        return ok && (mulmod(y, zi, P) | (mulmod(x, zi, P) & 1) << 255) == rr;
    }

    /// True iff a point with this `y` (< p) is of small order (the 8-torsion: y ∈ {0, 1, p − 1, y₈, p − y₈}).
    function smallOrderY(uint256 y) internal pure returns (bool) {
        return y < 2 || y == P - 1 || y == Y8 || y == P - Y8;
    }

    /// x of the point (x, y) with x's parity = `sign` (RFC 8032 §5.1.3): x = u·v³·(u·v⁷)^((p−5)/8), u = y² − 1,
    /// v = d·y² + 1, times √−1 if v·x² = −u; false if neither (not on the curve) or x = 0 with `sign` = 1.
    function _recoverX(uint256 y, uint256 sign) private view returns (bool ok, uint256 x) {
        uint256 yy = mulmod(y, y, P);
        uint256 u = addmod(yy, P - 1, P);
        uint256 v = addmod(mulmod(D, yy, P), 1, P);
        uint256 v3 = mulmod(mulmod(v, v, P), v, P);
        uint256 uv3 = mulmod(u, v3, P);
        (ok, x) = _modexp(mulmod(uv3, mulmod(v3, v, P), P), (P - 5) / 8);
        if (!ok) return (false, 0);
        x = mulmod(uv3, x, P);
        uint256 vxx = mulmod(v, mulmod(x, x, P), P);
        if (vxx != u) {
            if (vxx != P - u) return (false, 0); // u ≠ 0 here: y = ±1 is refused as small order first
            x = mulmod(x, SQRT_M1, P);
        }
        if (x == 0 && sign == 1) return (false, 0);
        if (x & 1 != sign) x = P - x;
    }

    /// `[s]B + [k]Q` with Q = (qx, qy) affine, s, k < 2^256 (here < L): projective (X, Y, Z).
    /// `p` = P as an argument: an opaque stack value (`DUP`, 3 gas); a literal `P` is rebuilt by the optimizer
    /// (runs = 200) as `sub(shl(255, 1), 19)`, 12 gas more per use.
    function _straus(uint256 s, uint256 k, uint256 qx, uint256 qy, uint256 p)
        private
        pure
        returns (uint256 x, uint256 y, uint256 z)
    {
        assembly ("memory-safe") {
            // 2·(X, Y, Z) -> (X, Y, Z, T) (dbl-2008-hwcd, a = −1); precomputation only, the main loop inlines it
            function dblt(x1, y1, z1, pp) -> x3, y3, z3, t3 {
                let a := mulmod(x1, x1, pp)
                let b := mulmod(y1, y1, pp)
                let c := mulmod(z1, z1, pp)
                c := addmod(c, c, pp)
                let h := addmod(a, b, pp)
                let e := add(mulmod(add(x1, y1), add(x1, y1), pp), sub(pp, h))
                let g := addmod(b, sub(pp, a), pp)
                let f := add(g, sub(pp, c))
                h := sub(pp, h)
                x3 := mulmod(e, f, pp)
                y3 := mulmod(g, h, pp)
                z3 := mulmod(f, g, pp)
                t3 := mulmod(e, h, pp)
            }
            // + the projective entry at e: (Y + X, Y − X, 2dT, 2Z)
            function addp(x1, y1, z1, t1, e, pp) -> x3, y3, z3, t3 {
                let a := mulmod(add(y1, sub(pp, x1)), mload(add(e, 0x20)), pp)
                let b := mulmod(add(y1, x1), mload(e), pp)
                let c := mulmod(t1, mload(add(e, 0x40)), pp)
                let d := mulmod(z1, mload(add(e, 0x60)), pp)
                let ee := add(b, sub(pp, a))
                let f := add(d, sub(pp, c))
                let g := add(d, c)
                let h := add(b, a)
                x3 := mulmod(ee, f, pp)
                y3 := mulmod(g, h, pp)
                z3 := mulmod(f, g, pp)
                t3 := mulmod(ee, h, pp)
            }
            // (X, Y, Z, T) as a projective entry at e
            function niels(x1, y1, z1, t1, e, pp) {
                mstore(e, add(y1, x1))
                mstore(add(e, 0x20), add(y1, sub(pp, x1)))
                mstore(add(e, 0x40), mulmod(t1, D2, pp))
                mstore(add(e, 0x60), add(z1, z1))
            }

            let qt := add(mload(0x40), 0x60) // jQ at qt + 128j, j = 1..15
            let bt := add(qt, 0x800) // jB at bt + 96j, j = 1..15
            mstore(add(bt, 96), 0x07cf9d3a33d4ba65270b4898643d42c2cf932dc6fb8c0e192fbc93c6f58c3b85)
            mstore(add(bt, 128), 0x44fd2f9298f81267a5c18434688f8a09fd399f05d140beb39d103905d740913e)
            mstore(add(bt, 160), 0x6f117b689f0c65a85a1b7dcbdd43598c26d9e823ccaac49eabc91205877aaa68)
            mstore(add(bt, 192), 0x590c063fa87d2e2e5aa69a65e1d607029f469d967a0ff5b59224e7fc933c71d7)
            mstore(add(bt, 224), 0x6bb595a669c92555e09e236bb16e37aa8f2b810c4e60acf68a99a56042b4d5a8)
            mstore(add(bt, 256), 0x701af5b13ea50b73500fa0840b3d6a3136c16bdd5d9acf7843faa8b3a59b7a5f)
            mstore(add(bt, 288), 0x7a164e1b9a80f8f4c11b50029f016732025a8430e8864b8aaf25b0a84cee9730)
            mstore(add(bt, 320), 0x2ab91587555bda628131f31a214bd6bd3bd353fde5c1ba7d56611fe8a4fcd265)
            mstore(add(bt, 352), 0x5a2826af12b9b4c6d170e5458cf2db4c589423221c35da6214ae933f0dd0d889)
            mstore(add(bt, 384), 0x680e910321e58727ca348d3dfb0a92656765c6f47dfd2538287351b98efc099f)
            mstore(add(bt, 416), 0x27933f4c7445a49ac3e8e3cd06a05073327e89715660faa995fe050a056818bf)
            mstore(add(bt, 448), 0x7f9d0cbf63553e2b5ddbdcf9102b44946e9e39457b5cc1725a13fbe9c476ff09)
            mstore(add(bt, 480), 0x2945ccf146e206ebdd1beb0c5abfec448d5048c3c75eed02a212bc4408a5bb33)
            mstore(add(bt, 512), 0x154a7e73eb1b55f3e33cf11cb864a087d50014d14b2729b77f9182c3a447d6ba)
            mstore(add(bt, 544), 0x43aabe696b3bb69ab41b670b1bbda72d270e0807d0bdd1fcbcbbdbf1812a8285)
            mstore(add(bt, 576), 0x51e57bb6a2cc38bd8065b668da59a7369b27158900c8af883a0ceeeb77157131)
            mstore(add(bt, 608), 0x38b64c41ae417884bb085ce7204553b9575be28427d22739499806b67b7d8ca4)
            mstore(add(bt, 640), 0x10b8e91a9f0d61e353e4a24b083bc144be70e00341a1bb0185ac326702ea4b71)
            mstore(add(bt, 672), 0x461bea69283c927e71b2528228542e497470353ab39dc0d26b1a5cd0944ea3bf)
            mstore(add(bt, 704), 0x1d6edd5d2e5317e09dea764f92192c3a6ca021533bba23a7ba6f2c9aaa3221b1)
            mstore(add(bt, 736), 0x7a9fbb1c6a0f90a7529c41ba5877adf3b3035f47053ea49af1836dc801b8b3a2)
            mstore(add(bt, 768), 0x0915e76061bce52fb1339c665ed9c3236cb30377e288702c59b7596604dd3e8f)
            mstore(add(bt, 800), 0x3a9024a1320e01c32c2741ac6e3c23fb963d7680e1b558f9e2a75dedf39234d9)
            mstore(add(bt, 832), 0x26907c5c2ecc4e95636412190eb62a32b8a371788bcca7d7e7c1f5d9c9a2911a)
            mstore(add(bt, 864), 0x34b9ed338add7f59ceb233c9c686f5b5a6509e6f51bc46c59b2e678aa6a8632f)
            mstore(add(bt, 896), 0x49c05a51fadc9c8f96cbc608e75eb04498a081b6f520419bf36e217e039d8064)
            mstore(add(bt, 928), 0x73c172021b008b06aaf6fc2993d4cf16e2ff83e8a719d22f06b4e8bf9045af1b)
            mstore(add(bt, 960), 0x43ac7628aae591ed0d5503639b55464645f534d41617e057ff1d93d2b360748e)
            mstore(add(bt, 992), 0x0353832c4950b70284739745f5dc395804f8183665a9f02f75f3558e227081dd)
            mstore(add(bt, 1024), 0x0ec62af470bf4ce7ff169f0f6731b5091d0c1ccbd3f06340d03d2ae403d0f8d8)
            mstore(add(bt, 1056), 0x4275aae2546d8faf113e847117703406e5d9fecf02302e272fbf00848a802ade)
            mstore(add(bt, 1088), 0x18ab598029d5c77fa3a075556a8deb953ed6b36977088381315f5b0249864348)
            mstore(add(bt, 1120), 0x3dc65522b53df94844311199b51a8622031eb4a13282e4a4d82b2cc5fd6089e9)
            mstore(add(bt, 1152), 0x078aafde8d3cdd5845ecdd2e701a6f9388de3dd7d834d1a9e2358042a71e7539)
            mstore(add(bt, 1184), 0x7956ece28a6022ed884dfb6e56d5dbdd23b2bf90ccb25b24856f8375b53d54b9)
            mstore(add(bt, 1216), 0x37c6a5151c83d0c6ffcb589af4976461f66cda23a24e180beea594d87f944553)
            mstore(add(bt, 1248), 0x234fd7eec346f241537a0e12fb07ba07bf84b39ab5bcdedbbf70c222a2007f6d)
            mstore(add(bt, 1280), 0x0267882d176024a79d12b232aaad5968aefcebc99b776f6b506f013b327fbf93)
            mstore(add(bt, 1312), 0x497ba6fdaa097863a2ef37f891a7e5332437e6b1df8dd4715360a119732ea378)
            mstore(add(bt, 1344), 0x6eaf60b2464d16301a474c042881bdd580277fc057efa98726f870ec3f213df2)
            mstore(add(bt, 1376), 0x2df0ea2c5b3c80d2112e56f16eec47a9ce69b20fdb7ca331dfdb8a44d4171280)
            mstore(add(bt, 1408), 0x24bf7e3cd8ba9c939c1fdf703ecb1baaf02397eda2a9bf5496a1c5877a1e1b82)
            mstore(add(bt, 1440), 0x61e22917f12de72b2dbdbdfac1f2d4d08648c28d189c246d24cecc0313cfeaa0)
            mstore(add(bt, 1472), 0x43b5cd4218d05ebf7508300807b25192d3829ba42a9910d6040bcd86468ccf0b)
            mstore(add(bt, 1504), 0x511d61210ae4d842032e5a7d93d64270eb38af4e373fdeee5d9a762f9bd0b516)
            // jQ: Q, 2Q, then + Q
            let t := mulmod(qx, qy, p)
            niels(qx, qy, 1, t, add(qt, 0x80), p)
            x, y, z, t := dblt(qx, qy, 1, p)
            niels(x, y, z, t, add(qt, 0x100), p)
            for { let j := 3 } lt(j, 16) { j := add(j, 1) } {
                x, y, z, t := addp(x, y, z, t, add(qt, 0x80), p)
                niels(x, y, z, t, add(qt, shl(7, j)), p)
            }
            // Straus: 4-bit windows from bits 252..255 down to 0..3, skipping leading windows that are 0 in both
            x := 0
            y := 1
            z := 1
            t := 0
            let i := 252
            for {} and(gt(i, 0), iszero(and(shr(i, or(k, s)), 15))) {} { i := sub(i, 4) }
            for {} 1 {} {
                let n := and(shr(i, k), 15)
                if n {
                    // + n(−A): projective entry (Y + X, Y − X, 2dT, 2Z)
                    n := add(qt, shl(7, n))
                    let a := mulmod(add(y, sub(p, x)), mload(add(n, 0x20)), p)
                    let b := mulmod(add(y, x), mload(n), p)
                    let c := mulmod(t, mload(add(n, 0x40)), p)
                    let d := mulmod(z, mload(add(n, 0x60)), p)
                    x := add(b, sub(p, a)) // E
                    y := add(d, c) // G
                    d := add(d, sub(p, c)) // F
                    b := add(b, a) // H
                    t := mulmod(x, b, p)
                    x := mulmod(x, d, p)
                    z := mulmod(d, y, p)
                    y := mulmod(y, b, p)
                }
                n := and(shr(i, s), 15)
                if n {
                    // + nB: affine entry (y + x, y − x, 2dxy), the window's last addition
                    n := add(bt, mul(96, n))
                    let a := mulmod(add(y, sub(p, x)), mload(add(n, 0x20)), p)
                    let b := mulmod(add(y, x), mload(n), p)
                    let c := mulmod(t, mload(add(n, 0x40)), p)
                    let d := addmod(z, z, p)
                    x := add(b, sub(p, a))
                    y := add(d, c)
                    d := add(d, sub(p, c))
                    b := add(b, a)
                    // no T: the next step is the doubling chain, whose last doubling recomputes it
                    x := mulmod(x, d, p)
                    z := mulmod(d, y, p)
                    y := mulmod(y, b, p)
                }
                if iszero(i) { break }
                i := sub(i, 4)
                // 4 doublings (dbl-2008-hwcd, a = −1): A = X², B = Y², C = 2Z², H' = A + B = −H, G = B − A,
                // E = (X + Y)² − H', F = G − C; X = E·F, Y = −G·H', Z = F·G (T = −E·H' only after the last)
                for { let j := 0 } lt(j, 3) { j := add(j, 1) } {
                    let a := mulmod(x, x, p)
                    let b := mulmod(y, y, p)
                    let c := mulmod(z, z, p)
                    let e := mulmod(add(x, y), add(x, y), p)
                    y := addmod(a, b, p) // H'
                    a := addmod(b, sub(p, a), p) // G
                    e := add(e, sub(p, y)) // E
                    c := add(a, sub(p, addmod(c, c, p))) // F
                    x := mulmod(e, c, p)
                    y := mulmod(a, sub(p, y), p)
                    z := mulmod(c, a, p)
                }
                {
                    let a := mulmod(x, x, p)
                    let b := mulmod(y, y, p)
                    let c := mulmod(z, z, p)
                    let e := mulmod(add(x, y), add(x, y), p)
                    y := sub(p, addmod(a, b, p)) // H
                    a := addmod(b, sub(p, a), p) // G
                    e := addmod(e, y, p) // E
                    c := add(a, sub(p, addmod(c, c, p))) // F
                    x := mulmod(e, c, p)
                    t := mulmod(e, y, p)
                    y := mulmod(a, y, p)
                    z := mulmod(c, a, p)
                }
            }
        }
    }

    /// `b^e mod p` via MODEXP (0x05); false if the call fails (out of gas), never reverts.
    function _modexp(uint256 b, uint256 e) private view returns (bool ok, uint256 r) {
        assembly ("memory-safe") {
            let m := mload(0x40)
            mstore(m, 32)
            mstore(add(m, 0x20), 32)
            mstore(add(m, 0x40), 32)
            mstore(add(m, 0x60), b)
            mstore(add(m, 0x80), e)
            mstore(add(m, 0xa0), P)
            ok := staticcall(gas(), 0x05, m, 0xc0, m, 0x20)
            ok := and(ok, eq(returndatasize(), 0x20)) // after the call: Yul evaluates arguments right to left
            r := mload(m)
        }
    }

    /// Byte reversal: RFC 8032 encodings are little-endian.
    function _rev(uint256 v) private pure returns (uint256) {
        v = ((v & 0xFF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00) >> 8)
            | ((v & 0x00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF00FF) << 8);
        v = ((v & 0xFFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000) >> 16)
            | ((v & 0x0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF0000FFFF) << 16);
        v = ((v & 0xFFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000) >> 32)
            | ((v & 0x00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF00000000FFFFFFFF) << 32);
        v = ((v & 0xFFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF0000000000000000) >> 64)
            | ((v & 0x0000000000000000FFFFFFFFFFFFFFFF0000000000000000FFFFFFFFFFFFFFFF) << 64);
        return (v >> 128) | (v << 128);
    }
}
