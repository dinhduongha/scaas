// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title SHAKE128 / SHAKE256 (FIPS 202) for the PQ verifiers: a Keccak-f[1600] sponge at fixed memory.
/// @notice The 25 lanes (A[x + 5y] at 0x80 + 32·(x + 5y), each a clean 64-bit value), the rho/pi temporaries, the
///         round constants and one padding block live in [0x80, END). `reserve()` claims that region and must be the
///         first allocation of the call frame (an external `verify`); otherwise it reverts `ShakeMemory`, never
///         corrupting memory. It assumes the legacy code generator (free memory pointer starts at 0x80); under via-IR
///         memory spilling every verify reverts `ShakeMemory`. The round body is unrolled from the FIPS 202 rotation table (theta, rho + pi, chi as Yul
///         functions to stay within the legacy code generator's stack); `reserve()` writes the 24 round constants.
/// @dev Byte order: a lane is the little-endian reading of its 8 bytes; `_bswap` reverses the bytes of the four
///      64-bit groups of a word, so a 32-byte read of the stream becomes four lanes and back.
library Shake {
    uint256 internal constant SHAKE128 = 168;
    uint256 internal constant SHAKE256 = 136;
    uint256 private constant S = 128;
    uint256 private constant RCT = 1728;
    uint256 private constant PAD = 0x9c0; // one padding block: 168 bytes + 56 slack
    uint256 internal constant END = 0xaa0;

    error ShakeMemory();

    function reserve() internal pure {
        assembly ("memory-safe") {
            if iszero(eq(mload(0x40), 0x80)) {
                mstore(0, 0xddb10a0e) // ShakeMemory()
                revert(0x1c, 4)
            }
            mstore(0x40, END)
            mstore(1728, 0x1)
            mstore(1760, 0x8082)
            mstore(1792, 0x800000000000808a)
            mstore(1824, 0x8000000080008000)
            mstore(1856, 0x808b)
            mstore(1888, 0x80000001)
            mstore(1920, 0x8000000080008081)
            mstore(1952, 0x8000000000008009)
            mstore(1984, 0x8a)
            mstore(2016, 0x88)
            mstore(2048, 0x80008009)
            mstore(2080, 0x8000000a)
            mstore(2112, 0x8000808b)
            mstore(2144, 0x800000000000008b)
            mstore(2176, 0x8000000000008089)
            mstore(2208, 0x8000000000008003)
            mstore(2240, 0x8000000000008002)
            mstore(2272, 0x8000000000000080)
            mstore(2304, 0x800a)
            mstore(2336, 0x800000008000000a)
            mstore(2368, 0x8000000080008081)
            mstore(2400, 0x8000000000008080)
            mstore(2432, 0x80000001)
            mstore(2464, 0x8000000080008008)
        }
    }

    /// Keccak-f[1600], 24 rounds (theta, rho + pi into the temporaries, chi back, iota).
    function permute() internal pure {
        assembly ("memory-safe") {
            function theta() -> d0, d1, d2, d3, d4 {
                mstore(928, xor(xor(xor(xor(mload(128), mload(288)), mload(448)), mload(608)), mload(768)))
                mstore(960, xor(xor(xor(xor(mload(160), mload(320)), mload(480)), mload(640)), mload(800)))
                mstore(992, xor(xor(xor(xor(mload(192), mload(352)), mload(512)), mload(672)), mload(832)))
                mstore(1024, xor(xor(xor(xor(mload(224), mload(384)), mload(544)), mload(704)), mload(864)))
                mstore(1056, xor(xor(xor(xor(mload(256), mload(416)), mload(576)), mload(736)), mload(896)))
                { let cp := mload(960) d0 := xor(mload(1056), and(or(shl(1, cp), shr(63, cp)), 0xffffffffffffffff)) }
                { let cp := mload(992) d1 := xor(mload(928), and(or(shl(1, cp), shr(63, cp)), 0xffffffffffffffff)) }
                { let cp := mload(1024) d2 := xor(mload(960), and(or(shl(1, cp), shr(63, cp)), 0xffffffffffffffff)) }
                { let cp := mload(1056) d3 := xor(mload(992), and(or(shl(1, cp), shr(63, cp)), 0xffffffffffffffff)) }
                { let cp := mload(928) d4 := xor(mload(1024), and(or(shl(1, cp), shr(63, cp)), 0xffffffffffffffff)) }
            }
            function rhoPi(d0, d1, d2, d3, d4) {
                mstore(928, xor(mload(128), d0))
                { let v := xor(mload(160), d1) mstore(1248, and(or(shl(1, v), shr(63, v)), 0xffffffffffffffff)) }
                { let v := xor(mload(192), d2) mstore(1568, and(or(shl(62, v), shr(2, v)), 0xffffffffffffffff)) }
                { let v := xor(mload(224), d3) mstore(1088, and(or(shl(28, v), shr(36, v)), 0xffffffffffffffff)) }
                { let v := xor(mload(256), d4) mstore(1408, and(or(shl(27, v), shr(37, v)), 0xffffffffffffffff)) }
                { let v := xor(mload(288), d0) mstore(1440, and(or(shl(36, v), shr(28, v)), 0xffffffffffffffff)) }
                { let v := xor(mload(320), d1) mstore(960, and(or(shl(44, v), shr(20, v)), 0xffffffffffffffff)) }
                { let v := xor(mload(352), d2) mstore(1280, and(or(shl(6, v), shr(58, v)), 0xffffffffffffffff)) }
                { let v := xor(mload(384), d3) mstore(1600, and(or(shl(55, v), shr(9, v)), 0xffffffffffffffff)) }
                { let v := xor(mload(416), d4) mstore(1120, and(or(shl(20, v), shr(44, v)), 0xffffffffffffffff)) }
                { let v := xor(mload(448), d0) mstore(1152, and(or(shl(3, v), shr(61, v)), 0xffffffffffffffff)) }
                { let v := xor(mload(480), d1) mstore(1472, and(or(shl(10, v), shr(54, v)), 0xffffffffffffffff)) }
                { let v := xor(mload(512), d2) mstore(992, and(or(shl(43, v), shr(21, v)), 0xffffffffffffffff)) }
                { let v := xor(mload(544), d3) mstore(1312, and(or(shl(25, v), shr(39, v)), 0xffffffffffffffff)) }
                { let v := xor(mload(576), d4) mstore(1632, and(or(shl(39, v), shr(25, v)), 0xffffffffffffffff)) }
                { let v := xor(mload(608), d0) mstore(1664, and(or(shl(41, v), shr(23, v)), 0xffffffffffffffff)) }
                { let v := xor(mload(640), d1) mstore(1184, and(or(shl(45, v), shr(19, v)), 0xffffffffffffffff)) }
                { let v := xor(mload(672), d2) mstore(1504, and(or(shl(15, v), shr(49, v)), 0xffffffffffffffff)) }
                { let v := xor(mload(704), d3) mstore(1024, and(or(shl(21, v), shr(43, v)), 0xffffffffffffffff)) }
                { let v := xor(mload(736), d4) mstore(1344, and(or(shl(8, v), shr(56, v)), 0xffffffffffffffff)) }
                { let v := xor(mload(768), d0) mstore(1376, and(or(shl(18, v), shr(46, v)), 0xffffffffffffffff)) }
                { let v := xor(mload(800), d1) mstore(1696, and(or(shl(2, v), shr(62, v)), 0xffffffffffffffff)) }
                { let v := xor(mload(832), d2) mstore(1216, and(or(shl(61, v), shr(3, v)), 0xffffffffffffffff)) }
                { let v := xor(mload(864), d3) mstore(1536, and(or(shl(56, v), shr(8, v)), 0xffffffffffffffff)) }
                { let v := xor(mload(896), d4) mstore(1056, and(or(shl(14, v), shr(50, v)), 0xffffffffffffffff)) }
            }
            function chi() {
                {
                    let b0 := mload(928)
                    let b1 := mload(960)
                    let b2 := mload(992)
                    let b3 := mload(1024)
                    let b4 := mload(1056)
                    mstore(128, xor(b0, and(not(b1), b2)))
                    mstore(160, xor(b1, and(not(b2), b3)))
                    mstore(192, xor(b2, and(not(b3), b4)))
                    mstore(224, xor(b3, and(not(b4), b0)))
                    mstore(256, xor(b4, and(not(b0), b1)))
                }
                {
                    let b0 := mload(1088)
                    let b1 := mload(1120)
                    let b2 := mload(1152)
                    let b3 := mload(1184)
                    let b4 := mload(1216)
                    mstore(288, xor(b0, and(not(b1), b2)))
                    mstore(320, xor(b1, and(not(b2), b3)))
                    mstore(352, xor(b2, and(not(b3), b4)))
                    mstore(384, xor(b3, and(not(b4), b0)))
                    mstore(416, xor(b4, and(not(b0), b1)))
                }
                {
                    let b0 := mload(1248)
                    let b1 := mload(1280)
                    let b2 := mload(1312)
                    let b3 := mload(1344)
                    let b4 := mload(1376)
                    mstore(448, xor(b0, and(not(b1), b2)))
                    mstore(480, xor(b1, and(not(b2), b3)))
                    mstore(512, xor(b2, and(not(b3), b4)))
                    mstore(544, xor(b3, and(not(b4), b0)))
                    mstore(576, xor(b4, and(not(b0), b1)))
                }
                {
                    let b0 := mload(1408)
                    let b1 := mload(1440)
                    let b2 := mload(1472)
                    let b3 := mload(1504)
                    let b4 := mload(1536)
                    mstore(608, xor(b0, and(not(b1), b2)))
                    mstore(640, xor(b1, and(not(b2), b3)))
                    mstore(672, xor(b2, and(not(b3), b4)))
                    mstore(704, xor(b3, and(not(b4), b0)))
                    mstore(736, xor(b4, and(not(b0), b1)))
                }
                {
                    let b0 := mload(1568)
                    let b1 := mload(1600)
                    let b2 := mload(1632)
                    let b3 := mload(1664)
                    let b4 := mload(1696)
                    mstore(768, xor(b0, and(not(b1), b2)))
                    mstore(800, xor(b1, and(not(b2), b3)))
                    mstore(832, xor(b2, and(not(b3), b4)))
                    mstore(864, xor(b3, and(not(b4), b0)))
                    mstore(896, xor(b4, and(not(b0), b1)))
                }
            }
            for { let r := 0 } lt(r, 24) { r := add(r, 1) } {
                let d0, d1, d2, d3, d4 := theta()
                rhoPi(d0, d1, d2, d3, d4)
                chi()
                mstore(128, xor(mload(128), mload(add(1728, shl(5, r)))))
            }
        }
    }

    /// Fresh sponge: absorbs `len` bytes at memory `p` with the SHAKE padding (0x1F … 0x80); the padded last block is
    /// XORed in but not permuted (every `squeeze` permutes first, so no permutation is wasted). Reverts `ShakeMemory`
    /// unless `reserve()` ran, checked by its side effects (the first two round constants, the free pointer ≥ `END`).
    function absorb(uint256 rate, uint256 p, uint256 len) internal pure {
        assembly ("memory-safe") {
            if iszero(and(and(eq(mload(1728), 0x1), eq(mload(1760), 0x8082)), iszero(lt(mload(0x40), END)))) {
                mstore(0, 0xddb10a0e) // ShakeMemory()
                revert(0x1c, 4)
            }
            for { let i := 0 } lt(i, 25) { i := add(i, 1) } { mstore(add(S, shl(5, i)), 0) }
        }
        while (len >= rate) {
            _xorBlock(rate, p);
            permute();
            p += rate;
            len -= rate;
        }
        assembly ("memory-safe") {
            for { let i := 0 } lt(i, 224) { i := add(i, 32) } { mstore(add(PAD, i), 0) }
            mcopy(PAD, p, len)
            mstore8(add(PAD, len), 0x1f)
            let last := add(PAD, sub(rate, 1))
            mstore8(last, xor(byte(0, mload(last)), 0x80))
        }
        _xorBlock(rate, PAD);
    }

    /// Permutes, then writes the next `rate` output bytes at `out` (it may write up to 31 bytes past them).
    function squeeze(uint256 rate, uint256 out) internal pure {
        permute();
        assembly ("memory-safe") {
            let n := shr(5, add(rate, 31))
            for { let m := 0 } lt(m, n) { m := add(m, 1) } {
                let l := add(S, shl(7, m))
                let w := or(or(shl(192, mload(l)), shl(128, mload(add(l, 32)))), or(shl(64, mload(add(l, 64))), mload(add(l, 96))))
                mstore(add(out, shl(5, m)), _bswap(w))
            }
            function _bswap(w) -> v {
                v := or(shr(8, and(w, 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00)), shl(8, and(w, 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff)))
                v := or(shr(16, and(v, 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000)), shl(16, and(v, 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff)))
                v := or(shr(32, and(v, 0xffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000)), shl(32, and(v, 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff)))
            }
        }
    }

    /// SHAKE over `len` bytes at `p`, `outLen` bytes written at `out` (whole blocks: up to rate + 31 bytes past).
    function hash(uint256 rate, uint256 p, uint256 len, uint256 out, uint256 outLen) internal pure {
        absorb(rate, p, len);
        for (uint256 o; o < outLen; o += rate) squeeze(rate, out + o);
    }

    function _xorBlock(uint256 rate, uint256 p) private pure {
        assembly ("memory-safe") {
            let lanes := shr(3, rate)
            for { let m := 0 } lt(shl(2, m), lanes) { m := add(m, 1) } {
                let w := mload(add(p, shl(5, m)))
                w := or(shr(8, and(w, 0xff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00)), shl(8, and(w, 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff)))
                w := or(shr(16, and(w, 0xffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000)), shl(16, and(w, 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff)))
                w := or(shr(32, and(w, 0xffffffff00000000ffffffff00000000ffffffff00000000ffffffff00000000)), shl(32, and(w, 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff)))
                for { let j := 0 } lt(j, 4) { j := add(j, 1) } {
                    let i := add(shl(2, m), j)
                    if lt(i, lanes) {
                        let a := add(S, shl(5, i))
                        mstore(a, xor(mload(a), and(shr(sub(192, shl(6, j)), w), 0xffffffffffffffff)))
                    }
                }
            }
        }
    }
}
