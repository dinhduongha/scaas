// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

/// @title SHA-512 (FIPS 180-4 §6.4) over a memory byte string.
/// @notice Pure Solidity/Yul: the EVM has no SHA-512 precompile. Each 64-bit word sits in a 256-bit stack slot and is
///         masked once per step (bits above 64 only carry upward); `rotr(x, n)` is the low 64 bits of `(x · (2^64 + 1)) >> n`. The 80 rounds are unrolled
///         with the round constants as literals and the a..h roles renamed per round (no variable shuffling); the
///         message schedule is expanded into scratch memory past the free memory pointer (not reserved; the padded copy
///         of the message lives there too). Gas is linear in ceil((len + 17) / 128) blocks. UNAUDITED.
library Sha512 {
    /// @return hi digest bytes 0..31, @return lo digest bytes 32..63 (the digest is `hi ‖ lo`).
    function hash(bytes memory data) internal pure returns (bytes32 hi, bytes32 lo) {
        assembly ("memory-safe") {
            let M := 0xffffffffffffffff
            let R := 0x10000000000000001 // x · R = x ‖ x for a 64-bit x
            let w := mload(0x40) // W[t] at w + 32t (80 words), then H0..H7 at w + 2560, then the padded message
            let buf := add(w, 2816)
            // padding: data ‖ 0x80 ‖ 0* ‖ u128 bit length, to a multiple of 128 bytes
            let len := mload(data)
            let end := add(buf, shl(7, shr(7, add(len, 144))))
            for { let q := add(buf, and(len, not(31))) } lt(q, end) { q := add(q, 32) } { mstore(q, 0) }
            mcopy(buf, add(data, 32), len)
            mstore8(add(buf, len), 0x80)
            mstore(sub(end, 32), or(mload(sub(end, 32)), shl(3, len)))

            mstore(add(w, 2560), 0x6a09e667f3bcc908)
            mstore(add(w, 2592), 0xbb67ae8584caa73b)
            mstore(add(w, 2624), 0x3c6ef372fe94f82b)
            mstore(add(w, 2656), 0xa54ff53a5f1d36f1)
            mstore(add(w, 2688), 0x510e527fade682d1)
            mstore(add(w, 2720), 0x9b05688c2b3e6c1f)
            mstore(add(w, 2752), 0x1f83d9abfb41bd6b)
            mstore(add(w, 2784), 0x5be0cd19137e2179)

            for { let blk := buf } lt(blk, end) { blk := add(blk, 128) } {
                // W[0..15]: the block's big-endian words; W[t] = σ1(W[t−2]) + W[t−7] + σ0(W[t−15]) + W[t−16]
                mstore(add(w, 0x0), shr(192, mload(add(blk, 0))))
                mstore(add(w, 0x20), shr(192, mload(add(blk, 8))))
                mstore(add(w, 0x40), shr(192, mload(add(blk, 16))))
                mstore(add(w, 0x60), shr(192, mload(add(blk, 24))))
                mstore(add(w, 0x80), shr(192, mload(add(blk, 32))))
                mstore(add(w, 0xa0), shr(192, mload(add(blk, 40))))
                mstore(add(w, 0xc0), shr(192, mload(add(blk, 48))))
                mstore(add(w, 0xe0), shr(192, mload(add(blk, 56))))
                mstore(add(w, 0x100), shr(192, mload(add(blk, 64))))
                mstore(add(w, 0x120), shr(192, mload(add(blk, 72))))
                mstore(add(w, 0x140), shr(192, mload(add(blk, 80))))
                mstore(add(w, 0x160), shr(192, mload(add(blk, 88))))
                mstore(add(w, 0x180), shr(192, mload(add(blk, 96))))
                mstore(add(w, 0x1a0), shr(192, mload(add(blk, 104))))
                mstore(add(w, 0x1c0), shr(192, mload(add(blk, 112))))
                mstore(add(w, 0x1e0), shr(192, mload(add(blk, 120))))
                {
                    let x
                    let y
                    x := mul(mload(add(w, 0x1c0)), R)
                    y := mul(mload(add(w, 0x20)), R)
                    mstore(
                        add(w, 0x200),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x120))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x0)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x1e0)), R)
                    y := mul(mload(add(w, 0x40)), R)
                    mstore(
                        add(w, 0x220),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x140))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x20)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x200)), R)
                    y := mul(mload(add(w, 0x60)), R)
                    mstore(
                        add(w, 0x240),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x160))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x40)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x220)), R)
                    y := mul(mload(add(w, 0x80)), R)
                    mstore(
                        add(w, 0x260),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x180))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x60)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x240)), R)
                    y := mul(mload(add(w, 0xa0)), R)
                    mstore(
                        add(w, 0x280),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x1a0))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x80)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x260)), R)
                    y := mul(mload(add(w, 0xc0)), R)
                    mstore(
                        add(w, 0x2a0),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x1c0))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0xa0)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x280)), R)
                    y := mul(mload(add(w, 0xe0)), R)
                    mstore(
                        add(w, 0x2c0),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x1e0))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0xc0)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x2a0)), R)
                    y := mul(mload(add(w, 0x100)), R)
                    mstore(
                        add(w, 0x2e0),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x200))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0xe0)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x2c0)), R)
                    y := mul(mload(add(w, 0x120)), R)
                    mstore(
                        add(w, 0x300),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x220))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x100)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x2e0)), R)
                    y := mul(mload(add(w, 0x140)), R)
                    mstore(
                        add(w, 0x320),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x240))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x120)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x300)), R)
                    y := mul(mload(add(w, 0x160)), R)
                    mstore(
                        add(w, 0x340),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x260))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x140)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x320)), R)
                    y := mul(mload(add(w, 0x180)), R)
                    mstore(
                        add(w, 0x360),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x280))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x160)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x340)), R)
                    y := mul(mload(add(w, 0x1a0)), R)
                    mstore(
                        add(w, 0x380),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x2a0))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x180)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x360)), R)
                    y := mul(mload(add(w, 0x1c0)), R)
                    mstore(
                        add(w, 0x3a0),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x2c0))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x1a0)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x380)), R)
                    y := mul(mload(add(w, 0x1e0)), R)
                    mstore(
                        add(w, 0x3c0),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x2e0))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x1c0)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x3a0)), R)
                    y := mul(mload(add(w, 0x200)), R)
                    mstore(
                        add(w, 0x3e0),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x300))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x1e0)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x3c0)), R)
                    y := mul(mload(add(w, 0x220)), R)
                    mstore(
                        add(w, 0x400),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x320))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x200)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x3e0)), R)
                    y := mul(mload(add(w, 0x240)), R)
                    mstore(
                        add(w, 0x420),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x340))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x220)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x400)), R)
                    y := mul(mload(add(w, 0x260)), R)
                    mstore(
                        add(w, 0x440),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x360))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x240)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x420)), R)
                    y := mul(mload(add(w, 0x280)), R)
                    mstore(
                        add(w, 0x460),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x380))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x260)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x440)), R)
                    y := mul(mload(add(w, 0x2a0)), R)
                    mstore(
                        add(w, 0x480),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x3a0))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x280)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x460)), R)
                    y := mul(mload(add(w, 0x2c0)), R)
                    mstore(
                        add(w, 0x4a0),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x3c0))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x2a0)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x480)), R)
                    y := mul(mload(add(w, 0x2e0)), R)
                    mstore(
                        add(w, 0x4c0),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x3e0))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x2c0)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x4a0)), R)
                    y := mul(mload(add(w, 0x300)), R)
                    mstore(
                        add(w, 0x4e0),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x400))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x2e0)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x4c0)), R)
                    y := mul(mload(add(w, 0x320)), R)
                    mstore(
                        add(w, 0x500),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x420))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x300)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x4e0)), R)
                    y := mul(mload(add(w, 0x340)), R)
                    mstore(
                        add(w, 0x520),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x440))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x320)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x500)), R)
                    y := mul(mload(add(w, 0x360)), R)
                    mstore(
                        add(w, 0x540),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x460))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x340)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x520)), R)
                    y := mul(mload(add(w, 0x380)), R)
                    mstore(
                        add(w, 0x560),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x480))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x360)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x540)), R)
                    y := mul(mload(add(w, 0x3a0)), R)
                    mstore(
                        add(w, 0x580),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x4a0))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x380)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x560)), R)
                    y := mul(mload(add(w, 0x3c0)), R)
                    mstore(
                        add(w, 0x5a0),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x4c0))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x3a0)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x580)), R)
                    y := mul(mload(add(w, 0x3e0)), R)
                    mstore(
                        add(w, 0x5c0),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x4e0))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x3c0)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x5a0)), R)
                    y := mul(mload(add(w, 0x400)), R)
                    mstore(
                        add(w, 0x5e0),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x500))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x3e0)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x5c0)), R)
                    y := mul(mload(add(w, 0x420)), R)
                    mstore(
                        add(w, 0x600),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x520))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x400)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x5e0)), R)
                    y := mul(mload(add(w, 0x440)), R)
                    mstore(
                        add(w, 0x620),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x540))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x420)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x600)), R)
                    y := mul(mload(add(w, 0x460)), R)
                    mstore(
                        add(w, 0x640),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x560))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x440)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x620)), R)
                    y := mul(mload(add(w, 0x480)), R)
                    mstore(
                        add(w, 0x660),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x580))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x460)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x640)), R)
                    y := mul(mload(add(w, 0x4a0)), R)
                    mstore(
                        add(w, 0x680),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x5a0))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x480)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x660)), R)
                    y := mul(mload(add(w, 0x4c0)), R)
                    mstore(
                        add(w, 0x6a0),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x5c0))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x4a0)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x680)), R)
                    y := mul(mload(add(w, 0x4e0)), R)
                    mstore(
                        add(w, 0x6c0),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x5e0))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x4c0)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x6a0)), R)
                    y := mul(mload(add(w, 0x500)), R)
                    mstore(
                        add(w, 0x6e0),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x600))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x4e0)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x6c0)), R)
                    y := mul(mload(add(w, 0x520)), R)
                    mstore(
                        add(w, 0x700),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x620))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x500)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x6e0)), R)
                    y := mul(mload(add(w, 0x540)), R)
                    mstore(
                        add(w, 0x720),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x640))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x520)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x700)), R)
                    y := mul(mload(add(w, 0x560)), R)
                    mstore(
                        add(w, 0x740),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x660))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x540)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x720)), R)
                    y := mul(mload(add(w, 0x580)), R)
                    mstore(
                        add(w, 0x760),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x680))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x560)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x740)), R)
                    y := mul(mload(add(w, 0x5a0)), R)
                    mstore(
                        add(w, 0x780),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x6a0))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x580)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x760)), R)
                    y := mul(mload(add(w, 0x5c0)), R)
                    mstore(
                        add(w, 0x7a0),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x6c0))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x5a0)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x780)), R)
                    y := mul(mload(add(w, 0x5e0)), R)
                    mstore(
                        add(w, 0x7c0),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x6e0))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x5c0)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x7a0)), R)
                    y := mul(mload(add(w, 0x600)), R)
                    mstore(
                        add(w, 0x7e0),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x700))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x5e0)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x7c0)), R)
                    y := mul(mload(add(w, 0x620)), R)
                    mstore(
                        add(w, 0x800),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x720))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x600)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x7e0)), R)
                    y := mul(mload(add(w, 0x640)), R)
                    mstore(
                        add(w, 0x820),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x740))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x620)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x800)), R)
                    y := mul(mload(add(w, 0x660)), R)
                    mstore(
                        add(w, 0x840),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x760))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x640)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x820)), R)
                    y := mul(mload(add(w, 0x680)), R)
                    mstore(
                        add(w, 0x860),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x780))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x660)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x840)), R)
                    y := mul(mload(add(w, 0x6a0)), R)
                    mstore(
                        add(w, 0x880),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x7a0))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x680)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x860)), R)
                    y := mul(mload(add(w, 0x6c0)), R)
                    mstore(
                        add(w, 0x8a0),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x7c0))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x6a0)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x880)), R)
                    y := mul(mload(add(w, 0x6e0)), R)
                    mstore(
                        add(w, 0x8c0),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x7e0))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x6c0)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x8a0)), R)
                    y := mul(mload(add(w, 0x700)), R)
                    mstore(
                        add(w, 0x8e0),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x800))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x6e0)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x8c0)), R)
                    y := mul(mload(add(w, 0x720)), R)
                    mstore(
                        add(w, 0x900),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x820))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x700)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x8e0)), R)
                    y := mul(mload(add(w, 0x740)), R)
                    mstore(
                        add(w, 0x920),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x840))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x720)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x900)), R)
                    y := mul(mload(add(w, 0x760)), R)
                    mstore(
                        add(w, 0x940),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x860))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x740)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x920)), R)
                    y := mul(mload(add(w, 0x780)), R)
                    mstore(
                        add(w, 0x960),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x880))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x760)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x940)), R)
                    y := mul(mload(add(w, 0x7a0)), R)
                    mstore(
                        add(w, 0x980),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x8a0))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x780)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x960)), R)
                    y := mul(mload(add(w, 0x7c0)), R)
                    mstore(
                        add(w, 0x9a0),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x8c0))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x7a0)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x980)), R)
                    y := mul(mload(add(w, 0x7e0)), R)
                    mstore(
                        add(w, 0x9c0),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x8e0))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x7c0)))
                            ),
                            M
                        )
                    )
                    x := mul(mload(add(w, 0x9a0)), R)
                    y := mul(mload(add(w, 0x800)), R)
                    mstore(
                        add(w, 0x9e0),
                        and(
                            add(
                                add(xor(xor(shr(19, x), shr(61, x)), shr(70, x)), mload(add(w, 0x900))),
                                add(xor(xor(shr(1, y), shr(8, y)), shr(71, y)), mload(add(w, 0x7e0)))
                            ),
                            M
                        )
                    )
                }
                let a := mload(add(w, 2560))
                let b := mload(add(w, 2592))
                let c := mload(add(w, 2624))
                let d := mload(add(w, 2656))
                let e := mload(add(w, 2688))
                let f := mload(add(w, 2720))
                let g := mload(add(w, 2752))
                let h := mload(add(w, 2784))
                let x
                // t = 0
                x := mul(e, R)
                h :=
                    add(
                        h,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(g, and(e, xor(f, g)))),
                            add(0x428a2f98d728ae22, mload(add(w, 0x0)))
                        )
                    )
                d := and(add(d, h), M)
                x := mul(a, R)
                h := and(add(h, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(a, b), and(c, or(a, b))))), M)
                // t = 1
                x := mul(d, R)
                g :=
                    add(
                        g,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(f, and(d, xor(e, f)))),
                            add(0x7137449123ef65cd, mload(add(w, 0x20)))
                        )
                    )
                c := and(add(c, g), M)
                x := mul(h, R)
                g := and(add(g, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(h, a), and(b, or(h, a))))), M)
                // t = 2
                x := mul(c, R)
                f :=
                    add(
                        f,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(e, and(c, xor(d, e)))),
                            add(0xb5c0fbcfec4d3b2f, mload(add(w, 0x40)))
                        )
                    )
                b := and(add(b, f), M)
                x := mul(g, R)
                f := and(add(f, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(g, h), and(a, or(g, h))))), M)
                // t = 3
                x := mul(b, R)
                e :=
                    add(
                        e,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(d, and(b, xor(c, d)))),
                            add(0xe9b5dba58189dbbc, mload(add(w, 0x60)))
                        )
                    )
                a := and(add(a, e), M)
                x := mul(f, R)
                e := and(add(e, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(f, g), and(h, or(f, g))))), M)
                // t = 4
                x := mul(a, R)
                d :=
                    add(
                        d,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(c, and(a, xor(b, c)))),
                            add(0x3956c25bf348b538, mload(add(w, 0x80)))
                        )
                    )
                h := and(add(h, d), M)
                x := mul(e, R)
                d := and(add(d, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(e, f), and(g, or(e, f))))), M)
                // t = 5
                x := mul(h, R)
                c :=
                    add(
                        c,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(b, and(h, xor(a, b)))),
                            add(0x59f111f1b605d019, mload(add(w, 0xa0)))
                        )
                    )
                g := and(add(g, c), M)
                x := mul(d, R)
                c := and(add(c, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(d, e), and(f, or(d, e))))), M)
                // t = 6
                x := mul(g, R)
                b :=
                    add(
                        b,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(a, and(g, xor(h, a)))),
                            add(0x923f82a4af194f9b, mload(add(w, 0xc0)))
                        )
                    )
                f := and(add(f, b), M)
                x := mul(c, R)
                b := and(add(b, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(c, d), and(e, or(c, d))))), M)
                // t = 7
                x := mul(f, R)
                a :=
                    add(
                        a,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(h, and(f, xor(g, h)))),
                            add(0xab1c5ed5da6d8118, mload(add(w, 0xe0)))
                        )
                    )
                e := and(add(e, a), M)
                x := mul(b, R)
                a := and(add(a, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(b, c), and(d, or(b, c))))), M)
                // t = 8
                x := mul(e, R)
                h :=
                    add(
                        h,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(g, and(e, xor(f, g)))),
                            add(0xd807aa98a3030242, mload(add(w, 0x100)))
                        )
                    )
                d := and(add(d, h), M)
                x := mul(a, R)
                h := and(add(h, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(a, b), and(c, or(a, b))))), M)
                // t = 9
                x := mul(d, R)
                g :=
                    add(
                        g,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(f, and(d, xor(e, f)))),
                            add(0x12835b0145706fbe, mload(add(w, 0x120)))
                        )
                    )
                c := and(add(c, g), M)
                x := mul(h, R)
                g := and(add(g, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(h, a), and(b, or(h, a))))), M)
                // t = 10
                x := mul(c, R)
                f :=
                    add(
                        f,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(e, and(c, xor(d, e)))),
                            add(0x243185be4ee4b28c, mload(add(w, 0x140)))
                        )
                    )
                b := and(add(b, f), M)
                x := mul(g, R)
                f := and(add(f, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(g, h), and(a, or(g, h))))), M)
                // t = 11
                x := mul(b, R)
                e :=
                    add(
                        e,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(d, and(b, xor(c, d)))),
                            add(0x550c7dc3d5ffb4e2, mload(add(w, 0x160)))
                        )
                    )
                a := and(add(a, e), M)
                x := mul(f, R)
                e := and(add(e, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(f, g), and(h, or(f, g))))), M)
                // t = 12
                x := mul(a, R)
                d :=
                    add(
                        d,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(c, and(a, xor(b, c)))),
                            add(0x72be5d74f27b896f, mload(add(w, 0x180)))
                        )
                    )
                h := and(add(h, d), M)
                x := mul(e, R)
                d := and(add(d, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(e, f), and(g, or(e, f))))), M)
                // t = 13
                x := mul(h, R)
                c :=
                    add(
                        c,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(b, and(h, xor(a, b)))),
                            add(0x80deb1fe3b1696b1, mload(add(w, 0x1a0)))
                        )
                    )
                g := and(add(g, c), M)
                x := mul(d, R)
                c := and(add(c, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(d, e), and(f, or(d, e))))), M)
                // t = 14
                x := mul(g, R)
                b :=
                    add(
                        b,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(a, and(g, xor(h, a)))),
                            add(0x9bdc06a725c71235, mload(add(w, 0x1c0)))
                        )
                    )
                f := and(add(f, b), M)
                x := mul(c, R)
                b := and(add(b, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(c, d), and(e, or(c, d))))), M)
                // t = 15
                x := mul(f, R)
                a :=
                    add(
                        a,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(h, and(f, xor(g, h)))),
                            add(0xc19bf174cf692694, mload(add(w, 0x1e0)))
                        )
                    )
                e := and(add(e, a), M)
                x := mul(b, R)
                a := and(add(a, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(b, c), and(d, or(b, c))))), M)
                // t = 16
                x := mul(e, R)
                h :=
                    add(
                        h,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(g, and(e, xor(f, g)))),
                            add(0xe49b69c19ef14ad2, mload(add(w, 0x200)))
                        )
                    )
                d := and(add(d, h), M)
                x := mul(a, R)
                h := and(add(h, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(a, b), and(c, or(a, b))))), M)
                // t = 17
                x := mul(d, R)
                g :=
                    add(
                        g,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(f, and(d, xor(e, f)))),
                            add(0xefbe4786384f25e3, mload(add(w, 0x220)))
                        )
                    )
                c := and(add(c, g), M)
                x := mul(h, R)
                g := and(add(g, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(h, a), and(b, or(h, a))))), M)
                // t = 18
                x := mul(c, R)
                f :=
                    add(
                        f,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(e, and(c, xor(d, e)))),
                            add(0x0fc19dc68b8cd5b5, mload(add(w, 0x240)))
                        )
                    )
                b := and(add(b, f), M)
                x := mul(g, R)
                f := and(add(f, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(g, h), and(a, or(g, h))))), M)
                // t = 19
                x := mul(b, R)
                e :=
                    add(
                        e,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(d, and(b, xor(c, d)))),
                            add(0x240ca1cc77ac9c65, mload(add(w, 0x260)))
                        )
                    )
                a := and(add(a, e), M)
                x := mul(f, R)
                e := and(add(e, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(f, g), and(h, or(f, g))))), M)
                // t = 20
                x := mul(a, R)
                d :=
                    add(
                        d,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(c, and(a, xor(b, c)))),
                            add(0x2de92c6f592b0275, mload(add(w, 0x280)))
                        )
                    )
                h := and(add(h, d), M)
                x := mul(e, R)
                d := and(add(d, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(e, f), and(g, or(e, f))))), M)
                // t = 21
                x := mul(h, R)
                c :=
                    add(
                        c,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(b, and(h, xor(a, b)))),
                            add(0x4a7484aa6ea6e483, mload(add(w, 0x2a0)))
                        )
                    )
                g := and(add(g, c), M)
                x := mul(d, R)
                c := and(add(c, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(d, e), and(f, or(d, e))))), M)
                // t = 22
                x := mul(g, R)
                b :=
                    add(
                        b,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(a, and(g, xor(h, a)))),
                            add(0x5cb0a9dcbd41fbd4, mload(add(w, 0x2c0)))
                        )
                    )
                f := and(add(f, b), M)
                x := mul(c, R)
                b := and(add(b, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(c, d), and(e, or(c, d))))), M)
                // t = 23
                x := mul(f, R)
                a :=
                    add(
                        a,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(h, and(f, xor(g, h)))),
                            add(0x76f988da831153b5, mload(add(w, 0x2e0)))
                        )
                    )
                e := and(add(e, a), M)
                x := mul(b, R)
                a := and(add(a, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(b, c), and(d, or(b, c))))), M)
                // t = 24
                x := mul(e, R)
                h :=
                    add(
                        h,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(g, and(e, xor(f, g)))),
                            add(0x983e5152ee66dfab, mload(add(w, 0x300)))
                        )
                    )
                d := and(add(d, h), M)
                x := mul(a, R)
                h := and(add(h, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(a, b), and(c, or(a, b))))), M)
                // t = 25
                x := mul(d, R)
                g :=
                    add(
                        g,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(f, and(d, xor(e, f)))),
                            add(0xa831c66d2db43210, mload(add(w, 0x320)))
                        )
                    )
                c := and(add(c, g), M)
                x := mul(h, R)
                g := and(add(g, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(h, a), and(b, or(h, a))))), M)
                // t = 26
                x := mul(c, R)
                f :=
                    add(
                        f,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(e, and(c, xor(d, e)))),
                            add(0xb00327c898fb213f, mload(add(w, 0x340)))
                        )
                    )
                b := and(add(b, f), M)
                x := mul(g, R)
                f := and(add(f, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(g, h), and(a, or(g, h))))), M)
                // t = 27
                x := mul(b, R)
                e :=
                    add(
                        e,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(d, and(b, xor(c, d)))),
                            add(0xbf597fc7beef0ee4, mload(add(w, 0x360)))
                        )
                    )
                a := and(add(a, e), M)
                x := mul(f, R)
                e := and(add(e, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(f, g), and(h, or(f, g))))), M)
                // t = 28
                x := mul(a, R)
                d :=
                    add(
                        d,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(c, and(a, xor(b, c)))),
                            add(0xc6e00bf33da88fc2, mload(add(w, 0x380)))
                        )
                    )
                h := and(add(h, d), M)
                x := mul(e, R)
                d := and(add(d, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(e, f), and(g, or(e, f))))), M)
                // t = 29
                x := mul(h, R)
                c :=
                    add(
                        c,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(b, and(h, xor(a, b)))),
                            add(0xd5a79147930aa725, mload(add(w, 0x3a0)))
                        )
                    )
                g := and(add(g, c), M)
                x := mul(d, R)
                c := and(add(c, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(d, e), and(f, or(d, e))))), M)
                // t = 30
                x := mul(g, R)
                b :=
                    add(
                        b,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(a, and(g, xor(h, a)))),
                            add(0x06ca6351e003826f, mload(add(w, 0x3c0)))
                        )
                    )
                f := and(add(f, b), M)
                x := mul(c, R)
                b := and(add(b, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(c, d), and(e, or(c, d))))), M)
                // t = 31
                x := mul(f, R)
                a :=
                    add(
                        a,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(h, and(f, xor(g, h)))),
                            add(0x142929670a0e6e70, mload(add(w, 0x3e0)))
                        )
                    )
                e := and(add(e, a), M)
                x := mul(b, R)
                a := and(add(a, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(b, c), and(d, or(b, c))))), M)
                // t = 32
                x := mul(e, R)
                h :=
                    add(
                        h,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(g, and(e, xor(f, g)))),
                            add(0x27b70a8546d22ffc, mload(add(w, 0x400)))
                        )
                    )
                d := and(add(d, h), M)
                x := mul(a, R)
                h := and(add(h, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(a, b), and(c, or(a, b))))), M)
                // t = 33
                x := mul(d, R)
                g :=
                    add(
                        g,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(f, and(d, xor(e, f)))),
                            add(0x2e1b21385c26c926, mload(add(w, 0x420)))
                        )
                    )
                c := and(add(c, g), M)
                x := mul(h, R)
                g := and(add(g, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(h, a), and(b, or(h, a))))), M)
                // t = 34
                x := mul(c, R)
                f :=
                    add(
                        f,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(e, and(c, xor(d, e)))),
                            add(0x4d2c6dfc5ac42aed, mload(add(w, 0x440)))
                        )
                    )
                b := and(add(b, f), M)
                x := mul(g, R)
                f := and(add(f, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(g, h), and(a, or(g, h))))), M)
                // t = 35
                x := mul(b, R)
                e :=
                    add(
                        e,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(d, and(b, xor(c, d)))),
                            add(0x53380d139d95b3df, mload(add(w, 0x460)))
                        )
                    )
                a := and(add(a, e), M)
                x := mul(f, R)
                e := and(add(e, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(f, g), and(h, or(f, g))))), M)
                // t = 36
                x := mul(a, R)
                d :=
                    add(
                        d,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(c, and(a, xor(b, c)))),
                            add(0x650a73548baf63de, mload(add(w, 0x480)))
                        )
                    )
                h := and(add(h, d), M)
                x := mul(e, R)
                d := and(add(d, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(e, f), and(g, or(e, f))))), M)
                // t = 37
                x := mul(h, R)
                c :=
                    add(
                        c,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(b, and(h, xor(a, b)))),
                            add(0x766a0abb3c77b2a8, mload(add(w, 0x4a0)))
                        )
                    )
                g := and(add(g, c), M)
                x := mul(d, R)
                c := and(add(c, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(d, e), and(f, or(d, e))))), M)
                // t = 38
                x := mul(g, R)
                b :=
                    add(
                        b,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(a, and(g, xor(h, a)))),
                            add(0x81c2c92e47edaee6, mload(add(w, 0x4c0)))
                        )
                    )
                f := and(add(f, b), M)
                x := mul(c, R)
                b := and(add(b, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(c, d), and(e, or(c, d))))), M)
                // t = 39
                x := mul(f, R)
                a :=
                    add(
                        a,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(h, and(f, xor(g, h)))),
                            add(0x92722c851482353b, mload(add(w, 0x4e0)))
                        )
                    )
                e := and(add(e, a), M)
                x := mul(b, R)
                a := and(add(a, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(b, c), and(d, or(b, c))))), M)
                // t = 40
                x := mul(e, R)
                h :=
                    add(
                        h,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(g, and(e, xor(f, g)))),
                            add(0xa2bfe8a14cf10364, mload(add(w, 0x500)))
                        )
                    )
                d := and(add(d, h), M)
                x := mul(a, R)
                h := and(add(h, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(a, b), and(c, or(a, b))))), M)
                // t = 41
                x := mul(d, R)
                g :=
                    add(
                        g,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(f, and(d, xor(e, f)))),
                            add(0xa81a664bbc423001, mload(add(w, 0x520)))
                        )
                    )
                c := and(add(c, g), M)
                x := mul(h, R)
                g := and(add(g, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(h, a), and(b, or(h, a))))), M)
                // t = 42
                x := mul(c, R)
                f :=
                    add(
                        f,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(e, and(c, xor(d, e)))),
                            add(0xc24b8b70d0f89791, mload(add(w, 0x540)))
                        )
                    )
                b := and(add(b, f), M)
                x := mul(g, R)
                f := and(add(f, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(g, h), and(a, or(g, h))))), M)
                // t = 43
                x := mul(b, R)
                e :=
                    add(
                        e,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(d, and(b, xor(c, d)))),
                            add(0xc76c51a30654be30, mload(add(w, 0x560)))
                        )
                    )
                a := and(add(a, e), M)
                x := mul(f, R)
                e := and(add(e, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(f, g), and(h, or(f, g))))), M)
                // t = 44
                x := mul(a, R)
                d :=
                    add(
                        d,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(c, and(a, xor(b, c)))),
                            add(0xd192e819d6ef5218, mload(add(w, 0x580)))
                        )
                    )
                h := and(add(h, d), M)
                x := mul(e, R)
                d := and(add(d, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(e, f), and(g, or(e, f))))), M)
                // t = 45
                x := mul(h, R)
                c :=
                    add(
                        c,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(b, and(h, xor(a, b)))),
                            add(0xd69906245565a910, mload(add(w, 0x5a0)))
                        )
                    )
                g := and(add(g, c), M)
                x := mul(d, R)
                c := and(add(c, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(d, e), and(f, or(d, e))))), M)
                // t = 46
                x := mul(g, R)
                b :=
                    add(
                        b,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(a, and(g, xor(h, a)))),
                            add(0xf40e35855771202a, mload(add(w, 0x5c0)))
                        )
                    )
                f := and(add(f, b), M)
                x := mul(c, R)
                b := and(add(b, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(c, d), and(e, or(c, d))))), M)
                // t = 47
                x := mul(f, R)
                a :=
                    add(
                        a,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(h, and(f, xor(g, h)))),
                            add(0x106aa07032bbd1b8, mload(add(w, 0x5e0)))
                        )
                    )
                e := and(add(e, a), M)
                x := mul(b, R)
                a := and(add(a, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(b, c), and(d, or(b, c))))), M)
                // t = 48
                x := mul(e, R)
                h :=
                    add(
                        h,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(g, and(e, xor(f, g)))),
                            add(0x19a4c116b8d2d0c8, mload(add(w, 0x600)))
                        )
                    )
                d := and(add(d, h), M)
                x := mul(a, R)
                h := and(add(h, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(a, b), and(c, or(a, b))))), M)
                // t = 49
                x := mul(d, R)
                g :=
                    add(
                        g,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(f, and(d, xor(e, f)))),
                            add(0x1e376c085141ab53, mload(add(w, 0x620)))
                        )
                    )
                c := and(add(c, g), M)
                x := mul(h, R)
                g := and(add(g, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(h, a), and(b, or(h, a))))), M)
                // t = 50
                x := mul(c, R)
                f :=
                    add(
                        f,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(e, and(c, xor(d, e)))),
                            add(0x2748774cdf8eeb99, mload(add(w, 0x640)))
                        )
                    )
                b := and(add(b, f), M)
                x := mul(g, R)
                f := and(add(f, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(g, h), and(a, or(g, h))))), M)
                // t = 51
                x := mul(b, R)
                e :=
                    add(
                        e,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(d, and(b, xor(c, d)))),
                            add(0x34b0bcb5e19b48a8, mload(add(w, 0x660)))
                        )
                    )
                a := and(add(a, e), M)
                x := mul(f, R)
                e := and(add(e, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(f, g), and(h, or(f, g))))), M)
                // t = 52
                x := mul(a, R)
                d :=
                    add(
                        d,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(c, and(a, xor(b, c)))),
                            add(0x391c0cb3c5c95a63, mload(add(w, 0x680)))
                        )
                    )
                h := and(add(h, d), M)
                x := mul(e, R)
                d := and(add(d, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(e, f), and(g, or(e, f))))), M)
                // t = 53
                x := mul(h, R)
                c :=
                    add(
                        c,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(b, and(h, xor(a, b)))),
                            add(0x4ed8aa4ae3418acb, mload(add(w, 0x6a0)))
                        )
                    )
                g := and(add(g, c), M)
                x := mul(d, R)
                c := and(add(c, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(d, e), and(f, or(d, e))))), M)
                // t = 54
                x := mul(g, R)
                b :=
                    add(
                        b,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(a, and(g, xor(h, a)))),
                            add(0x5b9cca4f7763e373, mload(add(w, 0x6c0)))
                        )
                    )
                f := and(add(f, b), M)
                x := mul(c, R)
                b := and(add(b, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(c, d), and(e, or(c, d))))), M)
                // t = 55
                x := mul(f, R)
                a :=
                    add(
                        a,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(h, and(f, xor(g, h)))),
                            add(0x682e6ff3d6b2b8a3, mload(add(w, 0x6e0)))
                        )
                    )
                e := and(add(e, a), M)
                x := mul(b, R)
                a := and(add(a, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(b, c), and(d, or(b, c))))), M)
                // t = 56
                x := mul(e, R)
                h :=
                    add(
                        h,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(g, and(e, xor(f, g)))),
                            add(0x748f82ee5defb2fc, mload(add(w, 0x700)))
                        )
                    )
                d := and(add(d, h), M)
                x := mul(a, R)
                h := and(add(h, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(a, b), and(c, or(a, b))))), M)
                // t = 57
                x := mul(d, R)
                g :=
                    add(
                        g,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(f, and(d, xor(e, f)))),
                            add(0x78a5636f43172f60, mload(add(w, 0x720)))
                        )
                    )
                c := and(add(c, g), M)
                x := mul(h, R)
                g := and(add(g, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(h, a), and(b, or(h, a))))), M)
                // t = 58
                x := mul(c, R)
                f :=
                    add(
                        f,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(e, and(c, xor(d, e)))),
                            add(0x84c87814a1f0ab72, mload(add(w, 0x740)))
                        )
                    )
                b := and(add(b, f), M)
                x := mul(g, R)
                f := and(add(f, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(g, h), and(a, or(g, h))))), M)
                // t = 59
                x := mul(b, R)
                e :=
                    add(
                        e,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(d, and(b, xor(c, d)))),
                            add(0x8cc702081a6439ec, mload(add(w, 0x760)))
                        )
                    )
                a := and(add(a, e), M)
                x := mul(f, R)
                e := and(add(e, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(f, g), and(h, or(f, g))))), M)
                // t = 60
                x := mul(a, R)
                d :=
                    add(
                        d,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(c, and(a, xor(b, c)))),
                            add(0x90befffa23631e28, mload(add(w, 0x780)))
                        )
                    )
                h := and(add(h, d), M)
                x := mul(e, R)
                d := and(add(d, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(e, f), and(g, or(e, f))))), M)
                // t = 61
                x := mul(h, R)
                c :=
                    add(
                        c,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(b, and(h, xor(a, b)))),
                            add(0xa4506cebde82bde9, mload(add(w, 0x7a0)))
                        )
                    )
                g := and(add(g, c), M)
                x := mul(d, R)
                c := and(add(c, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(d, e), and(f, or(d, e))))), M)
                // t = 62
                x := mul(g, R)
                b :=
                    add(
                        b,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(a, and(g, xor(h, a)))),
                            add(0xbef9a3f7b2c67915, mload(add(w, 0x7c0)))
                        )
                    )
                f := and(add(f, b), M)
                x := mul(c, R)
                b := and(add(b, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(c, d), and(e, or(c, d))))), M)
                // t = 63
                x := mul(f, R)
                a :=
                    add(
                        a,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(h, and(f, xor(g, h)))),
                            add(0xc67178f2e372532b, mload(add(w, 0x7e0)))
                        )
                    )
                e := and(add(e, a), M)
                x := mul(b, R)
                a := and(add(a, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(b, c), and(d, or(b, c))))), M)
                // t = 64
                x := mul(e, R)
                h :=
                    add(
                        h,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(g, and(e, xor(f, g)))),
                            add(0xca273eceea26619c, mload(add(w, 0x800)))
                        )
                    )
                d := and(add(d, h), M)
                x := mul(a, R)
                h := and(add(h, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(a, b), and(c, or(a, b))))), M)
                // t = 65
                x := mul(d, R)
                g :=
                    add(
                        g,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(f, and(d, xor(e, f)))),
                            add(0xd186b8c721c0c207, mload(add(w, 0x820)))
                        )
                    )
                c := and(add(c, g), M)
                x := mul(h, R)
                g := and(add(g, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(h, a), and(b, or(h, a))))), M)
                // t = 66
                x := mul(c, R)
                f :=
                    add(
                        f,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(e, and(c, xor(d, e)))),
                            add(0xeada7dd6cde0eb1e, mload(add(w, 0x840)))
                        )
                    )
                b := and(add(b, f), M)
                x := mul(g, R)
                f := and(add(f, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(g, h), and(a, or(g, h))))), M)
                // t = 67
                x := mul(b, R)
                e :=
                    add(
                        e,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(d, and(b, xor(c, d)))),
                            add(0xf57d4f7fee6ed178, mload(add(w, 0x860)))
                        )
                    )
                a := and(add(a, e), M)
                x := mul(f, R)
                e := and(add(e, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(f, g), and(h, or(f, g))))), M)
                // t = 68
                x := mul(a, R)
                d :=
                    add(
                        d,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(c, and(a, xor(b, c)))),
                            add(0x06f067aa72176fba, mload(add(w, 0x880)))
                        )
                    )
                h := and(add(h, d), M)
                x := mul(e, R)
                d := and(add(d, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(e, f), and(g, or(e, f))))), M)
                // t = 69
                x := mul(h, R)
                c :=
                    add(
                        c,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(b, and(h, xor(a, b)))),
                            add(0x0a637dc5a2c898a6, mload(add(w, 0x8a0)))
                        )
                    )
                g := and(add(g, c), M)
                x := mul(d, R)
                c := and(add(c, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(d, e), and(f, or(d, e))))), M)
                // t = 70
                x := mul(g, R)
                b :=
                    add(
                        b,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(a, and(g, xor(h, a)))),
                            add(0x113f9804bef90dae, mload(add(w, 0x8c0)))
                        )
                    )
                f := and(add(f, b), M)
                x := mul(c, R)
                b := and(add(b, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(c, d), and(e, or(c, d))))), M)
                // t = 71
                x := mul(f, R)
                a :=
                    add(
                        a,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(h, and(f, xor(g, h)))),
                            add(0x1b710b35131c471b, mload(add(w, 0x8e0)))
                        )
                    )
                e := and(add(e, a), M)
                x := mul(b, R)
                a := and(add(a, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(b, c), and(d, or(b, c))))), M)
                // t = 72
                x := mul(e, R)
                h :=
                    add(
                        h,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(g, and(e, xor(f, g)))),
                            add(0x28db77f523047d84, mload(add(w, 0x900)))
                        )
                    )
                d := and(add(d, h), M)
                x := mul(a, R)
                h := and(add(h, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(a, b), and(c, or(a, b))))), M)
                // t = 73
                x := mul(d, R)
                g :=
                    add(
                        g,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(f, and(d, xor(e, f)))),
                            add(0x32caab7b40c72493, mload(add(w, 0x920)))
                        )
                    )
                c := and(add(c, g), M)
                x := mul(h, R)
                g := and(add(g, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(h, a), and(b, or(h, a))))), M)
                // t = 74
                x := mul(c, R)
                f :=
                    add(
                        f,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(e, and(c, xor(d, e)))),
                            add(0x3c9ebe0a15c9bebc, mload(add(w, 0x940)))
                        )
                    )
                b := and(add(b, f), M)
                x := mul(g, R)
                f := and(add(f, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(g, h), and(a, or(g, h))))), M)
                // t = 75
                x := mul(b, R)
                e :=
                    add(
                        e,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(d, and(b, xor(c, d)))),
                            add(0x431d67c49c100d4c, mload(add(w, 0x960)))
                        )
                    )
                a := and(add(a, e), M)
                x := mul(f, R)
                e := and(add(e, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(f, g), and(h, or(f, g))))), M)
                // t = 76
                x := mul(a, R)
                d :=
                    add(
                        d,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(c, and(a, xor(b, c)))),
                            add(0x4cc5d4becb3e42b6, mload(add(w, 0x980)))
                        )
                    )
                h := and(add(h, d), M)
                x := mul(e, R)
                d := and(add(d, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(e, f), and(g, or(e, f))))), M)
                // t = 77
                x := mul(h, R)
                c :=
                    add(
                        c,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(b, and(h, xor(a, b)))),
                            add(0x597f299cfc657e2a, mload(add(w, 0x9a0)))
                        )
                    )
                g := and(add(g, c), M)
                x := mul(d, R)
                c := and(add(c, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(d, e), and(f, or(d, e))))), M)
                // t = 78
                x := mul(g, R)
                b :=
                    add(
                        b,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(a, and(g, xor(h, a)))),
                            add(0x5fcb6fab3ad6faec, mload(add(w, 0x9c0)))
                        )
                    )
                f := and(add(f, b), M)
                x := mul(c, R)
                b := and(add(b, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(c, d), and(e, or(c, d))))), M)
                // t = 79
                x := mul(f, R)
                a :=
                    add(
                        a,
                        add(
                            add(xor(xor(shr(14, x), shr(18, x)), shr(41, x)), xor(h, and(f, xor(g, h)))),
                            add(0x6c44198c4a475817, mload(add(w, 0x9e0)))
                        )
                    )
                e := and(add(e, a), M)
                x := mul(b, R)
                a := and(add(a, add(xor(xor(shr(28, x), shr(34, x)), shr(39, x)), or(and(b, c), and(d, or(b, c))))), M)
                mstore(add(w, 2560), and(add(mload(add(w, 2560)), a), M))
                mstore(add(w, 2592), and(add(mload(add(w, 2592)), b), M))
                mstore(add(w, 2624), and(add(mload(add(w, 2624)), c), M))
                mstore(add(w, 2656), and(add(mload(add(w, 2656)), d), M))
                mstore(add(w, 2688), and(add(mload(add(w, 2688)), e), M))
                mstore(add(w, 2720), and(add(mload(add(w, 2720)), f), M))
                mstore(add(w, 2752), and(add(mload(add(w, 2752)), g), M))
                mstore(add(w, 2784), and(add(mload(add(w, 2784)), h), M))
            }
            hi :=
                or(
                    or(shl(192, mload(add(w, 2560))), shl(128, mload(add(w, 2592)))),
                    or(shl(64, mload(add(w, 2624))), mload(add(w, 2656)))
                )
            lo :=
                or(
                    or(shl(192, mload(add(w, 2688))), shl(128, mload(add(w, 2720)))),
                    or(shl(64, mload(add(w, 2752))), mload(add(w, 2784)))
                )
        }
    }
}
