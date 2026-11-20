// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title The `bls12381-multi` (0x0121) key-data forms (spec 2026-11-19-bls12381-multi §2).
/// @notice `d = apk (256) ‖ u16 t ‖ u16 n ‖ n × (pk_i (256) ‖ u16 w_i)` in EIP-2537 G2 encoding (four 64-byte limbs, top 16 bytes
///         zero), length 260 + 258·n; `s` = the same with 48-byte limbs, length 196 + 194·n; the registry's key pointer holds
///         `p = ua (32) ‖ s`, length 228 + 194·n. Internal functions only, inlined into each caller (owner ruling 2026-11-19, plan
///         choice 4): no DELEGATECALL. No validation here: `compress` takes key data `UAKinds.validateKeyData` accepted (every limb's
///         top 16 bytes zero), `expand` and `point` take what the registry stored. UNAUDITED.
library BlsMultiKeyData {
    /// `d` → `s`: each 64-byte limb loses its 16 zero bytes.
    function compress(bytes memory d) internal pure returns (bytes memory s) {
        uint256 n = _u16(d, 258);
        s = new bytes(196 + 194 * n);
        assembly ("memory-safe") {
            let src := add(d, 32)
            let dst := add(s, 32)
            for { let i := 0 } lt(i, add(n, 1)) { i := add(i, 1) } {
                // i = 0: apk ‖ t ‖ n; i ≥ 1: pk_i ‖ w_i
                let so := add(src, mul(258, i))
                let dO := add(dst, mul(194, i))
                if i {
                    so := add(so, 2)
                    dO := add(dO, 2)
                }
                for { let j := 0 } lt(j, 4) { j := add(j, 1) } {
                    mcopy(add(dO, mul(j, 48)), add(so, add(mul(j, 64), 16)), 48)
                }
                switch i
                case 0 { mcopy(add(dO, 192), add(so, 256), 4) }
                default { mcopy(add(dO, 192), add(so, 256), 2) }
            }
        }
    }

    /// `s` → `d`: a 16-byte zero prefix per 48-byte limb.
    function expand(bytes memory s) internal pure returns (bytes memory d) {
        uint256 n = _u16(s, 194);
        d = new bytes(260 + 258 * n); // zeroed: the prefixes stay 0
        assembly ("memory-safe") {
            let src := add(s, 32)
            let dst := add(d, 32)
            for { let i := 0 } lt(i, add(n, 1)) { i := add(i, 1) } {
                let so := add(src, mul(194, i))
                let dO := add(dst, mul(258, i))
                if i {
                    so := add(so, 2)
                    dO := add(dO, 2)
                }
                for { let j := 0 } lt(j, 4) { j := add(j, 1) } {
                    mcopy(add(dO, add(mul(j, 64), 16)), add(so, mul(j, 48)), 48)
                }
                switch i
                case 0 { mcopy(add(dO, 256), add(so, 192), 4) }
                default { mcopy(add(dO, 256), add(so, 192), 2) }
            }
        }
    }

    /// Point `i` of the stored `p = ua ‖ s` in its 256-byte EIP-2537 form: `i = 0` the aggregate key `apk`, `i ≥ 1` member `i`
    /// (the i-th in key-data order). The caller bounds `i ≤ n`.
    function point(bytes memory p, uint256 i) internal pure returns (bytes memory out) {
        uint256 o = i == 0 ? 32 : 32 + 196 + 194 * (i - 1);
        out = new bytes(256);
        assembly ("memory-safe") {
            let src := add(add(p, 32), o)
            let dst := add(out, 32)
            for { let j := 0 } lt(j, 4) { j := add(j, 1) } {
                mcopy(add(dst, add(mul(j, 64), 16)), add(src, mul(j, 48)), 48)
            }
        }
    }

    function _u16(bytes memory b, uint256 o) private pure returns (uint256 v) {
        assembly ("memory-safe") {
            v := shr(240, mload(add(add(b, 32), o)))
        }
    }
}
