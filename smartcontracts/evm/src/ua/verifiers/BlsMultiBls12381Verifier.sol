// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUAMinimalVerifier} from "../IUAVerifier.sol";
import {UAKinds} from "../UAKinds.sol";
import {UASafeVerifier} from "./PairingVerifiers.sol";
import {Bls12381} from "../../common/Bls12381.sol";
import {CurveSigs} from "../../common/CurveSigs.sol";
import {HashToCurve} from "../../common/HashToCurve.sol";

/// @title UA verifier for `bls12381-multi` (0x0121, spec 2026-11-19-bls12381-multi §4, §5; CTR-UA-49 / CTR-UA-50).
/// @notice `verify(p, ua_msg, σ ‖ signers)` / `verifyMinimal(…)`: `p = ua (32) ‖ s` is the registry's stored key pointer
///         (`s` = the key data in 48-byte limbs, `228 + 194·n` bytes, checked against the `n` it holds); `sig` is σ (128, G1,
///         EIP-2537) ‖ `signers` (uint256, bit i = member i). `m = keccak256(ua ‖ ua_msg)`; `W(S) ≥ t` (`verifyMinimal`: also
///         `W(S) − min_{i∈S} w_i < t`); `apk(S)` = the stored `apk` when every member signed, the signers' G2ADD sum when
///         `2k ≤ n + 1`, else `apk` plus the negated sum of the non-signers (per-component Fp negation, `neg(0) = 0`); `σ ≠ O`,
///         `apk(S) ≠ O`; one PAIRING_CHECK `e(σ, −g2) · e(H_G1(m, DST_MULTI_SIG), apk(S)) == 1`.
///         `verifyPop(d, popMsg, pop)`: `d` = the registration key data (`260 + 258·n` bytes), `pop ≠ O` and
///         `e(pop, −g2) · Π_i e(H_G1(keccak256(popMsg ‖ pk_i), DST_MULTI_POP), pk_i) == 1` (n + 1 pairs). Neither form is
///         accepted by the other entry (they collide in length at d(n = 48) = p(n = 64) = 12,644 B). `verifyPop` is the
///         only use of `DST_MULTI_POP`. The registry has validated `d` (UAKinds) and wrote `p`; the pairing re-checks the
///         subgroups of σ, `pop`, the keys and `apk(S)`. **UNAUDITED.**
contract BlsMultiBls12381Verifier is UASafeVerifier, IUAMinimalVerifier {
    /// The PoP at n = 64 measured 5,578,582 (`BlsMultiVerifier.t.sol` `test_checkGas_worstRows`; spec §8.1 estimated ≈ 3.2 M: the
    /// Solidity hash-to-G1 costs more than its estimate), ~20 % margin. Plan Task 9 (`UAGas.t.sol` `test_T_GAS_blsMultiPop`, inside
    /// `check`): n = 2 244,152, n = 16 1,418,542, n = 64 5,578,617: kept, 1,121,383 (20.1 %) over the worst; with the hold
    /// (6,811,349) within the 12 M deploy budget.
    uint256 public constant POP_GAS = 6_700_000;

    /// BLS12-381 base field modulus `p_381`, split as a 64-byte EIP-2537 limb: the high 32 bytes (top 16 zero), the low 32.
    uint256 private constant P_HI = 0x1a0111ea397fe69a4b1ba7b6434bacd7;
    uint256 private constant P_LO = 0x64774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab;

    /// The worst verify measured 253,109 (n = 64, k = 33, the subtract path with the negation; k = 32 252,320; `test_checkGas_worstRows`;
    /// spec §8.2 estimated ≈ 240 k with the margin), ~20 % margin. Plan Task 9 (`UAGas.t.sol` `test_T_GAS_blsMultiVerify`, inside
    /// `check`, `verify` and `verifyMinimal` at (n, k) = (2, 2), (16, 8), (64, 1), (64, 32), (64, 33), (64, 64)): the worst 252,564
    /// (n = 64, k = 33, `verifyMinimal`): kept, 47,436 (18.8 %) over it.
    constructor() UASafeVerifier(300_000) {}

    function verifyMinimal(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool) {
        return _safe(keyData, message, sig, Mode.Minimal);
    }

    function _checkGas(Mode mode) internal view virtual override returns (uint256) {
        return mode == Mode.Pop ? POP_GAS : CHECK_GAS;
    }

    function check(bytes calldata keyData, bytes32 message, bytes calldata sig, Mode mode)
        external
        view
        override
        returns (bool)
    {
        return mode == Mode.Pop ? _pop(keyData, message, sig) : _sig(keyData, message, sig, mode == Mode.Minimal);
    }

    /// §5.2 over the stored `p`.
    function _sig(bytes calldata p, bytes32 uaMsg, bytes calldata sig, bool minimal) private view returns (bool) {
        if (sig.length != 160 || p.length < 228) return false;
        uint256 n = uint16(bytes2(p[226:228]));
        if (n < 2 || n > 64 || p.length != 228 + 194 * n) return false;
        uint256 signers = uint256(bytes32(sig[128:160]));
        if (signers == 0 || signers >> n != 0 || !_weights(p, signers, n, minimal)) return false;
        bytes memory apkS = _apk(p, signers, n);
        bytes memory sigma = sig[0:128];
        // apk(S) ≠ O (fail-closed clarity; an empty `apkS` is a failed G2ADD), σ ≠ O (CTR-UA-01)
        if (apkS.length == 0 || _zero(apkS) || _zero(sigma)) return false;
        bytes memory h = HashToCurve.hashToG1(
            abi.encodePacked(keccak256(abi.encodePacked(p[0:32], uaMsg))), CurveSigs.DST_MULTI_SIG
        );
        return Bls12381.pairingCheck(bytes.concat(sigma, Bls12381.NEG_G2_GENERATOR, h, apkS));
    }

    /// `W(S) ≥ t`; `minimal`: also `W(S) − min_{i∈S} w_i < t` (every signer necessary, §5.3). Sums in 256 bits.
    function _weights(bytes calldata p, uint256 signers, uint256 n, bool minimal) private pure returns (bool) {
        (uint256 w, uint256 minW) = (0, type(uint256).max);
        for (uint256 i; i < n; ++i) {
            if ((signers >> i) & 1 == 0) continue;
            uint256 o = 228 + 194 * i + 192;
            uint256 wi = uint16(bytes2(p[o:o + 2]));
            w += wi;
            if (wi < minW) minW = wi;
        }
        uint256 t = uint16(bytes2(p[224:226]));
        return w >= t && !(minimal && w - minW >= t);
    }

    /// `apk(S)` in EIP-2537 form (256 bytes), pinned (§5.2): the stored `apk` when all n signed; the signers' G2ADD sum when
    /// `2k ≤ n + 1`; else `apk` plus the negated sum of the non-signers. Empty when a G2ADD fails.
    function _apk(bytes calldata p, uint256 signers, uint256 n) private view returns (bytes memory buf) {
        uint256 k;
        for (uint256 i; i < n; ++i) {
            k += (signers >> i) & 1;
        }
        buf = new bytes(512); // acc ‖ the point added; every limb's 16-byte prefix stays 0
        if (k == n) {
            _load(buf, 0, p, 32); // the stored apk
        } else {
            bool adding = 2 * k <= n + 1;
            bool first = true;
            for (uint256 i; i < n; ++i) {
                if (((signers >> i) & 1 == 1) != adding) continue;
                if (first) {
                    _load(buf, 0, p, 228 + 194 * i);
                    first = false;
                } else {
                    _load(buf, 256, p, 228 + 194 * i);
                    if (!_g2add(buf)) return "";
                }
            }
            if (!adding) {
                _neg(buf, 128);
                _neg(buf, 192);
                _load(buf, 256, p, 32);
                if (!_g2add(buf)) return "";
            }
        }
        assembly ("memory-safe") {
            mstore(buf, 256)
        }
    }

    /// §4 over the registration key data `d`.
    function _pop(bytes calldata d, bytes32 popMsg, bytes calldata pop) private view returns (bool) {
        if (pop.length != 128 || d.length < 260) return false;
        uint256 n = uint16(bytes2(d[258:260]));
        if (n < 2 || n > 64 || d.length != 260 + 258 * n || _zero(pop[0:128])) return false;
        bytes memory pairs = new bytes(384 * (n + 1));
        bytes memory neg = Bls12381.NEG_G2_GENERATOR;
        assembly ("memory-safe") {
            calldatacopy(add(pairs, 32), pop.offset, 128)
            mcopy(add(pairs, 160), add(neg, 32), 256)
        }
        for (uint256 i; i < n; ++i) {
            bytes calldata pk = d[260 + 258 * i:516 + 258 * i];
            bytes memory h = HashToCurve.hashToG1(
                abi.encodePacked(keccak256(abi.encodePacked(popMsg, pk))), CurveSigs.DST_MULTI_POP
            );
            assembly ("memory-safe") {
                let at := add(add(pairs, 32), mul(384, add(i, 1)))
                mcopy(at, add(h, 32), 128)
                calldatacopy(add(at, 128), pk.offset, 256)
            }
        }
        return Bls12381.pairingCheck(pairs);
    }

    /// The point at `p[o:o + 192]` (48-byte limbs) into `buf[at:at + 256]` (EIP-2537 limbs).
    function _load(bytes memory buf, uint256 at, bytes calldata p, uint256 o) private pure {
        assembly ("memory-safe") {
            let dst := add(add(buf, 32), at)
            let src := add(p.offset, o)
            for { let j := 0 } lt(j, 4) { j := add(j, 1) } {
                calldatacopy(add(dst, add(mul(j, 64), 16)), add(src, mul(j, 48)), 48)
            }
        }
    }

    /// `buf[0:256] = G2ADD(buf[0:256], buf[256:512])`, capped at `UAKinds.G2ADD_GAS` (a call inside the capped `check`).
    function _g2add(bytes memory buf) private view returns (bool ok) {
        uint256 cap = UAKinds.G2ADD_GAS;
        assembly ("memory-safe") {
            ok := staticcall(cap, 0x0d, add(buf, 32), 512, add(buf, 32), 256)
            ok := and(ok, eq(returndatasize(), 256)) // after the call: Yul evaluates arguments right to left
        }
    }

    /// The Fp limb at `buf[at:at + 64]` replaced by `p_381 − y`, except `0` stays `0` (N3: O maps to O, a zero component stays
    /// canonical). The limb is canonical (`< p_381`): a stored key or a G2ADD output.
    function _neg(bytes memory buf, uint256 at) internal pure {
        assembly ("memory-safe") {
            let a := add(add(buf, 32), at)
            let hi := mload(a)
            let lo := mload(add(a, 32))
            if or(hi, lo) {
                mstore(a, sub(sub(P_HI, hi), lt(P_LO, lo)))
                mstore(add(a, 32), sub(P_LO, lo))
            }
        }
    }

    function _zero(bytes memory b) private pure returns (bool) {
        return keccak256(b) == keccak256(new bytes(b.length));
    }
}
