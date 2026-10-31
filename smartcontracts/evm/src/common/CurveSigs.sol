// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {Bls12381} from "./Bls12381.sol";
import {HashToCurve} from "./HashToCurve.sol";
import {ZetherTranscript} from "../zether/ZetherTranscript.sol";
import {G1Bn254, G1Bls12381} from "../zether/ZetherCurves.sol";

/// @title Schnorr on bn254 / BLS12-381 G1 and BLS min-sig on both curves, with the tag / DST / label as a parameter.
/// @notice **UNAUDITED.** Shared by the UA verifiers (`src/ua/verifiers/`: the UA Schnorr
///         tag, the Zether Schnorr tag of the Zether kinds, the BLS DSTs / labels). Returns false on a wrong signature and on a malformed bn254 G1 point
///         (checked in Solidity). A malformed BLS12-381 point (non-canonical, off the curve, outside the subgroup) or a
///         malformed bn254 G2 key makes a precompile fail — consuming all the gas it was given — and the curve helpers
///         **revert** (`G1Bls12381.BadPoint`, `Bls12381.PrecompileFailed`) or answer false (bn254 pairing); callers
///         that must answer false within a bound wrap the call with a gas cap (`UASafeVerifier`).
library CurveSigs {
    /// bn254 G2 generator, EIP-197 order: x_im, x_re, y_im, y_re.
    bytes internal constant BN254_G2 = abi.encodePacked(
        uint256(11559732032986387107991004021392285783925812861821192530917403151452391805634),
        uint256(10857046999023057135944570762232829481370756359578518086990519993285655852781),
        uint256(4082367875863433681332203403145435568316851327593401208105741076214120093531),
        uint256(8495653923123431417604973247489272438418190587263600148770280649306958101930)
    );

    /// @notice Schnorr on the curve of `y` (64 B bn254, 128 B BLS12-381): `sig = R ‖ z`,
    ///         `e = hashToScalar(keccak256(tag ‖ R ‖ Y ‖ m), r)`, accept iff `z < r`, `e ≠ 0`, `R ≠ O`, `Y ≠ O` and
    ///         `[z]G − R − [e]Y == O` (one MSM; on BLS12-381 G1MSM also checks `R`, `Y` in the subgroup).
    function schnorr(bytes memory tag, bytes memory y, bytes32 m, bytes memory sig) internal view returns (bool) {
        uint256 p = y.length;
        if ((p != 64 && p != 128) || sig.length != p + 32) return false;
        bytes memory rPt = new bytes(p);
        uint256 z;
        assembly ("memory-safe") {
            for { let i := 0 } lt(i, p) { i := add(i, 32) } { mstore(add(add(rPt, 32), i), mload(add(add(sig, 32), i))) }
            z := mload(add(add(sig, 32), p))
        }
        // bn254: R, Y canonical and on the curve (cofactor 1), so the precompiles below cannot fail.
        if (p == 64 && !(_bnG1(rPt) && _bnG1(y))) return false;
        uint256 r = p == 64 ? G1Bn254.R : G1Bls12381.R;
        uint256 e = ZetherTranscript.hashToScalar(keccak256(abi.encodePacked(tag, rPt, y, m)), r);
        if (z >= r || e == 0 || _isZero(rPt) || _isZero(y)) return false;
        uint256[] memory sc = new uint256[](3);
        (sc[0], sc[1], sc[2]) = (z, r - 1, r - e);
        bytes memory out = p == 64
            ? G1Bn254.msm(bytes.concat(G1Bn254.generator(), rPt, y), sc)
            : G1Bls12381.msm(bytes.concat(G1Bls12381.generator(), rPt, y), sc);
        return _isZero(out);
    }

    /// @notice BLS min-sig on bn254: `e(−sig, G2) · e(H(m), pk) == 1`, `H = G1Bn254.mapToG1(label ‖ m)`
    ///         (try-and-increment: unbounded, ~5.2 k gas per extra iteration under EIP-7883). `sig` canonical, on the curve,
    ///         ≠ O; the pairing precompile checks `pk` canonical, on the twist and in G2.
    function blsBn254(bytes memory label, bytes memory pk, bytes32 m, bytes memory sig) internal view returns (bool) {
        if (pk.length != 128 || !_bnG1(sig)) return false;
        bytes memory h = G1Bn254.mapToG1(abi.encodePacked(label, m));
        (bool ok, bytes memory out) = address(0x08).staticcall(bytes.concat(G1Bn254.neg(sig), BN254_G2, h, pk));
        return ok && out.length == 32 && abi.decode(out, (uint256)) == 1;
    }

    /// @notice BLS min-sig on BLS12-381: `H = HashToCurve.hashToG1(m, dst)`, `sig ≠ O`, `Bls12381.verifyMinSig`
    ///         (PAIRING_CHECK checks `sig` and `pk` canonical, on curve and in their subgroups, EIP-2537).
    function bls12381(bytes memory dst, bytes memory pk, bytes32 m, bytes memory sig) internal view returns (bool) {
        if (sig.length != 128 || pk.length != 256 || _isZero(sig)) return false;
        return Bls12381.verifyMinSig(HashToCurve.hashToG1(abi.encodePacked(m), dst), pk, sig);
    }

    /// bn254 G1: 64 bytes, canonical, on `y² = x³ + 3` (excludes O = (0, 0)); pure, so a bad point costs no
    /// failing precompile (which would consume all the gas it was given).
    function _bnG1(bytes memory a) private pure returns (bool) {
        if (a.length != 64) return false;
        (uint256 x, uint256 y) = abi.decode(a, (uint256, uint256));
        uint256 q = G1Bn254.P;
        return x < q && y < q && mulmod(y, y, q) == addmod(mulmod(mulmod(x, x, q), x, q), 3, q);
    }

    function _isZero(bytes memory b) private pure returns (bool) {
        return keccak256(b) == keccak256(new bytes(b.length));
    }
}
