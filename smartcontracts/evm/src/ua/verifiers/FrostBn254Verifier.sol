// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {IUAPopVerifier} from "../IUAVerifier.sol";
import {CurveSigs} from "../../common/CurveSigs.sol";
import {G1Bn254} from "../../zether/ZetherCurves.sol";
import {SCHNORR_TAG} from "./PairingVerifiers.sol";

/// @title UA verifier for `frost-bn254` (0x0113, accounts.md §1.6.1, §1.9): FROST(bn254, keccak256).
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** `verify(Y, ua_msg, R ‖ z)`: the `schnorr-bn254` check
///         (`CurveSigs.schnorr` under `"scaas.ua.schnorr.v1"`; the ciphersuite's H2 is that challenge), `Y` (64) the
///         stored group key. `verifyPop(keyData, msg, sig)`: key data = `Y (64) ‖ u16 t ‖ u16 n ‖ n × (t × C_ik (64) ‖
///         R_i (64) ‖ μ_i (32))`, 2 ≤ t ≤ n ≤ 16, participant `i = 1..n`; for each `i`: `C_i0`, `R_i` canonical and on
///         the curve (checked in Solidity, so no precompile can fail on them), `μ_i < r`,
///         `[μ_i]G + [r − c_i]C_i0 == R_i` with `c_i = H_dkg(i (32 BE) ‖ C_i0 ‖ R_i)`,
///         `H_dkg(m) = int(keccak256(ctx ‖ "dkg" ‖ m ‖ 0x00) ‖ keccak256(ctx ‖ "dkg" ‖ m ‖ 0x01)) mod r`,
///         `ctx = "FROST-BN254-KECCAK256-SCAAS-v1"`; `Y == Σ C_i0`; then `verify(Y, msg, sig)`. `C_ik` for k ≥ 1 are
///         checked by `UAKinds.validateKeyData` at registration, not here (see `UAFrostSecp256k1Verifier`).
///         Malformed input returns false; only a caller that gives too little gas for the precompiles sees a revert.
contract FrostBn254Verifier is IUAPopVerifier {
    bytes internal constant DKG_PREFIX = "FROST-BN254-KECCAK256-SCAAS-v1dkg";
    uint256 private constant TWO_256_MOD_R = (type(uint256).max % G1Bn254.R) + 1;

    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool) {
        return keyData.length == 64 && CurveSigs.schnorr(SCHNORR_TAG, keyData, message, sig);
    }

    function verifyPop(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool) {
        if (keyData.length < 68) return false;
        uint256 t = uint16(bytes2(keyData[64:66]));
        uint256 n = uint16(bytes2(keyData[66:68]));
        if (t < 2 || t > n || n > 16) return false;
        uint256 per = (t + 1) * 64 + 32;
        if (keyData.length != 68 + n * per) return false;
        bytes memory acc = G1Bn254.identity();
        for (uint256 i; i < n; ++i) {
            uint256 o = 68 + i * per;
            bytes memory c0 = keyData[o:o + 64];
            if (!_pok(i + 1, c0, keyData[o + t * 64:o + per])) return false;
            acc = G1Bn254.add(acc, c0);
        }
        bytes memory y = keyData[0:64];
        if (keccak256(acc) != keccak256(y)) return false;
        return CurveSigs.schnorr(SCHNORR_TAG, y, message, sig);
    }

    /// Participant `id`'s PoK: `rm = R_i (64) ‖ μ_i (32)`; `[μ_i]G + [r − c_i]C_i0 == R_i`.
    function _pok(uint256 id, bytes memory c0, bytes calldata rm) private view returns (bool) {
        bytes memory rPt = rm[0:64];
        uint256 mu = uint256(bytes32(rm[64:96]));
        uint256 r = G1Bn254.R;
        if (!_onCurve(c0) || !_onCurve(rPt) || mu >= r) return false;
        uint256 hi = uint256(keccak256(abi.encodePacked(DKG_PREFIX, id, c0, rPt, uint8(0))));
        uint256 lo = uint256(keccak256(abi.encodePacked(DKG_PREFIX, id, c0, rPt, uint8(1))));
        uint256[] memory sc = new uint256[](2);
        (sc[0], sc[1]) = (mu, r - addmod(mulmod(hi, TWO_256_MOD_R, r), lo, r));
        return keccak256(G1Bn254.msm(bytes.concat(G1Bn254.generator(), c0), sc)) == keccak256(rPt);
    }

    /// 64 bytes, canonical, on `y² = x³ + 3` (excludes O = (0, 0)).
    function _onCurve(bytes memory a) private pure returns (bool) {
        (uint256 x, uint256 y) = abi.decode(a, (uint256, uint256));
        uint256 q = G1Bn254.P;
        return x < q && y < q && mulmod(y, y, q) == addmod(mulmod(mulmod(x, x, q), x, q), 3, q);
    }
}
