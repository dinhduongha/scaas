// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {CurveSigs} from "../../common/CurveSigs.sol";
import {G1Bn254} from "../../zether/ZetherCurves.sol";
import {UASafeVerifier, SCHNORR_TAG} from "./PairingVerifiers.sol";
import {KEYAGG_LIST_TAG, KEYAGG_COEF_TAG} from "./Musig2Secp256k1Verifier.sol";

/// @title UA verifier for `musig2-bn254` (0x0112, accounts.md §1.6.1, §1.9).
/// @notice `verify(vk, m, sig)`: `vk = Q` (64, from `keyPtr`), the scaas Schnorr of `schnorr-bn254` (`R ‖ z`, 96).
///         `verifyPop(keyData, m, sig)`: `keyData = Q (64) ‖ u16 n ‖ n × P_i (64)`, `P_i` strictly increasing; the
///         BIP-327 KeyAgg port: `L = hash_{KeyAgg list}(P_1 ‖ … ‖ P_n)` (BIP-327's 32-byte tagged SHA-256),
///         `a_i = H_{KeyAgg coefficient}(L ‖ P_i)` with the widened hash `H_t(x) = tagged_t(x ‖ 0x00) ‖ tagged_t(x ‖ 0x01)`
///         read as a 512-bit integer mod r, `a_i = 1` for the second key (`P_2`), `Q == Σ a_i·P_i` (ECMUL/ECADD, full
///         points, no parity), then the Schnorr by `Q`. Runs inside `UASafeVerifier` (an off-curve point makes the
///         precompile fail and `G1Bn254` revert: false; the identity (0,0) is ECMUL's O, so it is not refused here: `UAKinds`
///         key validation (`_bnG1`) refuses an identity member before the registry calls this). **UNAUDITED — NOT FOR PRODUCTION FUNDS.**
contract Musig2Bn254Verifier is UASafeVerifier {
    /// verifyPop at n = 16 measured 188,045 inside `check` (`Musig2Verifiers.t.sol` `test_bnPopGas`); ~20 % margin.
    uint256 public constant POP_GAS = 230_000;

    /// verify = `schnorr-bn254`: valid ≈ 27 k inside `check`.
    constructor() UASafeVerifier(40_000) {}

    function _checkGas(bool pop) internal view override returns (uint256) {
        return pop ? POP_GAS : CHECK_GAS;
    }

    function check(bytes calldata keyData, bytes32 message, bytes calldata sig, bool pop)
        external
        view
        override
        returns (bool)
    {
        if (!pop) return keyData.length == 64 && CurveSigs.schnorr(SCHNORR_TAG, keyData, message, sig);
        return keyAgg(keyData) && CurveSigs.schnorr(SCHNORR_TAG, keyData[0:64], message, sig);
    }

    function keyAgg(bytes calldata d) internal view returns (bool) {
        if (d.length < 66) return false;
        uint256 n = uint16(bytes2(d[64:66]));
        if (n < 2 || n > 16 || d.length != 66 + 64 * n) return false;
        bytes32 l = sha256(abi.encodePacked(KEYAGG_LIST_TAG, KEYAGG_LIST_TAG, d[66:]));
        uint256[] memory sc = new uint256[](n);
        uint256 twoTo256 = (type(uint256).max % G1Bn254.R) + 1;
        for (uint256 i; i < n; ++i) {
            uint256 o = 66 + 64 * i;
            if (i > 0) {
                (uint256 px, uint256 x) = (uint256(bytes32(d[o - 64:o - 32])), uint256(bytes32(d[o:o + 32])));
                if (px > x || (px == x && uint256(bytes32(d[o - 32:o])) >= uint256(bytes32(d[o + 32:o + 64])))) {
                    return false; // strictly increasing
                }
            }
            if (i == 1) {
                sc[i] = 1;
                continue;
            }
            uint256 hi = uint256(sha256(abi.encodePacked(KEYAGG_COEF_TAG, KEYAGG_COEF_TAG, l, d[o:o + 64], uint8(0))));
            uint256 lo = uint256(sha256(abi.encodePacked(KEYAGG_COEF_TAG, KEYAGG_COEF_TAG, l, d[o:o + 64], uint8(1))));
            sc[i] = addmod(mulmod(hi, twoTo256, G1Bn254.R), lo, G1Bn254.R);
        }
        return keccak256(G1Bn254.msm(d[66:], sc)) == keccak256(d[0:64]);
    }
}
