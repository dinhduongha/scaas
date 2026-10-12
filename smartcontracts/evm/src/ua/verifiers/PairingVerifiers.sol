// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
pragma solidity ^0.8.24;

import {IUAPopVerifier} from "../IUAVerifier.sol";
import {UAKinds} from "../UAKinds.sol";
import {CurveSigs} from "../../common/CurveSigs.sol";

/// @title A UA verifier that answers false instead of reverting (accounts.md §1.9, CTR-UA-17).
/// @notice `verify` / `verifyPop` run `check` through an external self-call capped at `CHECK_GAS` under `try`, so a
///         revert inside a curve helper (off-curve, non-canonical or out-of-subgroup point: the precompile fails and
///         `G1Bn254` / `G1Bls12381` / `Bls12381` revert) or an out-of-gas inside it becomes `false`. The cap matters: a
///         failing EIP-196/197/2537 precompile consumes all the gas it was given, and the curve helpers forward `gas()`,
///         so without it a malformed point would burn 63/64 of the caller's gas. A call that cannot give `check` its
///         full `CHECK_GAS` reverts `UAKinds.UAVerifyGas` (a statement about the gas, never `false` about the key).
///         Worst case of any call: `CHECK_GAS` + the wrapper. **UNAUDITED — NOT FOR PRODUCTION FUNDS.**
abstract contract UASafeVerifier is IUAPopVerifier {
    uint256 public immutable CHECK_GAS;

    constructor(uint256 checkGas) {
        CHECK_GAS = checkGas;
    }

    function verify(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool) {
        return _safe(keyData, message, sig, false);
    }

    function verifyPop(bytes calldata keyData, bytes32 message, bytes calldata sig) external view returns (bool) {
        return _safe(keyData, message, sig, true);
    }

    /// @notice The unguarded check (`pop` selects the PoP domain); may revert on malformed points. External only so
    ///         `verify` / `verifyPop` can catch its reverts; it is as safe to call as they are, minus that guarantee.
    function check(bytes calldata keyData, bytes32 message, bytes calldata sig, bool pop)
        external view virtual returns (bool);

    function _safe(bytes calldata keyData, bytes32 message, bytes calldata sig, bool pop) private view returns (bool) {
        if (gasleft() < CHECK_GAS + CHECK_GAS / 63 + 5_000) revert UAKinds.UAVerifyGas();
        try this.check{gas: CHECK_GAS}(keyData, message, sig, pop) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
    }
}

bytes constant SCHNORR_TAG = "scaas.ua.schnorr.v1";

/// @title `schnorr-bn254` (0x0104): `Y` (64), `sig = R ‖ z` (96); `verifyPop` = `verify`.
contract SchnorrBn254Verifier is UASafeVerifier {
    /// valid ≈ 27 k inside `check` (3 ECMUL + 3 ECADD); R, Y checked in Solidity, so no failing precompile.
    constructor() UASafeVerifier(40_000) {}

    function check(bytes calldata keyData, bytes32 message, bytes calldata sig, bool)
        external view override returns (bool)
    {
        return keyData.length == 64 && CurveSigs.schnorr(SCHNORR_TAG, keyData, message, sig);
    }
}

/// @title `schnorr-bls12381` (0x0105): `Y` (128, EIP-2537), `sig = R ‖ z` (160); `verifyPop` = `verify`.
contract SchnorrBls12381Verifier is UASafeVerifier {
    /// valid ≈ 39 k inside `check` (G1MSM k = 3); a malformed R / Y fails G1MSM and burns the cap.
    constructor() UASafeVerifier(60_000) {}

    function check(bytes calldata keyData, bytes32 message, bytes calldata sig, bool)
        external view override returns (bool)
    {
        return keyData.length == 128 && CurveSigs.schnorr(SCHNORR_TAG, keyData, message, sig);
    }
}

/// @title `bls12381-minsig` (0x0106): `pk ∈ G2` (256, EIP-2537), `sig ∈ G1` (128); RFC 9380 hash-to-G1 of `ua_msg`.
contract BlsMinSigBls12381Verifier is UASafeVerifier {
    /// valid ≈ 157 k inside `check` (2 MAP_FP_TO_G1, G1ADD, PAIRING_CHECK k = 2); a malformed sig burns the cap.
    constructor() UASafeVerifier(180_000) {}

    bytes internal constant DST_SIG = "SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_SIG_";
    bytes internal constant DST_POP = "SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_";

    function check(bytes calldata keyData, bytes32 message, bytes calldata sig, bool pop)
        external view override returns (bool)
    {
        return CurveSigs.bls12381(pop ? DST_POP : DST_SIG, keyData, message, sig);
    }
}

/// @title `bls-bn254-minsig` (0x0107): `pk ∈ G2` (128, EIP-197 order), `sig ∈ G1` (64); try-and-increment `mapToG1`.
contract BlsMinSigBn254Verifier is UASafeVerifier {
    /// valid ≈ 123 k + 5.2 k per extra `mapToG1` iteration; 330 k leaves ~39 extra iterations (an honest message
    /// needs more with probability ~2^-39; it then fails closed and the signer re-signs another digest).
    constructor() UASafeVerifier(330_000) {}

    bytes internal constant LABEL_SIG = "SCAAS-UA-BLS-BN254-SIG-V1";
    bytes internal constant LABEL_POP = "SCAAS-UA-BLS-BN254-POP-V1";

    function check(bytes calldata keyData, bytes32 message, bytes calldata sig, bool pop)
        external view override returns (bool)
    {
        return CurveSigs.blsBn254(pop ? LABEL_POP : LABEL_SIG, keyData, message, sig);
    }
}
