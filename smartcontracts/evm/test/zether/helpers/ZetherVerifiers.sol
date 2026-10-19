// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IZetherVerifier, IZetherBurnVerifier, IZetherInnerProductVerifier} from "../../../src/zether/IZetherVerifier.sol";
import {
    ZetherInnerProductVerifierBn254,
    ZetherTransferVerifierBn254,
    ZetherBurnVerifierBn254,
    ZetherInnerProductVerifierBls12381,
    ZetherTransferVerifierBls12381,
    ZetherBurnVerifierBls12381
} from "../../../src/zether/ZetherVerifier.sol";

/// @notice The verifiers of a curve (CTR-ZTH-20 split: inner-product, transfer, burn), deployed directly for the
///         verifier-level tests, and their init codes for `OpenFactory.deployZetherVerifier`.
library ZetherVerifiers {
    function deploy(bool bls) internal returns (IZetherVerifier t, IZetherBurnVerifier b) {
        if (bls) {
            IZetherInnerProductVerifier ip = new ZetherInnerProductVerifierBls12381();
            t = IZetherVerifier(address(new ZetherTransferVerifierBls12381(ip)));
            b = IZetherBurnVerifier(address(new ZetherBurnVerifierBls12381(ip)));
        } else {
            IZetherInnerProductVerifier ip = new ZetherInnerProductVerifierBn254();
            t = IZetherVerifier(address(new ZetherTransferVerifierBn254(ip)));
            b = IZetherBurnVerifier(address(new ZetherBurnVerifierBn254(ip)));
        }
    }

    /// @dev Init codes without constructor arguments (the factory appends the inner-product verifier).
    function codes(bool bls) internal pure returns (bytes memory ip, bytes memory t, bytes memory b) {
        if (bls) {
            return (type(ZetherInnerProductVerifierBls12381).creationCode, type(ZetherTransferVerifierBls12381).creationCode,
                type(ZetherBurnVerifierBls12381).creationCode);
        }
        return (type(ZetherInnerProductVerifierBn254).creationCode, type(ZetherTransferVerifierBn254).creationCode,
            type(ZetherBurnVerifierBn254).creationCode);
    }
}
