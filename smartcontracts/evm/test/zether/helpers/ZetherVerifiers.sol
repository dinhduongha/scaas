// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IZetherVerifier, IZetherBurnVerifier, IZetherInnerProductVerifier} from "../../../src/zether/IZetherVerifier.sol";
import {
    ZetherInnerProductVerifierBls12381,
    ZetherTransferVerifierBls12381,
    ZetherBurnVerifierBls12381
} from "../../../src/zether/ZetherVerifier.sol";

/// @notice The BLS12-381 verifiers (CTR-ZTH-20 split: inner-product, transfer, burn), deployed directly for the tests
///         (the bn254 ones are in `legacy/ua6/`).
library ZetherVerifiers {
    function deploy() internal returns (IZetherVerifier t, IZetherBurnVerifier b) {
        IZetherInnerProductVerifier ip = new ZetherInnerProductVerifierBls12381();
        t = IZetherVerifier(address(new ZetherTransferVerifierBls12381(ip)));
        b = IZetherBurnVerifier(address(new ZetherBurnVerifierBls12381(ip)));
    }
}
