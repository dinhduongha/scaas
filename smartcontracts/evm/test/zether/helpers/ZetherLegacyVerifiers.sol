// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IZetherVerifier, IZetherBurnVerifier} from "../../../src/zether/IZetherVerifier.sol";
import {
    ZetherInnerProductVerifierBls12381 as OldInnerProduct,
    ZetherTransferVerifierBls12381 as OldTransfer,
    ZetherBurnVerifierBls12381 as OldBurn
} from "../../../legacy/zether-msm/ZetherVerifier.sol";

/// @notice The per-equation verifiers of `legacy/zether-msm/` (eight Σ MSMs, two per Bulletproof), for the differential
///         suite: old and new must agree on the whole corpus. Test only, never deployed.
library ZetherLegacyVerifiers {
    function deploy() internal returns (IZetherVerifier t, IZetherBurnVerifier b) {
        OldInnerProduct ip = new OldInnerProduct();
        t = IZetherVerifier(address(new OldTransfer(ip)));
        b = IZetherBurnVerifier(address(new OldBurn(ip)));
    }
}
