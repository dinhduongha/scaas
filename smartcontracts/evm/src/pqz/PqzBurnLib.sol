// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IFactoryToken} from "../factory/IFactoryToken.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {ZetherTypes} from "../zether/ZetherTypes.sol";
import {IPqzToken} from "./IPqzToken.sol";
import {PqzCt} from "./PqzCt.sol";
import {PqzSafety} from "./PqzSafety.sol";
import {UAPqzVerifier} from "./UAPqzVerifier.sol";
import {PqzCore} from "./PqzCore.sol";

/// @title burn, refresh and the unwrap debit (D14): one of the four `DELEGATECALL` libraries of the PQZ release (plan 5h D14), in the ERC-7201
///        namespace `scaas.pqz`; the shared steps are `internal` in `PqzCore`, compiled into each.
/// @notice **UNAUDITED.** `address(this)` is the token.
library PqzBurnLib {
    /// @notice `R_BURN`: the debit with `amount` public (0 = refresh); the token then moves `paid` (D19)
    ///         and pays `amount · shieldScale`.
    function unshield(
        PqzCore.Env memory e,
        bytes calldata payload,
        bytes calldata hint,
        bytes calldata proof,
        bytes calldata authSig
    ) public returns (PqzCore.Paid memory paid) {
        (PqzCore.Op memory o, bytes memory buf) = PqzCore.prepareBurn(e, payload, hint, proof.length);
        PqzCore._check(o, buf, proof, authSig);
        PqzCore._settleBurn(o, payload[PqzCore.B_OUT:PqzCore.B_OUT + PqzCt.CT]);
        paid = PqzCore._paid(o);
    }
}
