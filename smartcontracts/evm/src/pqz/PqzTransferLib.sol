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

/// @title op 1 and op 7 transfers (D14): one of the four `DELEGATECALL` libraries of the PQZ release (plan 5h D14), in the ERC-7201
///        namespace `scaas.pqz`; the shared steps are `internal` in `PqzCore`, compiled into each.
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** `address(this)` is the token.
library PqzTransferLib {
    /// @notice One-recipient transfer: checks, statement, `authSig`, proof, then the debit, the credit, the fee, the
    ///         entry by `mode` (HASH commit-reveal, BUNDLE stored, NONE nothing).
    ///      Arguments ordered for the stack: the ones used last on top.
    function transfer(
        PqzCore.Env memory e,
        bytes calldata payload,
        bytes calldata hint,
        bytes calldata proof,
        bytes calldata authSig
    ) public returns (bytes32 ref) {
        (PqzCore.Op memory o, bytes memory buf) = PqzCore.prepareTransfer(e, payload, hint, proof.length);
        PqzCore._check(o, buf, proof, authSig);
        ref = PqzCore._settleTransfer(o, payload);
    }

    /// @notice Op 7 `R_TXM`: `M` legs (decoys are legs of amount 0), one proof; the sender exactly as a single transfer,
    ///         a credit per leg, the fee once, the entry by `mode`. Payload: `p ‖ validUntilBlock ‖ shieldIn ‖ fromUA ‖
    ///         beneficiaryUA ‖ M ‖ salt(16) ‖ UA_0 … UA_{M−1} ‖ out ‖ [memo]`, `out = u_0 … u_{G−1} ‖ v_0 … v_{M−1} ‖ v_f ‖
    ///         [v_{a,0} … v_{a,M−1}]`, memo `18 + 40·M` bytes on HASH.
    function transferMulti(
        PqzCore.Env memory e,
        bytes calldata payload,
        bytes calldata hint,
        bytes calldata proof,
        bytes calldata authSig
    ) public returns (bytes32 ref) {
        (PqzCore.Op memory o, bytes memory buf) = PqzCore.prepareMulti(e, payload, hint, proof.length);
        PqzCore._check(o, buf, proof, authSig);
        ref = PqzCore._settleMulti(o, payload);
    }
}
