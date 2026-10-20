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

/// @title statement views and disclosure (D14): one of the four `DELEGATECALL` libraries of the PQZ release (plan 5h D14), in the ERC-7201
///        namespace `scaas.pqz`; the shared steps are `internal` in `PqzCore`, compiled into each.
/// @notice **UNAUDITED — NOT FOR PRODUCTION FUNDS.** `address(this)` is the token.
library PqzViewLib {
    /// @notice The statement an entry point would build for `payload` (`op` 7 multi, 1 single, 2 burn / refresh with
    ///         `e.amount`, `e.recipient`), after every cheap check; a transfer payload with the memo is commit-reveal.
    ///         Public, so the builders stay in the library and out of the tokens' code.
    function statementOf(uint8 op, PqzCore.Env memory e, bytes calldata payload, bytes calldata acc, bytes[] calldata inl)
        public view returns (bytes memory)
    {
        bytes memory buf;
        if (op == 7) {
            e.mode = PqzCore.multiHasMemo(payload) ? ZetherTypes.TransferMode.HASH : PqzCore._defaultMode();
            (, buf) = PqzCore.prepareMulti(e, payload, acc, inl, 0);
        } else if (op == 1) {
            uint256 l = payload.length - PqzCore.T_OUT;
            e.mode = l == PqzCore.OUT_ON + PqzCore.MEMO || l == PqzCore.OUT_OFF + PqzCore.MEMO ? ZetherTypes.TransferMode.HASH : PqzCore._defaultMode();
            (, buf) = PqzCore.prepareTransfer(e, payload, acc, inl, 0);
        } else {
            (, buf) = PqzCore.prepareBurn(e, payload, acc, inl, 0);
        }
        return PqzCore._stmtOf(buf);
    }

    /// @notice The disclosure statement of leg `leg` of `ref` (reverts as `PqzCore.disclosureBuffer`).
    function disclosureStatementOf(bytes32 ref, uint256 leg, uint256 amount, uint8 kind, bytes memory bundle, PqzCore.Env memory e)
        public view returns (bytes memory)
    {
        return PqzCore._stmtOf(PqzCore.disclosureBuffer(ref, leg, amount, kind, bundle, e, 0));
    }

    /// @notice The precompile's PqzCore.verdict on the disclosure of leg `leg` with `proof` (the caller checked the shape).
    function verifyAmountOf(
        bytes32 ref,
        uint256 leg,
        uint256 amount,
        uint8 kind,
        bytes memory bundle,
        bytes memory proof,
        PqzCore.Env memory e
    ) public view returns (bool) {
        bytes memory buf = PqzCore.disclosureBuffer(ref, leg, amount, kind, bundle, e, proof.length);
        assembly ("memory-safe") { mcopy(add(add(buf, 37), 33184), add(proof, 32), mload(proof)) }
        return PqzCore.verdict(PqzCore.$().pqz, buf);
    }
}
