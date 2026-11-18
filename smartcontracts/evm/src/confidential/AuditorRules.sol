// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {GovernanceLib} from "../governance/GovernanceLib.sol";
import {GovernanceBits} from "../governance/GovernanceBits.sol";
import {IGovernance} from "../governance/IGovernance.sol";
import {IConfidentialToken} from "./IConfidentialToken.sol";

/// @title The rules both confidential families share for replacing the auditor on bit 32 `AUDITOR` (set-auditor spec §4, §5.1,
///        §8; CTR-GOV-31): the confirm window, the status of a stored proposal, the proposer and epoch checks, the
///        `AuditorConsent` digest. Internal only, compiled into `ZetherLib` and `PqzStateLib`; each family keeps its own fields.
/// @notice **UNAUDITED.**
library AuditorRules {
    /// @notice A proposal is confirmable in `[eta, eta + AUDITOR_CONFIRM_WINDOW]`, whatever the delay (coordinator ruling,
    ///         spec §4, O12): never an empty window, and an unconfirmed proposal frees the slot after it.
    uint64 internal constant AUDITOR_CONFIRM_WINDOW = 7 days;
    bytes32 internal constant AUDITOR_CONSENT_TYPEHASH =
        keccak256("AuditorConsent(address token,bytes32 auditor,uint32 epoch,bytes32 chainUid)");

    uint8 internal constant NONE = 0;
    uint8 internal constant WAITING = 1;
    uint8 internal constant CONFIRMABLE = 2;
    uint8 internal constant EXPIRED = 3;
    uint8 internal constant VOID = 4;

    /// @notice The status of a stored proposal (`eta` 0: none): void once bit 32 is off or its proposer's role epoch moved (a
    ///         revoke or a renounce bumps it, a re-grant does not restore it); then waiting, confirmable or expired by time.
    function status(uint64 eta, uint32 roleEpoch, bytes32 proposer) internal view returns (uint8) {
        if (eta == 0) return NONE;
        GovernanceLib.GovernanceStorage storage g = GovernanceLib.$();
        if (g.features >> GovernanceBits.AUDITOR & 1 == 0 || g.epoch[GovernanceBits.AUDITOR][proposer] != roleEpoch) return VOID;
        if (block.timestamp < eta) return WAITING;
        if (block.timestamp <= uint256(eta) + AUDITOR_CONFIRM_WINDOW) return CONFIRMABLE;
        return EXPIRED;
    }

    /// @notice Waiting or confirmable: the proposal holds the slot.
    function live(uint64 eta, uint32 roleEpoch, bytes32 proposer) internal view returns (bool) {
        uint8 st = status(eta, roleEpoch, proposer);
        return st == WAITING || st == CONFIRMABLE;
    }

    /// @notice `epoch` is the one the new auditor takes, `current + 1` (spec §5.1 step 2).
    function requireNext(uint32 current, uint32 epoch) internal pure {
        if (epoch != current + 1) revert IConfidentialToken.AuditorEpochMismatch(current + 1, epoch);
    }

    /// @notice A confirm or a cancel comes from the holder that proposed.
    function requireProposer(bytes32 caller, bytes32 proposer) internal pure {
        if (caller != proposer) revert IGovernance.NotProposer(GovernanceBits.AUDITOR, bytes32(0), proposer);
    }

    /// @notice The proposer's role epoch on bit 32, stored with the proposal.
    function roleEpochOf(bytes32 holder) internal view returns (uint32) {
        return GovernanceLib.$().epoch[GovernanceBits.AUDITOR][holder];
    }

    /// @notice The typed `AuditorConsent` of this token (`address(this)` under `DELEGATECALL`) under its EIP-712 domain.
    function consentDigest(bytes32 domainSeparator, bytes32 auditor, uint32 epoch, bytes32 chainUid)
        internal view returns (bytes32)
    {
        return keccak256(abi.encodePacked(hex"1901", domainSeparator,
            keccak256(abi.encode(AUDITOR_CONSENT_TYPEHASH, address(this), auditor, epoch, chainUid))));
    }

    /// @notice `auditorState()` from the stored fields (spec §8): with bit 32 off the proposal fields read 0, status void.
    function state(uint32 epoch, bytes32 pending, uint64 eta, bytes32 proposer, uint32 roleEpoch)
        internal view returns (uint32, bytes32, uint64, bytes32, uint8 st)
    {
        st = status(eta, roleEpoch, proposer);
        if (st == VOID && GovernanceLib.$().features >> GovernanceBits.AUDITOR & 1 == 0) return (epoch, 0, 0, 0, st);
        return (epoch, pending, eta, proposer, st);
    }
}
