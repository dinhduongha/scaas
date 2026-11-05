// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @notice Placeholder of the skeleton (plan T27): every body below and every token-side check of `RegulatedBase` reverts
///         with it until T28 (FREEZE, RECORD, FORCE, PAUSE), T29 (the receiver check) and T32 (`operatorTransfer`) replace
///         it. A regulated kind cannot be created before then: `init` reverts (fail closed).
error RegulatedNotBuilt();

/// @title The bodies of the regulated controls (CTR-AS-02's shape, regulated-kinds spec §3.1), reached by `DELEGATECALL`
///        from the thin stubs of `RegulatedBase`: storage is the token's `scaas.regulated` namespace, `address(this)` the
///        token, `msg.sender` the direct caller (the router or the holder, never the subject): the token passes
///        `_govSubject()` and every immutable it needs as arguments.
/// @notice **UNAUDITED.** Skeleton (plan T27): the arity is final, every body reverts `RegulatedNotBuilt`. In the release's
///         link closure of every regulated kind 8-13 (`Env.libs`, `libCodeHashes`).
library RegulatedLib {
    /// @notice The checks of spec §2.4 on the factory's raw `initArgs`, before the kind's own init and any mint.
    function init(bytes calldata /* initArgs */) public pure {
        revert RegulatedNotBuilt();
    }

    function freeze(bytes32 /* account */, bytes32 /* ref */, bytes32 /* recordId */, bytes32 /* subject */) public pure {
        revert RegulatedNotBuilt();
    }

    function unfreeze(bytes32 /* account */, bytes32 /* ref */, bytes32 /* subject */) public pure {
        revert RegulatedNotBuilt();
    }

    /// @notice The record's checks and `executed += amount`; returns the move the token makes (`_poolMove`, which the
    ///         library cannot reach).
    function forceTransfer(bytes32 /* recordId */, uint256 /* amount */, bytes32 /* subject */)
        public pure returns (bytes32 /* from */, bytes32 /* to */)
    {
        revert RegulatedNotBuilt();
    }

    function pause(bytes32 /* ref */, uint64 /* until */, bytes32 /* subject */) public pure {
        revert RegulatedNotBuilt();
    }

    function unpause(bytes32 /* ref */, bytes32 /* subject */) public pure {
        revert RegulatedNotBuilt();
    }

    function recordOrder(bytes32 /* orderId */, bytes32 /* documentHash */, bytes32 /* recordSubject */,
        bytes32 /* beneficiary */, uint256 /* maxAmount */, uint64 /* freezeUntil */, bytes32 /* subject */) public pure
    {
        revert RegulatedNotBuilt();
    }

    function revokeOrder(bytes32 /* recordId */, bytes32 /* reasonRef */, bytes32 /* subject */) public pure {
        revert RegulatedNotBuilt();
    }

    /// @notice The refusals of CTR-GOV-08 and CTR-GOV-13 and the power's `use`; the token then moves on `_uaMove` (hooked).
    function operatorTransfer(bytes32 /* from */, bytes32 /* to */, uint256 /* amount */, bytes32 /* ref */,
        bytes32 /* subject */, address /* uaRegistry */) public pure
    {
        revert RegulatedNotBuilt();
    }
}
