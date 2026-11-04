// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title What a governed contract asks its chain's `GovernanceRouter` (CTR-GOV-01 and CTR-GOV-15 Changes, owner
///        2026-11-04; spec `2026-11-04-governance-ua-identity.md` §2, §3). The router itself is plan task T11.
interface IGovernanceRouter {
    /// @notice The UA the router authenticated for the call it is making to `msg.sender` now; 0 outside a live call.
    function subject() external view returns (bytes32);
}
