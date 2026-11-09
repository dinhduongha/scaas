// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @notice A plain kind's `implArgs` (T66b, spec 2026-11-09-t66b-library-organisation.md §4.5): its body modules, decoded once.
struct ImplArgs {
    address[] modules;
}

/// @notice A regulated kind's `implArgs` (8–13): the `ComplianceRegistry` runtime's code hash and its body modules.
struct RegulatedImplArgs {
    bytes32 registryCodehash;
    address[] modules;
}

/// @notice The identity views of a body module that its implementation's constructor checks (§4.5; Fable P2-1, P2-A): none
///         reads value-bearing state, so each answers a direct call.
interface ITokenModule {
    function kind() external pure returns (uint8);
    function moduleGroup() external pure returns (uint8);
    function factory() external view returns (address);
    function REGISTRY_CODEHASH() external view returns (bytes32);
    function pqzSet() external pure returns (bytes32);
}

/// @notice A release's body modules, in its stubs' order (`OpenFactory._checkImplementation`: each one pinned in the env).
interface ITokenModules {
    function modules() external view returns (address[] memory);
}
