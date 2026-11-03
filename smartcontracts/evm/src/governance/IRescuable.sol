// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title Rescue of what a token does not owe (CTR-GOV-06, spec §6.2): `RESCUABLE` (17) is set exactly when `rescueTo != 0`,
///        always locked, and `rescueTo` has no writer after `init`. Its own interface, so `IGovernance`'s id stays one on every
///        contract; a token answers it by ERC-165 while bit 17 is set.
interface IRescuable {
    event Rescued(address indexed asset, address indexed to, uint256 amount);

    /// @notice At creation: bit 17 without `rescueTo`, `rescueTo` without bit 17, or `rescueTo` the token itself, `UA_POOL`
    ///         or `SHIELD_POOL`.
    error RescueConfigInvalid();
    /// @notice The token's own units, or the native coin to an EIP-7702 designator `rescueTo`.
    error RescueAssetInvalid(address asset);
    /// @notice A foreign asset whose transfer moved a leg's balance: an alias of the leg (A16).
    error RescueTouchedLeg(address leg);

    /// @notice Anyone, no signature, not an `mtx*`: pays what the token does not owe of `asset` (`address(0)`: the native
    ///         coin) to `rescueTo()`, the first row of spec §6.2 that matches deciding.
    function rescue(address asset) external;
    function rescueTo() external view returns (address);
}
