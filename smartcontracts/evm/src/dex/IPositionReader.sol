// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title A position reader (CTR-DEX-31, spec 2026-11-10-dex-liquidity.md §7.1): read-only, one per position-manager family,
///        no state, no admin; signed in a `LiquidityOrder` and listed by a holder of `LISTING` (`setExchangeTarget`).
interface IPositionReader {
    /// @notice The one position manager it reads (immutable).
    function manager() external view returns (address);

    /// @notice `poolId`: v4 the `PoolId` (keccak256 of the `PoolKey`), v3 the pool address as bytes32. `encumbered`:
    ///         anything that lets a third party act on the position after a transfer (v4: a subscriber).
    function position(uint256 tokenId) external view
        returns (bytes32 poolId, int24 tickLower, int24 tickUpper, uint128 liquidity, bool encumbered);
}
