// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IPositionReader} from "./IPositionReader.sol";
import {IUniswapV3Factory} from "./uniswap/IUniswapV3.sol";

/// @notice The view of Uniswap v3's `NonfungiblePositionManager` the reader needs.
interface IV3PositionManager {
    function positions(uint256 tokenId) external view returns (uint96 nonce, address operator, address token0,
        address token1, uint24 fee, int24 tickLower, int24 tickUpper, uint128 liquidity, uint256 feeGrowthInside0LastX128,
        uint256 feeGrowthInside1LastX128, uint128 tokensOwed0, uint128 tokensOwed1);
}

/// @title The position reader of a Uniswap v3 `NonfungiblePositionManager` (CTR-DEX-31, spec 2026-11-10-dex-liquidity.md
///        §7.1): the pool is the factory's pool of the position's tokens and fee, as bytes32; never encumbered (v3's
///        per-token approval, the position's `operator`, is cleared by the transfer [inference, checked by the fork
///        test]). Immutables only, no admin. UNAUDITED.
contract V3PositionReader is IPositionReader {
    address public immutable manager;
    address public immutable factory;

    constructor(address npm, address v3Factory) {
        (manager, factory) = (npm, v3Factory);
    }

    function position(uint256 tokenId) external view
        returns (bytes32 poolId, int24 tickLower, int24 tickUpper, uint128 liquidity, bool encumbered)
    {
        address t0;
        address t1;
        uint24 fee;
        (,, t0, t1, fee, tickLower, tickUpper, liquidity,,,,) = IV3PositionManager(manager).positions(tokenId);
        poolId = bytes32(uint256(uint160(IUniswapV3Factory(factory).getPool(t0, t1, fee))));
        encumbered = false;
    }
}
