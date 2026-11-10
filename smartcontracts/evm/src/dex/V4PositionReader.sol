// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IPositionReader} from "./IPositionReader.sol";
import {PoolKey} from "./uniswap/IUniswapV4.sol";

/// @notice The views of Uniswap v4's `PositionManager` the reader needs; `info` is v4-periphery's packed `PositionInfo`
///         (bits 0-7 `hasSubscriber`, 8-31 `tickLower`, 32-55 `tickUpper`, the upper 200 bits a truncated pool id).
interface IV4PositionManager {
    function getPoolAndPositionInfo(uint256 tokenId) external view returns (PoolKey memory poolKey, uint256 info);
    function getPositionLiquidity(uint256 tokenId) external view returns (uint128 liquidity);
}

/// @title The position reader of a Uniswap v4 `PositionManager` (CTR-DEX-31, spec 2026-11-10-dex-liquidity.md §7.1): the pool
///        id is `keccak256(abi.encode(poolKey))` (the hooks address included, so a hostile hook is another pool), the ticks
///        from the packed info, the liquidity from `getPositionLiquidity`, encumbered while a subscriber is set
///        [inference, checked against v4-periphery at the fork block]. Immutables only, no admin. UNAUDITED.
contract V4PositionReader is IPositionReader {
    address public immutable manager;

    constructor(address positionManager) {
        manager = positionManager;
    }

    function position(uint256 tokenId) external view
        returns (bytes32 poolId, int24 tickLower, int24 tickUpper, uint128 liquidity, bool encumbered)
    {
        (PoolKey memory key, uint256 info) = IV4PositionManager(manager).getPoolAndPositionInfo(tokenId);
        poolId = keccak256(abi.encode(key));
        tickLower = int24(int256(info >> 8));   // the low 24 bits, sign-extended by the narrowing cast
        tickUpper = int24(int256(info >> 32));
        encumbered = info & 0xff != 0;
        liquidity = IV4PositionManager(manager).getPositionLiquidity(tokenId);
    }
}
