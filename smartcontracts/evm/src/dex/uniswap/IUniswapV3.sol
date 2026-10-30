// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// Minimal Uniswap v3 interfaces (written in-repo, ABI-compatible with Uniswap's deployments; no Uniswap source).

interface IUniswapV3Pool {
    /// Exact input when `amountSpecified > 0`; the pool sends the output to `recipient`, then calls
    /// `uniswapV3SwapCallback` on `msg.sender`, which must pay the positive delta.
    function swap(address recipient, bool zeroForOne, int256 amountSpecified, uint160 sqrtPriceLimitX96,
        bytes calldata data) external returns (int256 amount0, int256 amount1);
}

interface IUniswapV3Factory {
    function getPool(address tokenA, address tokenB, uint24 fee) external view returns (address pool);
}

interface IUniswapV3SwapCallback {
    function uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata data) external;
}
