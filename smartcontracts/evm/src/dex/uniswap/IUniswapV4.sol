// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// Minimal Uniswap v4 types and `PoolManager` interface (written in-repo, ABI-compatible with Uniswap's deployments;
/// no Uniswap source). `Currency` and `IHooks` are addresses on the ABI; address 0 is the native coin.

struct PoolKey {
    address currency0;
    address currency1;
    uint24 fee;
    int24 tickSpacing;
    address hooks;
}

/// `amountSpecified < 0` = exact input.
struct SwapParams {
    bool zeroForOne;
    int256 amountSpecified;
    uint160 sqrtPriceLimitX96;
}

/// `amount0` in the upper 128 bits, `amount1` in the lower; positive = owed to the caller.
type BalanceDelta is int256;

interface IPoolManager {
    function unlock(bytes calldata data) external returns (bytes memory);
    function swap(PoolKey memory key, SwapParams memory params, bytes calldata hookData)
        external returns (BalanceDelta);
    function sync(address currency) external;
    function settle() external payable returns (uint256 paid);
    function take(address currency, address to, uint256 amount) external;
}

interface IUnlockCallback {
    function unlockCallback(bytes calldata data) external returns (bytes memory);
}
