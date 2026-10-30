// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// Uniswap v2 `getAmountOut` (0.3 % fee): what a pair with these reserves pays for `amountIn`.
function v2AmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut) pure returns (uint256) {
    uint256 x = amountIn * 997;
    return x * reserveOut / (reserveIn * 1000 + x);
}

/// A constant-product pair in the shape of a Uniswap v2 pair (tokens sorted, `getReserves`, `swap`, `sync`): paid
/// first by a transfer, `swap` sends the asked amounts and checks the fee-adjusted invariant against the stored
/// reserves. No LP shares, no flash-swap callback, no TWAP.
contract MockV2Pair {
    address public immutable token0;
    address public immutable token1;
    uint112 reserve0;
    uint112 reserve1;

    constructor(address a, address b) {
        (token0, token1) = a < b ? (a, b) : (b, a);
    }

    function getReserves() external view returns (uint112, uint112, uint32) {
        return (reserve0, reserve1, 0);
    }

    function sync() public {
        reserve0 = uint112(IERC20(token0).balanceOf(address(this)));
        reserve1 = uint112(IERC20(token1).balanceOf(address(this)));
    }

    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata) external {
        if (amount0Out != 0) IERC20(token0).transfer(to, amount0Out);
        if (amount1Out != 0) IERC20(token1).transfer(to, amount1Out);
        uint256 b0 = IERC20(token0).balanceOf(address(this));
        uint256 b1 = IERC20(token1).balanceOf(address(this));
        uint256 in0 = b0 + amount0Out - reserve0;
        uint256 in1 = b1 + amount1Out - reserve1;
        require((b0 * 1000 - in0 * 3) * (b1 * 1000 - in1 * 3) >= uint256(reserve0) * reserve1 * 1e6, "K");
        sync();
    }
}
