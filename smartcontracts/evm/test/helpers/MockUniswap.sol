// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IUniswapV3Factory, IUniswapV3SwapCallback} from "../../src/dex/uniswap/IUniswapV3.sol";
import {IPoolManager, IUnlockCallback, PoolKey, SwapParams, BalanceDelta} from "../../src/dex/uniswap/IUniswapV4.sol";

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

/// A v3-shaped pool made by `MockV3Factory` through CREATE2 (no constructor arguments: it reads them from its factory,
/// as Uniswap's pools do). Exact input only, priced as the v2 pair on its balances; `maxIn` caps what one swap consumes
/// (a price limit / thin liquidity) so a route can leave the input unspent.
contract MockV3Pool {
    address public immutable token0;
    address public immutable token1;
    uint24 public immutable fee;
    uint256 public maxIn = type(uint256).max;

    constructor() {
        (token0, token1, fee) = MockV3Factory(msg.sender).parameters();
    }

    function setMaxIn(uint256 m) external {
        maxIn = m;
    }

    function swap(address recipient, bool zeroForOne, int256 amountSpecified, uint160, bytes calldata data)
        external returns (int256 a0, int256 a1)
    {
        require(amountSpecified > 0, "exact input only");
        (address tIn, address tOut) = zeroForOne ? (token0, token1) : (token1, token0);
        uint256 amountIn = uint256(amountSpecified) < maxIn ? uint256(amountSpecified) : maxIn;
        uint256 rIn = IERC20(tIn).balanceOf(address(this));
        uint256 out = v2AmountOut(amountIn, rIn, IERC20(tOut).balanceOf(address(this)));
        IERC20(tOut).transfer(recipient, out);
        (a0, a1) = zeroForOne ? (int256(amountIn), -int256(out)) : (-int256(out), int256(amountIn));
        IUniswapV3SwapCallback(msg.sender).uniswapV3SwapCallback(a0, a1, data);
        require(IERC20(tIn).balanceOf(address(this)) >= rIn + amountIn, "IIA");
    }
}

/// A v3-shaped factory: pools at CREATE2(this, keccak(token0, token1, fee), keccak(MockV3Pool creation code)).
contract MockV3Factory is IUniswapV3Factory {
    mapping(address => mapping(address => mapping(uint24 => address))) public getPool;
    address p0;
    address p1;
    uint24 pFee;

    function poolInitCodeHash() external pure returns (bytes32) {
        return keccak256(type(MockV3Pool).creationCode);
    }

    function parameters() external view returns (address, address, uint24) {
        return (p0, p1, pFee);
    }

    function createPool(address a, address b, uint24 fee) external returns (address pool) {
        (p0, p1, pFee) = a < b ? (a, b, fee) : (b, a, fee);
        pool = address(new MockV3Pool{salt: keccak256(abi.encode(p0, p1, fee))}());
        getPool[a][b][fee] = pool;
        getPool[b][a][fee] = pool;
        (p0, p1, pFee) = (address(0), address(0), 0);
    }
}

/// A v4-shaped `PoolManager`: `unlock` calls back the caller and then requires every delta settled; pools are seeded
/// reserves (`seed`, the tokens sent separately) priced as the v2 pair; exact input only; `sync` / `settle` / `take` as
/// v4 (no native coin, no hooks, no fees to LPs beyond the 0.3 % of `v2AmountOut`).
contract MockPoolManager is IPoolManager {
    mapping(bytes32 => uint256[2]) public reserves;
    mapping(address => int256) public delta;
    uint256 nonzero;
    bool unlocked;
    address synced;
    uint256 syncedBalance;

    function seed(PoolKey calldata key, uint256 r0, uint256 r1) external {
        reserves[keccak256(abi.encode(key))] = [r0, r1];
    }

    function unlock(bytes calldata data) external returns (bytes memory r) {
        require(!unlocked, "AlreadyUnlocked");
        unlocked = true;
        r = IUnlockCallback(msg.sender).unlockCallback(data);
        require(nonzero == 0, "CurrencyNotSettled");
        unlocked = false;
    }

    function swap(PoolKey memory key, SwapParams memory p, bytes calldata) external returns (BalanceDelta) {
        require(unlocked && p.amountSpecified < 0, "exact input in an unlock only");
        uint256[2] storage r = reserves[keccak256(abi.encode(key))];
        uint256 amountIn = uint256(-p.amountSpecified);
        (uint256 i, uint256 o) = p.zeroForOne ? (0, 1) : (1, 0);
        uint256 out = v2AmountOut(amountIn, r[i], r[o]);
        r[i] += amountIn;
        r[o] -= out;
        (int128 d0, int128 d1) = p.zeroForOne
            ? (-int128(int256(amountIn)), int128(int256(out)))
            : (int128(int256(out)), -int128(int256(amountIn)));
        _acct(key.currency0, d0);
        _acct(key.currency1, d1);
        return BalanceDelta.wrap((int256(d0) << 128) | int256(uint256(uint128(d1))));
    }

    function sync(address currency) external {
        (synced, syncedBalance) = (currency, IERC20(currency).balanceOf(address(this)));
    }

    function settle() external payable returns (uint256 paid) {
        paid = IERC20(synced).balanceOf(address(this)) - syncedBalance;
        _acct(synced, int256(paid));
        synced = address(0);
    }

    function take(address currency, address to, uint256 amount) external {
        _acct(currency, -int256(amount));
        IERC20(currency).transfer(to, amount);
    }

    function _acct(address c, int256 change) private {
        int256 before = delta[c];
        int256 next = before + change;
        if (before == 0 && next != 0) ++nonzero;
        else if (before != 0 && next == 0) --nonzero;
        delta[c] = next;
    }
}
