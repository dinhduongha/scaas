// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.28;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IExchangeExecutor} from "./ISCaaSDex.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {IUniswapV3Pool, IUniswapV3SwapCallback} from "./uniswap/IUniswapV3.sol";
import {IPoolManager, IUnlockCallback, PoolKey, SwapParams, BalanceDelta} from "./uniswap/IUniswapV4.sol";

/// @title The reference executor of `mtxExchangeVia` / `mtxHybridVia` (spec §9, DX15, CTR-DEX-20 (b)).
/// @notice Runs `data = abi.encode(Hop[])` in order, exact input, each hop on the executor's **whole** balance of its
///         input token (no predicted intermediate amounts). Kind 1 = a Uniswap v3 pool `(tokenIn, tokenOut, fee)`;
///         kind 2 = a v4 pool `(PoolKey, zeroForOne)`; if any hop is v4, every hop runs inside one `unlock`. At the end
///         the whole balance of each `tokensIn` and `tokensOut` goes to the DEX (output above the floors is the signers'
///         surplus; unsold input is the DEX's to refund or refuse, DX7) and every hop token must be at 0
///         (`Leftover`): it holds nothing between calls, and a stray balance becomes surplus at its next use.
///         Only the DEX calls it; a v3 callback pays only the pool it derives by CREATE2 from its factory; a v4
///         callback runs only from the PoolManager inside an unlock this executor started. No admin, owner, upgrade
///         or sweep. Its callers are unguarded (D4): any submitter may name it; the DEX's floors bound the route.
contract UniswapExecutor is IExchangeExecutor, IUniswapV3SwapCallback, IUnlockCallback {
    using SafeERC20 for IERC20;

    struct Hop {
        uint8 kind;
        bytes args;
    }

    /// TickMath MIN_SQRT_RATIO + 1 / MAX_SQRT_RATIO − 1 (v3 and v4 share them): no price limit.
    uint160 private constant MIN_SQRT = 4295128740;
    uint160 private constant MAX_SQRT = 1461446703485210103287273052203988822378723970341;

    address public immutable DEX;
    address public immutable V3_FACTORY; // 0 = v3 hops off
    bytes32 public immutable V3_POOL_INIT_CODE_HASH;
    address public immutable V4_POOL_MANAGER; // 0 = v4 hops off

    bool private transient unlocking;

    error NotDex();
    error NotPool();
    error NotPoolManager();
    error NativeCurrency();
    error Leftover(address token);
    error NotAContract(address a);
    error HopKindOff(uint8 kind);

    /// @dev D5: the DEX, and the v3 factory / v4 pool manager when set, must be contracts.
    constructor(address dex, address v3Factory, bytes32 v3PoolInitCodeHash, address v4PoolManager) {
        if (!SigCheck.isContract(dex)) revert NotAContract(dex);
        if (v3Factory != address(0) && !SigCheck.isContract(v3Factory)) revert NotAContract(v3Factory);
        if (v4PoolManager != address(0) && !SigCheck.isContract(v4PoolManager)) revert NotAContract(v4PoolManager);
        DEX = dex;
        V3_FACTORY = v3Factory;
        V3_POOL_INIT_CODE_HASH = v3PoolInitCodeHash;
        V4_POOL_MANAGER = v4PoolManager;
    }

    function exchangeCallback(bytes32, address[] calldata tokensOut, uint256[] calldata,
        address[] calldata tokensIn, uint256[] calldata, bytes calldata data) external
    {
        if (msg.sender != DEX) revert NotDex();
        Hop[] memory hops = abi.decode(data, (Hop[]));
        bool v4;
        for (uint256 i; i < hops.length; ++i) if (hops[i].kind == 2) v4 = true;
        if (v4) {
            if (V4_POOL_MANAGER == address(0)) revert HopKindOff(2);
            unlocking = true;
            IPoolManager(V4_POOL_MANAGER).unlock(data);
        } else {
            _run(hops);
        }
        for (uint256 i; i < tokensIn.length; ++i) _flush(tokensIn[i]);
        for (uint256 i; i < tokensOut.length; ++i) _flush(tokensOut[i]);
        for (uint256 i; i < hops.length; ++i) {
            (address t0, address t1) = _tokens(hops[i]);
            if (IERC20(t0).balanceOf(address(this)) != 0) revert Leftover(t0);
            if (IERC20(t1).balanceOf(address(this)) != 0) revert Leftover(t1);
        }
    }

    /// @dev Pays only `CREATE2(V3_FACTORY, keccak(token0, token1, fee), V3_POOL_INIT_CODE_HASH)` of the hop it names; a
    ///      real pool calls back only its own `swap` caller, so this is the pool the executor just called.
    function uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata data) external {
        (address tIn, address tOut, uint24 fee) = abi.decode(data, (address, address, uint24));
        if (V3_FACTORY == address(0) || msg.sender != _v3Pool(tIn, tOut, fee)) revert NotPool();
        IERC20(tIn).safeTransfer(msg.sender, uint256(amount0Delta > 0 ? amount0Delta : amount1Delta));
    }

    function unlockCallback(bytes calldata data) external returns (bytes memory) {
        if (msg.sender != V4_POOL_MANAGER || !unlocking) revert NotPoolManager();
        unlocking = false;
        _run(abi.decode(data, (Hop[])));
        return "";
    }

    function _run(Hop[] memory hops) private {
        for (uint256 i; i < hops.length; ++i) {
            Hop memory h = hops[i];
            if (h.kind == 1 && V3_FACTORY != address(0)) _v3Hop(h.args);
            else if (h.kind == 2) _v4Hop(h.args); // only reached inside the unlock: V4_POOL_MANAGER is set
            else revert HopKindOff(h.kind);
        }
    }

    function _v3Hop(bytes memory args) private {
        (address tIn, address tOut, uint24 fee) = abi.decode(args, (address, address, uint24));
        bool zeroForOne = tIn < tOut;
        IUniswapV3Pool(_v3Pool(tIn, tOut, fee)).swap(address(this), zeroForOne, int256(_bal(tIn)),
            zeroForOne ? MIN_SQRT : MAX_SQRT, args);
    }

    /// @dev Exact input of the whole balance; the input owed is settled (sync / transfer / settle), the output taken.
    ///      Any other delta sign is left unsettled, so the PoolManager reverts the unlock.
    function _v4Hop(bytes memory args) private {
        (PoolKey memory key, bool zeroForOne) = abi.decode(args, (PoolKey, bool));
        if (key.currency0 == address(0) || key.currency1 == address(0)) revert NativeCurrency();
        (address cIn, address cOut) = zeroForOne ? (key.currency0, key.currency1) : (key.currency1, key.currency0);
        IPoolManager pm = IPoolManager(V4_POOL_MANAGER);
        int256 d = BalanceDelta.unwrap(
            pm.swap(key, SwapParams(zeroForOne, -int256(_bal(cIn)), zeroForOne ? MIN_SQRT : MAX_SQRT), ""));
        (int128 dIn, int128 dOut) = zeroForOne ? (int128(d >> 128), int128(d)) : (int128(d), int128(d >> 128));
        if (dIn < 0) {
            pm.sync(cIn);
            IERC20(cIn).safeTransfer(address(pm), uint256(-int256(dIn)));
            pm.settle();
        }
        if (dOut > 0) pm.take(cOut, address(this), uint256(int256(dOut)));
    }

    function _tokens(Hop memory h) private pure returns (address, address) {
        if (h.kind == 1) {
            (address tIn, address tOut,) = abi.decode(h.args, (address, address, uint24));
            return (tIn, tOut);
        }
        (PoolKey memory key,) = abi.decode(h.args, (PoolKey, bool));
        return (key.currency0, key.currency1);
    }

    function _v3Pool(address a, address b, uint24 fee) private view returns (address) {
        (address t0, address t1) = a < b ? (a, b) : (b, a);
        return address(uint160(uint256(keccak256(abi.encodePacked(hex"ff", V3_FACTORY,
            keccak256(abi.encode(t0, t1, fee)), V3_POOL_INIT_CODE_HASH)))));
    }

    function _flush(address token) private {
        uint256 b = _bal(token);
        if (b != 0) IERC20(token).safeTransfer(DEX, b);
    }

    function _bal(address token) private view returns (uint256) {
        return IERC20(token).balanceOf(address(this));
    }
}
