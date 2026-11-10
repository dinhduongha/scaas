// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {PoolKey} from "../../src/dex/uniswap/IUniswapV4.sol";
import {ITradeToken, ILiquidityPullToken} from "../../src/trade/ITradeToken.sol";
import {IUARegistry} from "../../src/ua/IUARegistry.sol";
import {IPositionReader} from "../../src/dex/IPositionReader.sol";

/// Test mocks of the liquidity spec (2026-11-10-dex-liquidity.md §14). Test only, UNAUDITED.

/// A Uniswap v2-style pair with an ERC-20 LP: `mint(to)` / `burn(to)` on what was paid in by transfer, v2's math
/// (`sqrt`, `MINIMUM_LIQUIDITY` locked at a dead address), `sync`, `skim`. No swap, no fee, no TWAP.
contract MockV2LiquidityPair is ERC20 {
    uint256 public constant MINIMUM_LIQUIDITY = 1000;
    address public immutable token0;
    address public immutable token1;
    uint256 public reserve0;
    uint256 public reserve1;

    constructor(address a, address b) ERC20("LP", "LP") {
        (token0, token1) = a < b ? (a, b) : (b, a);
    }

    function mint(address to) external returns (uint256 liquidity) {
        uint256 b0 = IERC20(token0).balanceOf(address(this));
        uint256 b1 = IERC20(token1).balanceOf(address(this));
        (uint256 a0, uint256 a1) = (b0 - reserve0, b1 - reserve1);
        uint256 ts = totalSupply();
        if (ts == 0) {
            liquidity = Math.sqrt(a0 * a1) - MINIMUM_LIQUIDITY;
            _mint(address(0xdead), MINIMUM_LIQUIDITY);
        } else {
            liquidity = Math.min(a0 * ts / reserve0, a1 * ts / reserve1);
        }
        require(liquidity > 0, "LP: none");
        _mint(to, liquidity);
        (reserve0, reserve1) = (b0, b1);
    }

    function burn(address to) external returns (uint256 a0, uint256 a1) {
        uint256 liq = balanceOf(address(this));
        uint256 ts = totalSupply();
        a0 = liq * IERC20(token0).balanceOf(address(this)) / ts;
        a1 = liq * IERC20(token1).balanceOf(address(this)) / ts;
        _burn(address(this), liq);
        IERC20(token0).transfer(to, a0);
        IERC20(token1).transfer(to, a1);
        sync();
    }

    function sync() public {
        (reserve0, reserve1) = (IERC20(token0).balanceOf(address(this)), IERC20(token1).balanceOf(address(this)));
    }

    function skim(address to) external {
        IERC20(token0).transfer(to, IERC20(token0).balanceOf(address(this)) - reserve0);
        IERC20(token1).transfer(to, IERC20(token1).balanceOf(address(this)) - reserve1);
    }
}

/// `createPair` open to anyone, as v2's factory.
contract MockV2Factory {
    mapping(address => mapping(address => address)) public getPair;

    function createPair(address a, address b) external returns (address pair) {
        require(getPair[a][b] == address(0), "exists");
        pair = address(new MockV2LiquidityPair(a, b));
        (getPair[a][b], getPair[b][a]) = (pair, pair);
    }
}

/// A Uniswap v4-style position manager, reduced: an ERC-721 whose positions hold `liq` units of each currency (one unit
/// of each per unit of liquidity), paid from what was sent to it beforehand (`settle` from its own balance, the rest swept
/// back to `refundTo`); owed fees are collected to the caller on any liquidity change (v4's auto-collect); a subscriber
/// flag; a burnt id's `ownerOf` reverts (OZ). Only the owner or an approved address acts on a position.
contract MockPositionManagerV4 is ERC721 {
    struct Pos {
        PoolKey key;
        int24 lo;
        int24 hi;
        uint128 liq;
        uint256 owed0;
        uint256 owed1;
        bool sub;
    }

    mapping(uint256 => Pos) internal _pos;
    mapping(address => uint256) public reserved; // per currency: what backs the positions and their owed fees
    uint256 public nextId = 1;

    constructor() ERC721("Positions", "POS") {}

    function mint(PoolKey calldata key, int24 lo, int24 hi, uint128 liq, address owner, address refundTo)
        external returns (uint256 id)
    {
        id = nextId++;
        _mint(owner, id);
        Pos storage p = _pos[id];
        (p.key, p.lo, p.hi, p.liq) = (key, lo, hi, liq);
        _take(key, liq, refundTo);
    }

    function increase(uint256 id, uint128 liq, address refundTo) external {
        _auth(id);
        Pos storage p = _pos[id];
        _collect(id, refundTo);
        p.liq += liq;
        _take(p.key, liq, refundTo);
    }

    /// Removes `liq`, pays it and the owed fees to `to`.
    function decrease(uint256 id, uint128 liq, address to) external {
        _auth(id);
        Pos storage p = _pos[id];
        _collect(id, to);
        p.liq -= liq;
        _pay(p.key.currency0, to, liq);
        _pay(p.key.currency1, to, liq);
    }

    /// Owed fees only (v4: a zero decrease).
    function collect(uint256 id, address to) external {
        _auth(id);
        _collect(id, to);
    }

    function burn(uint256 id) external {
        _auth(id);
        require(_pos[id].liq == 0 && _pos[id].owed0 == 0 && _pos[id].owed1 == 0, "not empty");
        _burn(id);
        delete _pos[id];
    }

    /// Test: fees the position earned (the manager must hold them: `reserved` covers them).
    function accrue(uint256 id, uint256 a0, uint256 a1) external {
        Pos storage p = _pos[id];
        (p.owed0, p.owed1) = (p.owed0 + a0, p.owed1 + a1);
        reserved[p.key.currency0] += a0;
        reserved[p.key.currency1] += a1;
        require(IERC20(p.key.currency0).balanceOf(address(this)) >= reserved[p.key.currency0], "fund 0");
        require(IERC20(p.key.currency1).balanceOf(address(this)) >= reserved[p.key.currency1], "fund 1");
    }

    function setSubscriber(uint256 id, bool on) external {
        _pos[id].sub = on;
    }

    function getPoolAndPositionInfo(uint256 id) external view returns (PoolKey memory key, uint256 info) {
        Pos storage p = _pos[id];
        key = p.key;
        info = (uint256(uint24(p.hi)) << 32) | (uint256(uint24(p.lo)) << 8) | (p.sub ? 1 : 0)
            | (uint256(keccak256(abi.encode(p.key))) & ~uint256(type(uint56).max));
    }

    function getPositionLiquidity(uint256 id) external view returns (uint128) {
        return _pos[id].liq;
    }

    function poolId(PoolKey memory key) external pure returns (bytes32) {
        return keccak256(abi.encode(key));
    }

    function _auth(uint256 id) private view {
        address o = ownerOf(id);
        require(msg.sender == o || getApproved(id) == msg.sender || isApprovedForAll(o, msg.sender), "not authorized");
    }

    function _take(PoolKey memory key, uint256 liq, address refundTo) private {
        reserved[key.currency0] += liq;
        reserved[key.currency1] += liq;
        _sweep(key.currency0, refundTo);
        _sweep(key.currency1, refundTo);
    }

    function _sweep(address c, address to) private {
        uint256 b = IERC20(c).balanceOf(address(this));
        require(b >= reserved[c], "short");
        if (b > reserved[c]) IERC20(c).transfer(to, b - reserved[c]);
    }

    function _collect(uint256 id, address to) private {
        Pos storage p = _pos[id];
        (uint256 a0, uint256 a1) = (p.owed0, p.owed1);
        (p.owed0, p.owed1) = (0, 0);
        _pay(p.key.currency0, to, a0);
        _pay(p.key.currency1, to, a1);
    }

    function _pay(address c, address to, uint256 a) private {
        if (a == 0) return;
        reserved[c] -= a;
        IERC20(c).transfer(to, a);
    }
}

/// `claim(user)` pays `user` from the distributor's own balance (the third-party credit of review P1-1).
contract MockDistributor {
    function claim(address token, address user, uint256 amount) external {
        IERC20(token).transfer(user, amount);
    }
}

/// An `mtxExchange`-style contract without `liquidityOrderDigest` (a DEX release before the liquidity spec, review P1-2):
/// it runs a token's `mtxLiquidityPull` of an order signed for it, then moves the pulled tokens to `to`.
contract MockOldDex {
    function run(address token, ITradeToken.LiquidityOrder calldata o, IUARegistry.UASig calldata auth, uint256 amount,
        address to) external
    {
        ILiquidityPullToken(token).mtxLiquidityPull(o, auth, amount, msg.sender);
        IERC20(token).transfer(to, amount);
    }
}

/// A contract answering `liquidityOrderDigest` wrongly: `mode` 1 another word, 2 a short return, 3 the right word only when
/// `right` is set (a positive control computed by the test).
contract MockWrongDex {
    uint8 public mode;
    bytes32 public right;

    function set(uint8 m, bytes32 r) external {
        (mode, right) = (m, r);
    }

    function liquidityOrderDigest(ITradeToken.LiquidityOrder calldata) external view returns (bytes32) {
        if (mode == 2) assembly { mstore(0, 1) return(0, 16) }
        if (mode == 3) return right;
        return keccak256("another");
    }

    function pull(address token, ITradeToken.LiquidityOrder calldata o, IUARegistry.UASig calldata auth, uint256 amount)
        external
    {
        ILiquidityPullToken(token).mtxLiquidityPull(o, auth, amount, msg.sender);
    }
}

/// A position reader that answers `words` 32-byte words of whatever was set (review P2-4: the length check).
contract MockShortReader {
    address public manager;
    uint256 public words = 4;

    constructor(address m) {
        manager = m;
    }

    function position(uint256) external view returns (bytes32, int24, int24, uint128, bool) {
        uint256 n = words * 32;
        assembly {
            mstore(0, 0) mstore(0x20, 0) mstore(0x40, 0) mstore(0x60, 0) mstore(0x80, 0)
            return(0, n)
        }
    }
}

/// An ERC-721 whose `transferFrom` keeps the position (L18 / L25: never moved).
contract MockStickyPositions is ERC721 {
    constructor() ERC721("Sticky", "STK") {}

    function mint(address to, uint256 id) external {
        _mint(to, id);
    }

    function transferFrom(address, address, uint256) public pure override {}
}

/// Re-enters the DEX during a plan (L34).
contract MockReenter {
    address public target;
    bytes public data;

    function set(address t, bytes calldata d) external {
        (target, data) = (t, d);
    }

    function go() external {
        (bool ok, bytes memory r) = target.call(data);
        if (!ok) assembly { revert(add(r, 32), mload(r)) }
    }
}


/// Answers a fixed position for any id (L25: a reader that matches while its manager keeps the NFT).
contract MockFixedReader {
    address public immutable manager;
    bytes32 internal immutable _pool;
    int24 internal immutable _lo;
    int24 internal immutable _hi;
    uint128 internal immutable _liq;

    constructor(address m, bytes32 pool, int24 lo, int24 hi, uint128 liq) {
        (manager, _pool, _lo, _hi, _liq) = (m, pool, lo, hi, liq);
    }

    function position(uint256) external view returns (bytes32, int24, int24, uint128, bool) {
        return (_pool, _lo, _hi, _liq, false);
    }
}

/// A swap venue paid first by a transfer: pays `amountOut` of `tOut` to `to` from its own inventory (the zap's hop).
contract MockSwap {
    function swap(address tOut, uint256 amountOut, address to) external {
        IERC20(tOut).transfer(to, amountOut);
    }
}

/// Reads the DEX's `liquidityOrderDigest` by STATICCALL, as a token's T7 does (owner 2026-11-10: the view behind its stub).
contract MockDigestProbe {
    function probe(address dex, ITradeToken.LiquidityOrder calldata o, bytes32 expected) external view {
        (bool ok, bytes memory r) = dex.staticcall(abi.encodeWithSelector(0x436033f5, o));
        require(ok && r.length == 32 && abi.decode(r, (bytes32)) == expected, "probe");
    }
}

/// The node's RPC-level pre-check test (`scaas-node/tests/e2e.rs`, `liquidity_pre_checks_on_a_chain`): a DEX bound to the
/// chain whose `modules()` lists `ms`. With the governance module only, a DEX release before the liquidity module; with both,
/// a marked DEX whose `mtxLiquidity` answers what a token's T7 answers when starved, `NotLiquidityDex(dex)`. No token is a
/// SCaaS token to it.
contract MockNodeDex {
    error NotLiquidityDex(address caller);

    bytes32 public immutable chainUid;
    address[] internal _ms;

    constructor(bytes32 uid, address[] memory ms) {
        (chainUid, _ms) = (uid, ms);
    }

    function modules() external view returns (address[] memory) {
        return _ms;
    }

    function tokenKind(address) external pure returns (uint8) {
        return 0;
    }

    fallback() external {
        revert NotLiquidityDex(address(this));
    }
}

/// A SCaaS token of an earlier release as the node's pre-check reads it (its runtime set at a listed token's address by the
/// same test): ERC-165 without `ILiquidityPullToken`, no `mtxLiquidityPull`.
contract MockEarlierToken {
    function supportsInterface(bytes4 id) external pure returns (bool) {
        return id == 0x01ffc9a7;
    }
}
