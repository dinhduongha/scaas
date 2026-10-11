// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {ISCaaSDex} from "./ISCaaSDex.sol";
import {ITradeToken} from "../trade/ITradeToken.sol";
import {IOpenFactory} from "../factory/IOpenFactory.sol";
import {SaltedEIP712} from "../common/SaltedEIP712.sol";

/// @title `SCaaSDex` (CTR-DEX-16, -17, -11, -03, -24): an EIP-1167 clone made by `OpenFactory.createDex`.
/// @notice One settlement = one taker against 1..n makers at each maker's signed price (rounded in the maker's favour).
///         Every leg is pulled into the DEX through its sell token's `mtxTrade` (Path A: the exact fill, the token
///         checks every signed bound; Path B, `ESCROW`: the whole amount, the DEX checks the matched part and refunds
///         the rest), every party is paid in the same call, each order's fee `⌈receiveFill·fee/10⁶⌉` is charged once on
///         its aggregate receive and split between the submitter and the treasury, and the DEX's balance of both
///         tokens is unchanged at the end (`ConservationBroken`). Each settlement is atomic; one that fails emits
///         `MatchFailed` and the others still run. The admin lists markets and sets the fee split, never an amount.
///         Built: SCaaS legs only (outside legs, `DexOrder`, `DexPuller`: P2b-2; exchange path: P2c).
contract SCaaSDex is ISCaaSDex, SaltedEIP712, ReentrancyGuardTransient {
    uint256 internal constant PPM = 1_000_000;
    uint8 internal constant ESCROW = 2;
    uint8 internal constant KIND_SCAAS = 1;
    uint8 internal constant KIND_OUTSIDE = 2;

    /// @custom:storage-location erc7201:scaas.dex
    struct DexStorage {
        bool initialized;
        address admin;
        uint32 relayerSharePpm;
        address treasury;
        bool listedOnly;
        mapping(bytes32 pair => bool) listed;
        mapping(address token => uint8) kind;
    }

    // keccak256(abi.encode(uint256(keccak256("scaas.dex")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE = 0xb144ea5327f344ea7e3b34dd1898f534c8ce28f9f54d0d89a1b78f8fcf7dac00;

    address public immutable FACTORY;

    /// @dev Per leg, computed before any transfer.
    struct Calc {
        bytes32 h;
        uint256 sold;    // matched sell fill
        uint256 recv;    // gross receive
        uint256 fee;     // dexFee on recv
        uint256 refund;  // Path B: amount - sold
    }

    /// @dev Runs once on the implementation and locks it.
    constructor(address factory_, bytes32 chainUid_) SaltedEIP712("SCaaS Dex", "1", chainUid_) {
        FACTORY = factory_;
        _s().initialized = true;
    }

    function _s() private pure returns (DexStorage storage s) {
        assembly ("memory-safe") { s.slot := _STORAGE }
    }

    // ------------------------------------------------------------------ init and admin (CTR-DEX-24, CTR-DEX-03)

    function initialize(address, uint64, DexConfig calldata cfg) external {
        if (msg.sender != FACTORY) revert NotFactory();
        DexStorage storage s = _s();
        if (s.initialized) revert AlreadyInitialized();
        s.initialized = true;
        s.admin = cfg.admin;
        s.listedOnly = cfg.listedOnly;
        _setFeeSplit(s, cfg.relayerSharePpm, cfg.treasury);
    }

    /// @notice Lists or delists the pair and records each token's kind from the factory (never from a leg).
    function setMarket(address base, address quote, bool listed) external {
        DexStorage storage s = _onlyAdmin();
        s.listed[_pair(base, quote)] = listed;
        s.kind[base] = _classify(base);
        s.kind[quote] = _classify(quote);
        emit MarketSet(base, quote, listed);
    }

    function setFeeSplit(uint32 relayerSharePpm_, address treasury_) external {
        _setFeeSplit(_onlyAdmin(), relayerSharePpm_, treasury_);
    }

    function _setFeeSplit(DexStorage storage s, uint32 ppm, address t) private {
        if (ppm > PPM || (ppm < PPM && (t == address(0) || t == address(this)))) revert FeeSplitInvalid(ppm, t);
        s.relayerSharePpm = ppm;
        s.treasury = t;
        emit FeeSplitSet(ppm, t);
    }

    function _onlyAdmin() private view returns (DexStorage storage s) {
        s = _s();
        if (msg.sender != s.admin || msg.sender == address(0)) revert NotAdmin(msg.sender);
    }

    /// @dev SCaaS iff the factory made it from a registered (version ≠ 0), non-deprecated implementation.
    function _classify(address token) private view returns (uint8) {
        IOpenFactory f = IOpenFactory(FACTORY);
        if (!f.isToken(token)) return KIND_OUTSIDE;
        (IOpenFactory.TokenKind k, uint64 v) = f.versionOf(token);
        return v != 0 && !f.isDeprecated(k, v) ? KIND_SCAAS : KIND_OUTSIDE;
    }

    function _pair(address a, address b) private pure returns (bytes32) {
        return a < b ? keccak256(abi.encode(a, b)) : keccak256(abi.encode(b, a));
    }

    // ------------------------------------------------------------------ views

    function admin() external view returns (address) { return _s().admin; }
    function relayerSharePpm() external view returns (uint32) { return _s().relayerSharePpm; }
    function treasury() external view returns (address) { return _s().treasury; }
    function listedOnly() external view returns (bool) { return _s().listedOnly; }
    function marketListed(address a, address b) external view returns (bool) { return _s().listed[_pair(a, b)]; }
    function tokenKind(address token) external view returns (uint8) { return _s().kind[token]; }
    function factory() external view returns (address) { return FACTORY; }
    function chainUid() external view returns (bytes32) { return CHAIN_UID; }

    // ------------------------------------------------------------------ settle (CTR-DEX-16)

    /// @notice Each settlement atomic; at least one must succeed, else the call reverts (the relayer's simulation
    ///         catches it).
    function mtxSettle(Settlement[] calldata ss) external nonReentrant returns (bool[] memory ok) {
        ok = new bool[](ss.length);
        bool any;
        for (uint256 i; i < ss.length; ++i) {
            try this.settleOne(ss[i], msg.sender) {
                ok[i] = true;
                any = true;
            } catch (bytes memory reason) {
                emit MatchFailed(ss[i].ref, reason);
            }
        }
        if (!any) revert NothingSettled();
    }

    /// @notice Only through `mtxSettle` (the self-call isolates one settlement); `submitter` is the real caller.
    function settleOne(Settlement calldata s, address submitter) external {
        if (msg.sender != address(this)) revert NotSelf();
        uint256 n = s.makers.length;
        if (n == 0) revert NoMakers();
        address tokenA = s.taker.sellToken;      // the taker sells A, the makers sell B
        address tokenB = s.taker.o.receiveToken;
        _checkMarket(tokenA, tokenB);
        Calc[] memory makers = new Calc[](n);
        uint256 takerSell;
        uint256 takerRecv;
        for (uint256 i; i < n; ++i) {
            Leg calldata m = s.makers[i];
            if (m.sellToken != tokenB || m.o.receiveToken != tokenA) revert TokenMismatch();
            if (m.o.from == s.taker.o.from) revert SelfTrade(m.o.from);
            makers[i] = _makerCalc(m, submitter);
            for (uint256 j; j < i; ++j) if (makers[j].h == makers[i].h) revert DuplicateOrder(makers[i].h);
            takerSell += makers[i].recv;
            takerRecv += makers[i].sold;
        }
        if (s.taker.fill != takerSell) revert FillMismatch(takerSell, s.taker.fill);
        Calc memory taker = _calc(s.taker, submitter, takerSell, takerRecv);
        uint256 balA = IERC20(tokenA).balanceOf(address(this));
        uint256 balB = IERC20(tokenB).balanceOf(address(this));
        _pull(s.taker, taker, submitter);
        for (uint256 i; i < n; ++i) _pull(s.makers[i], makers[i], submitter);
        _pay(s.ref, s.taker, taker, tokenB, submitter);
        for (uint256 i; i < n; ++i) _pay(s.ref, s.makers[i], makers[i], tokenA, submitter);
        if (IERC20(tokenA).balanceOf(address(this)) != balA) revert ConservationBroken(tokenA);
        if (IERC20(tokenB).balanceOf(address(this)) != balB) revert ConservationBroken(tokenB);
    }

    function _checkMarket(address a, address b) private view {
        DexStorage storage s = _s();
        if (a == b) revert TokenMismatch();
        if (!s.listed[_pair(a, b)]) revert MarketNotListed(a, b);
        if (s.kind[a] != KIND_SCAAS) revert OutsideLegNotBuilt(a);
        if (s.kind[b] != KIND_SCAAS) revert OutsideLegNotBuilt(b);
    }

    /// @dev A maker sells `fill` at its own price: it receives `⌈fill·receiveAmount/amount⌉` (in its favour).
    function _makerCalc(Leg calldata m, address submitter) private view returns (Calc memory c) {
        uint256 recv = Math.mulDiv(m.fill, m.o.receiveAmount, m.o.amount, Math.Rounding.Ceil);
        c = _calc(m, submitter, m.fill, recv);
    }

    /// @dev Relayer binding, `dex`, the fee on the aggregate receive; Path B: the DEX's own checks on the matched part.
    function _calc(Leg calldata l, address submitter, uint256 sold, uint256 recv) private view returns (Calc memory c) {
        ITradeToken.TradeOrder calldata o = l.o;
        if (o.relayer != address(0) && o.relayer != submitter) revert WrongRelayer(submitter);
        if (o.dex != address(this)) revert DexMismatch(o.dex);
        c.h = ITradeToken(l.sellToken).tradeOrderDigest(o);
        c.sold = sold;
        c.recv = recv;
        c.fee = Math.mulDiv(recv, o.fee, PPM, Math.Rounding.Ceil);
        if (o.flags & ESCROW != 0) {
            // the token pulls `amount` once (Path B); the DEX checks what the token cannot see
            if (sold > o.amount) revert Overfill(c.h);
            if (sold != o.amount) {
                uint256 m = o.minFill > o.amount - o.amount / 2 ? o.minFill : o.amount - o.amount / 2;
                if (sold < m || recv < o.receiveAmount - o.receiveAmount / 2) revert BelowMinFill(c.h);
            }
            if (sold * o.receiveAmount > recv * o.amount) revert PriceLimit(c.h);
            c.refund = o.amount - sold;
        }
    }

    function _pull(Leg calldata l, Calc memory c, address submitter) private {
        ITradeToken.TradeFill memory f = l.o.flags & ESCROW != 0
            ? ITradeToken.TradeFill(l.o.amount, 0, 0, submitter)
            : ITradeToken.TradeFill(c.sold, c.recv, c.fee, submitter);
        ITradeToken(l.sellToken).mtxTrade(l.o, l.sig, f);
    }

    /// @dev Proceeds net of the fee to `destination` (or `from`), the fee split, the Path B refund.
    function _pay(bytes32 ref, Leg calldata l, Calc memory c, address recvToken, address submitter) private {
        DexStorage storage s = _s();
        address to = l.o.destination == address(0) ? l.o.from : l.o.destination;
        uint256 relayerShare = c.fee * s.relayerSharePpm / PPM;
        uint256 treasuryShare = c.fee - relayerShare;
        _send(recvToken, to, c.recv - c.fee);
        _send(recvToken, submitter, relayerShare);
        _send(recvToken, s.treasury, treasuryShare);
        _send(l.sellToken, l.o.from, c.refund);
        emit LegSettled(ref, c.h, l.o.from, to, c.sold, c.recv, c.fee, c.refund, relayerShare, treasuryShare);
    }

    function _send(address token, address to, uint256 amount) private {
        if (amount != 0) IERC20(token).transfer(to, amount);
    }
}
