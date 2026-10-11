// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {ISCaaSDex} from "./ISCaaSDex.sol";
import {ITradeToken} from "../trade/ITradeToken.sol";
import {IOpenFactory} from "../factory/IOpenFactory.sol";
import {SaltedEIP712} from "../common/SaltedEIP712.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {TradeLib} from "../trade/TradeLib.sol";
import {DexPuller} from "./DexPuller.sol";

/// @title `SCaaSDex` (CTR-DEX-16, -17, -11, -03, -24, -18, -22, -08): an EIP-1167 clone made by `OpenFactory.createDex`.
/// @notice One settlement = one taker against 1..n makers at each maker's signed price (rounded in the maker's favour).
///         Every leg is pulled into the DEX through its sell token's `mtxTrade` (Path A: the exact fill, the token
///         checks every signed bound; Path B, `ESCROW`: the whole amount, the DEX checks the matched part and refunds
///         the rest), every party is paid in the same call, each order's fee `⌈receiveFill·fee/10⁶⌉` is charged once on
///         its aggregate receive and split between the submitter and the treasury, and the DEX's balance of both
///         tokens is unchanged at the end (`ConservationBroken`). Each settlement is atomic; one that fails emits
///         `MatchFailed` (its first 256 bytes of revert data) and the others still run; a starved ERC-1271 check
///         (`SigCheckGasStarved`) reverts the whole call. The admin lists markets and sets the fee split, never an amount.
///         An outside-token leg (CTR-DEX-18) is the same `TradeOrder` signed in this DEX's domain as `DexOrder`: the DEX
///         runs the token's checks (`TradeLib`, its own `scaas.trade` state), the signature (`SigCheck`, ERC-1271
///         capped by codehash, CTR-DEX-08) and pulls the fill through its `DexPuller` (CTR-DEX-22); `ESCROW` is refused.
///         Exchange path: P2c.
contract SCaaSDex is ISCaaSDex, SaltedEIP712, ReentrancyGuardTransient {
    using SafeERC20 for IERC20;

    uint256 internal constant PPM = 1_000_000;
    uint8 internal constant ESCROW = 2;
    uint8 internal constant KIND_SCAAS = 1;
    uint8 internal constant KIND_OUTSIDE = 2;
    /// @dev Bytes of a failed settlement's revert data kept for `MatchFailed`: the copy costs this frame at most this
    ///      much, so a returnbomb (an outside token reverting with megabytes) cannot take the other settlements down.
    uint256 internal constant MAX_REASON = 256;
    /// @dev ERC-1271 gas cap for this chain's `SmartKeyAccount` clones (CTR-ACC-05); other contracts get
    ///      `SigCheck.ERC1271_GAS` (50 000).
    uint256 internal constant SMART_KEY_1271_GAS = 400_000;

    /// @custom:storage-location erc7201:scaas.dex
    struct DexStorage {
        bool initialized;
        address admin;
        uint32 relayerSharePpm;
        address treasury;
        bool listedOnly;
        mapping(bytes32 pair => bool) listed;
        mapping(address token => uint8) kind;
        address puller;
    }

    bytes32 internal constant DEX_ORDER_TYPEHASH = keccak256(
        "DexOrder(address sellToken,TradeOrder order)TradeOrder(address from,address receiveToken,uint256 amount,"
        "uint256 receiveAmount,uint256 minFill,uint256 fee,address relayer,address dex,address destination,uint8 flags,"
        "uint256 batch,uint256 nonce,uint256 validUntil)"
    );

    // keccak256(abi.encode(uint256(keccak256("scaas.dex")) - 1)) & ~bytes32(uint256(0xff))
    bytes32 private constant _STORAGE = 0xb144ea5327f344ea7e3b34dd1898f534c8ce28f9f54d0d89a1b78f8fcf7dac00;

    address public immutable FACTORY;
    /// @notice This chain's `SmartKeyAccount` implementation (0 = none), as the tokens expose it; the deploy checks they agree.
    address public immutable SMART_KEY_ACCOUNT_IMPL;
    /// @dev EIP-1167 runtime codehash of this chain's `SmartKeyAccount` clones (0 = none), as the token's.
    bytes32 private immutable _SMART_KEY_CLONE_CODEHASH;

    /// @dev Per leg, computed before any transfer.
    struct Calc {
        bytes32 h;
        uint256 sold;    // matched sell fill
        uint256 recv;    // gross receive
        uint256 fee;     // dexFee on recv
        uint256 refund;  // Path B: amount - sold
        bool outside;    // an outside-token leg (`DexOrder`), from the DEX's listing
    }

    /// @dev Runs once on the implementation and locks it.
    constructor(address factory_, bytes32 chainUid_, address smartKeyAccountImpl_)
        SaltedEIP712("SCaaS Dex", "1", chainUid_)
    {
        FACTORY = factory_;
        SMART_KEY_ACCOUNT_IMPL = smartKeyAccountImpl_;
        _SMART_KEY_CLONE_CODEHASH = smartKeyAccountImpl_ == address(0) ? bytes32(0) : keccak256(abi.encodePacked(
            hex"363d3d373d3d3d363d73", smartKeyAccountImpl_, hex"5af43d82803e903d91602b57fd5bf3"));
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
        s.puller = address(new DexPuller());
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
        if (msg.sender != s.admin) revert NotAdmin(msg.sender);
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
    function puller() external view returns (address) { return _s().puller; }
    function pulled(bytes32 orderHash) external view returns (uint256) { return TradeLib.$().pulled[orderHash]; }
    function minNonce(address from, uint256 batch) external view returns (uint256) {
        return TradeLib.$().minNonce[from][batch];
    }

    function dexOrderDigest(address sellToken, ITradeToken.TradeOrder calldata o) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(DEX_ORDER_TYPEHASH, sellToken, TradeLib.hashStruct(o))));
    }

    function cancelOrderDigest(bytes32 orderHash) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(TradeLib.CANCEL_ORDER_TYPEHASH, orderHash)));
    }

    function invalidateNoncesDigest(address from, uint256 batch, uint256 newMin) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(TradeLib.INVALIDATE_NONCES_TYPEHASH, from, batch, newMin)));
    }

    // ------------------------------------------------------------------ outside-token cancels (CTR-DEX-18, -02)

    /// @notice Never expire; a closed order or a bad signature skips that item (the batch does not revert); a starved
    ///         ERC-1271 check reverts the call (CTR-DEX-08).
    function mtxCancelOrders(DexOrder[] calldata orders, bytes[] calldata sigs) external nonReentrant {
        if (orders.length != sigs.length) revert LengthMismatch();
        for (uint256 i; i < orders.length; ++i) {
            ITradeToken.TradeOrder calldata o = orders[i].order;
            bytes32 h = dexOrderDigest(orders[i].sellToken, o);
            if (SigCheck.isValid(o.from, cancelOrderDigest(h), sigs[i], _cap(o.from))) TradeLib.cancel(o, h);
        }
    }

    function mtxInvalidateNonces(address from, uint256 batch, uint256 newMin, bytes calldata sig) external nonReentrant {
        bytes32 d = invalidateNoncesDigest(from, batch, newMin);
        if (!SigCheck.isValid(from, d, sig, _cap(from))) revert BadSignature(d);
        TradeLib.invalidate(from, batch, newMin);
    }

    /// @dev CTR-DEX-08: 400 k for a `SmartKeyAccount` clone, else 50 k.
    function _cap(address signer) private view returns (uint256) {
        bytes32 h = _SMART_KEY_CLONE_CODEHASH;
        return h != bytes32(0) && signer.codehash == h ? SMART_KEY_1271_GAS : SigCheck.ERC1271_GAS;
    }

    // ------------------------------------------------------------------ settle (CTR-DEX-16)

    /// @notice Each settlement atomic; at least one must succeed, else the call reverts (the relayer's simulation
    ///         catches it). A failed settlement emits `MatchFailed` with at most `MAX_REASON` bytes of its revert data;
    ///         `SigCheckGasStarved` reverts the whole call (CTR-DEX-08: the submitter's gas, not the signature, failed).
    function mtxSettle(Settlement[] calldata ss) external nonReentrant returns (bool[] memory ok) {
        ok = new bool[](ss.length);
        bool any;
        for (uint256 i; i < ss.length; ++i) {
            bytes memory data = abi.encodeCall(this.settleOne, (ss[i], msg.sender));
            bool success;
            bytes memory reason;
            assembly ("memory-safe") {
                success := call(gas(), address(), 0, add(data, 0x20), mload(data), 0, 0)
                let n := returndatasize()
                if gt(n, MAX_REASON) { n := MAX_REASON }
                reason := mload(0x40)
                mstore(reason, n)
                returndatacopy(add(reason, 0x20), 0, n)
                mstore(0x40, add(add(reason, 0x20), and(add(n, 0x1f), not(0x1f))))
            }
            if (success) {
                ok[i] = true;
                any = true;
            } else if (reason.length >= 4 && bytes4(reason) == SigCheckGasStarved.selector) {
                assembly ("memory-safe") { revert(add(reason, 0x20), mload(reason)) }
            } else {
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
    }

    /// @dev A maker sells `fill` at its own price: it receives `⌈fill·receiveAmount/amount⌉` (in its favour).
    function _makerCalc(Leg calldata m, address submitter) private view returns (Calc memory c) {
        uint256 recv = Math.mulDiv(m.fill, m.o.receiveAmount, m.o.amount, Math.Rounding.Ceil);
        c = _calc(m, submitter, m.fill, recv);
    }

    /// @dev Relayer binding, `dex`, the leg's kind from the listing (an outside leg is a `DexOrder`, never `ESCROW`),
    ///      the fee on the aggregate receive; Path B: the DEX's own checks on the matched part.
    function _calc(Leg calldata l, address submitter, uint256 sold, uint256 recv) private view returns (Calc memory c) {
        ITradeToken.TradeOrder calldata o = l.o;
        if (o.relayer != address(0) && o.relayer != submitter) revert WrongRelayer(submitter);
        if (o.dex != address(this)) revert DexMismatch(o.dex);
        c.outside = _s().kind[l.sellToken] != KIND_SCAAS;
        c.h = c.outside ? dexOrderDigest(l.sellToken, o) : ITradeToken(l.sellToken).tradeOrderDigest(o);
        if (c.outside && o.flags & ESCROW != 0) revert BadFlags(c.h); // pulled exactly into the DEX: nothing to escrow
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
        if (!c.outside) return ITradeToken(l.sellToken).mtxTrade(l.o, l.sig, f);
        // outside token: the DEX runs the token's checks on its own state, then pulls through the puller
        TradeLib.precheck(l.o, f, c.h, address(this), l.sellToken);
        if (!SigCheck.isValid(l.o.from, c.h, l.sig, _cap(l.o.from))) revert BadSignature(c.h);
        DexPuller(_s().puller).pull(l.sellToken, l.o.from, TradeLib.record(l.o, f, c.h));
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
        emit LegSettled(ref, c.h, l.o.from, to, c.sold, c.recv - c.fee, c.fee, c.refund, relayerShare, treasuryShare);
    }

    function _send(address token, address to, uint256 amount) private {
        if (amount != 0) IERC20(token).safeTransfer(to, amount);
    }
}
