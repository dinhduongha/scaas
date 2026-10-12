// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {ISCaaSDex, IExchangeExecutor} from "./ISCaaSDex.sol";
import {ITradeToken} from "../trade/ITradeToken.sol";
import {IOpenFactory} from "../factory/IOpenFactory.sol";
import {SaltedEIP712} from "../common/SaltedEIP712.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {TradeLib} from "../trade/TradeLib.sol";
import {DexPuller} from "./DexPuller.sol";

/// @title `SCaaSDex` (CTR-DEX-16, -17, -11, -03, -24, -18, -22, -08, -20, -21, -23): an EIP-1167 clone made by
///        `OpenFactory.createDex`.
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
///         Exchange path (CTR-DEX-20): the same orders against AMM routes instead of makers, each at a floor the
///         submitter commits to; every output above the floors is paid to the signers (CTR-DEX-21); interactions may
///         not call the DEX, the puller or any `mtxTrade`, nor call `increaseAllowance` or Permit2 `approve`
///         (controller ruling, pending the owner; other allowance-raising calls are not tracked),
///         listed targets only when a leg or the admin asks (CTR-DEX-23), and every allowance an `approve` interaction
///         grants is set back to 0 before the payout.
contract SCaaSDex is ISCaaSDex, SaltedEIP712, ReentrancyGuardTransient {
    using SafeERC20 for IERC20;

    uint256 internal constant PPM = 1_000_000;
    uint8 internal constant ESCROW = 2;
    uint8 internal constant KIND_SCAAS = 1;
    uint8 internal constant KIND_OUTSIDE = 2;
    /// @dev Bytes of a failed settlement's revert data kept for `MatchFailed`: the copy costs this frame at most this
    ///      much, so a returnbomb (an outside token reverting with megabytes) cannot take the other settlements down.
    uint256 internal constant MAX_REASON = 256;
    /// @dev `TradeOrder.flags` bit: every interaction target or executor must be listed (CTR-DEX-23).
    uint8 internal constant LISTED_POOLS = 4;
    /// @dev ERC-20 `increaseAllowance(address,uint256)` and Permit2 `approve(address,address,uint160,uint48)`: refused on
    ///      every exchange interaction, so the only allowance a route grants is an `approve` the DEX resets to 0.
    bytes4 internal constant INCREASE_ALLOWANCE = 0x39509351;
    bytes4 internal constant PERMIT2_APPROVE = 0x87517c45;
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
        mapping(address token => uint256) listings; // listed markets the token is a side of: > 0 = known
        mapping(address target => bool) exchangeTarget;
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

    /// @dev Per token of an exchange plan.
    struct Tok {
        address token;
        uint256 snap;       // the DEX's balance before the pulls
        uint256 sold;       // Σ sellFill of the legs selling it: what the route may spend
        uint256 refunds;    // Σ Path B refunds of the legs selling it
        uint256 floors;     // Σ receiveFill of the legs receiving it
        uint256 excess;     // surplus above the floors, for the legs receiving it
        uint256 floorsLeft; // floors of the legs not yet paid: the last one takes the rounding remainder
        uint256 paid;       // surplus paid so far
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
        bytes32 k = _pair(base, quote);
        if (s.listed[k] != listed) {
            s.listed[k] = listed;
            if (listed) {
                ++s.listings[base];
                ++s.listings[quote];
            } else {
                --s.listings[base];
                --s.listings[quote];
            }
        }
        s.kind[base] = _classify(base);
        s.kind[quote] = _classify(quote);
        emit MarketSet(base, quote, listed);
    }

    function setFeeSplit(uint32 relayerSharePpm_, address treasury_) external {
        _setFeeSplit(_onlyAdmin(), relayerSharePpm_, treasury_);
    }

    /// @notice Lists or delists an interaction target or an executor (CTR-DEX-23).
    function setExchangeTarget(address target, bool listed) external {
        _onlyAdmin().exchangeTarget[target] = listed;
        emit ExchangeTargetSet(target, listed);
    }

    /// @notice DEX-wide listed-only mode for the exchange path (CTR-DEX-23); a leg's `LISTED_POOLS` asks the same.
    function setListedOnly(bool on) external {
        _onlyAdmin().listedOnly = on;
        emit ListedOnlySet(on);
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
    function tokenKnown(address token) external view returns (bool) { return _s().listings[token] != 0; }
    function exchangeTarget(address target) external view returns (bool) { return _s().exchangeTarget[target]; }
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
        Calc memory taker = _calc(s.taker.sellToken, s.taker.o, submitter, takerSell, takerRecv);
        uint256 balA = IERC20(tokenA).balanceOf(address(this));
        uint256 balB = IERC20(tokenB).balanceOf(address(this));
        _pullLeg(s.taker, taker, submitter);
        for (uint256 i; i < n; ++i) _pullLeg(s.makers[i], makers[i], submitter);
        _pay(s.ref, s.taker, taker, submitter);
        for (uint256 i; i < n; ++i) _pay(s.ref, s.makers[i], makers[i], submitter);
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
        c = _calc(m.sellToken, m.o, submitter, m.fill, recv);
    }

    /// @dev Relayer binding, `dex`, the leg's kind from the listing (an outside leg is a `DexOrder`, never `ESCROW`),
    ///      the fee on the aggregate receive (the floor on the exchange path); Path B: the DEX's own checks on the
    ///      matched part. Path A bounds are checked at the pull, by the token or by `TradeLib` on the DEX.
    function _calc(address sellToken, ITradeToken.TradeOrder calldata o, address submitter, uint256 sold, uint256 recv)
        private view returns (Calc memory c)
    {
        if (o.relayer != address(0) && o.relayer != submitter) revert WrongRelayer(submitter);
        if (o.dex != address(this)) revert DexMismatch(o.dex);
        c.outside = _s().kind[sellToken] != KIND_SCAAS;
        c.h = c.outside ? dexOrderDigest(sellToken, o) : ITradeToken(sellToken).tradeOrderDigest(o);
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

    function _pullLeg(Leg calldata l, Calc memory c, address submitter) private {
        _pull(l.sellToken, l.o, l.sig, c, submitter);
    }

    function _pull(address sellToken, ITradeToken.TradeOrder calldata o, bytes calldata sig, Calc memory c,
        address submitter) private
    {
        ITradeToken.TradeFill memory f = o.flags & ESCROW != 0
            ? ITradeToken.TradeFill(o.amount, 0, 0, submitter)
            : ITradeToken.TradeFill(c.sold, c.recv, c.fee, submitter);
        if (!c.outside) return ITradeToken(sellToken).mtxTrade(o, sig, f);
        // outside token: the DEX runs the token's checks on its own state, then pulls through the puller
        TradeLib.precheck(o, f, c.h, address(this), sellToken);
        if (!SigCheck.isValid(o.from, c.h, sig, _cap(o.from))) revert BadSignature(c.h);
        DexPuller(_s().puller).pull(sellToken, o.from, TradeLib.record(o, f, c.h));
    }

    function _pay(bytes32 ref, Leg calldata l, Calc memory c, address submitter) private {
        (address to, uint256 relayerShare, uint256 treasuryShare) = _payLeg(l.sellToken, l.o, c, 0, submitter);
        emit LegSettled(ref, c.h, l.o.from, to, c.sold, c.recv - c.fee, c.fee, c.refund, relayerShare, treasuryShare);
    }

    /// @dev Proceeds net of the fee, plus `surplus`, to `destination` (or `from`), the fee split, the Path B refund.
    function _payLeg(address sellToken, ITradeToken.TradeOrder calldata o, Calc memory c, uint256 surplus,
        address submitter) private returns (address to, uint256 relayerShare, uint256 treasuryShare)
    {
        DexStorage storage s = _s();
        to = o.destination == address(0) ? o.from : o.destination;
        relayerShare = c.fee * s.relayerSharePpm / PPM;
        treasuryShare = c.fee - relayerShare;
        _send(o.receiveToken, to, c.recv - c.fee + surplus);
        _send(o.receiveToken, submitter, relayerShare);
        _send(o.receiveToken, s.treasury, treasuryShare);
        _send(sellToken, o.from, c.refund);
    }

    // ------------------------------------------------------------------ exchange path (CTR-DEX-20, -21, -23)

    /// @notice Path (a): the DEX makes each interaction (never on itself or its puller, never `mtxTrade`,
    ///         `increaseAllowance` or Permit2 `approve` (controller ruling, pending the owner), listed when a leg or
    ///         the admin asks); a failing one reverts the plan with its data. Every allowance an `approve`
    ///         interaction granted is set back to 0 after the last interaction (controller ruling: the DEX keeps no
    ///         allowance past the route).
    function mtxExchange(ExchangePlan calldata p, Interaction[] calldata xs) external nonReentrant {
        (Tok[] memory t, Calc[] memory c, bool onlyListed) = _exchangeIn(p);
        address[] memory approvedToken = new address[](xs.length);
        address[] memory approvedSpender = new address[](xs.length);
        uint256 na;
        for (uint256 i; i < xs.length; ++i) {
            bytes4 sel = _interact(xs[i], onlyListed);
            if (sel == IERC20.approve.selector) {
                approvedToken[na] = xs[i].target;
                (approvedSpender[na++],) = abi.decode(xs[i].data[4:], (address, uint256));
            }
        }
        for (uint256 i; i < na; ++i) IERC20(approvedToken[i]).forceApprove(approvedSpender[i], 0);
        _exchangeOut(p, t, c);
    }

    /// @notice Path (b): the sold fills go to `executor` (listed when a leg or the admin asks), which must transfer at
    ///         least the floors to the DEX inside `exchangeCallback`; re-entry hits `nonReentrant`, a `mtxTrade` or a
    ///         puller call from it fails (it is neither `o.dex` nor the DEX).
    // At the stack limit (via_ir off): add no locals here; move _flows + hand-out + callback into a helper first.
    function mtxExchangeVia(ExchangePlan calldata p, address executor, bytes calldata data) external nonReentrant {
        (Tok[] memory t, Calc[] memory c, bool onlyListed) = _exchangeIn(p);
        if (onlyListed && !_s().exchangeTarget[executor]) revert TargetNotListed(executor);
        (address[] memory tokensOut, uint256[] memory amountsOut, address[] memory tokensIn, uint256[] memory amountsIn)
            = _flows(t);
        for (uint256 i; i < tokensOut.length; ++i) _send(tokensOut[i], executor, amountsOut[i]);
        IExchangeExecutor(executor).exchangeCallback(p.ref, tokensOut, amountsOut, tokensIn, amountsIn, data);
        _exchangeOut(p, t, c);
    }

    /// @dev Path (b)'s figures: per sold token Σ sellFill (the Path B remainders stay for the refunds), per receive
    ///      token Σ floors.
    function _flows(Tok[] memory t) private pure returns (address[] memory tokensOut, uint256[] memory amountsOut,
        address[] memory tokensIn, uint256[] memory amountsIn)
    {
        uint256 nOut;
        uint256 nIn;
        for (uint256 i; i < t.length; ++i) {
            if (t[i].sold != 0) ++nOut;
            if (t[i].floors != 0) ++nIn;
        }
        (tokensOut, amountsOut) = (new address[](nOut), new uint256[](nOut));
        (tokensIn, amountsIn) = (new address[](nIn), new uint256[](nIn));
        (nOut, nIn) = (0, 0);
        for (uint256 i; i < t.length; ++i) {
            if (t[i].sold != 0) (tokensOut[nOut], amountsOut[nOut++]) = (t[i].token, t[i].sold);
            if (t[i].floors != 0) (tokensIn[nIn], amountsIn[nIn++]) = (t[i].token, t[i].floors);
        }
    }

    /// @dev Steps 1-3: check every leg, snapshot every token, pull every leg; each pulled token's balance must rise by
    ///      exactly what was pulled (a fee-on-transfer or rebasing sell token fails here).
    function _exchangeIn(ExchangePlan calldata p) private returns (Tok[] memory t, Calc[] memory c, bool onlyListed) {
        DexStorage storage s = _s();
        uint256 n = p.legs.length;
        if (n == 0) revert NoLegs();
        onlyListed = s.listedOnly;
        t = new Tok[](2 * n + p.extraTokens.length);
        c = new Calc[](n);
        for (uint256 i; i < n; ++i) {
            ExchangeLeg calldata l = p.legs[i];
            address rt = l.o.receiveToken;
            if (s.listings[l.sellToken] == 0) revert TokenNotKnown(l.sellToken);
            if (s.listings[rt] == 0) revert TokenNotKnown(rt);
            for (uint256 j; j < i; ++j) if (p.legs[j].o.from == l.o.from) revert SelfTrade(l.o.from);
            c[i] = _calc(l.sellToken, l.o, msg.sender, l.sellFill, l.receiveFill);
            if (l.o.flags & LISTED_POOLS != 0) onlyListed = true;
            Tok memory ts = _tok(t, l.sellToken);
            ts.sold += c[i].sold;
            ts.refunds += c[i].refund;
            _tok(t, rt).floors += c[i].recv;
        }
        for (uint256 i; i < p.extraTokens.length; ++i) _tok(t, p.extraTokens[i]);
        uint256 nt;
        while (nt < t.length && t[nt].token != address(0)) ++nt;
        assembly ("memory-safe") { mstore(t, nt) }
        for (uint256 i; i < nt; ++i) {
            t[i].snap = IERC20(t[i].token).balanceOf(address(this));
            t[i].floorsLeft = t[i].floors;
        }
        for (uint256 i; i < n; ++i) _pull(p.legs[i].sellToken, p.legs[i].o, p.legs[i].sig, c[i], msg.sender);
        for (uint256 i; i < nt; ++i) {
            Tok memory x = t[i];
            if (IERC20(x.token).balanceOf(address(this)) != x.snap + x.sold + x.refunds) {
                revert ConservationBroken(x.token);
            }
        }
    }

    /// @dev One interaction of path (a); returns its selector.
    function _interact(Interaction calldata x, bool onlyListed) private returns (bytes4 sel) {
        DexStorage storage s = _s();
        if (x.target == address(this) || x.target == s.puller) revert ForbiddenTarget(x.target);
        sel = bytes4(x.data);
        if (x.data.length < 4 || sel == ITradeToken.mtxTrade.selector) revert ForbiddenSelector(x.target, sel);
        // controller ruling: no allowance may be raised outside `approve` (reset after the route)
        if (sel == INCREASE_ALLOWANCE || sel == PERMIT2_APPROVE) revert ForbiddenSelector(x.target, sel);
        if (onlyListed && !s.exchangeTarget[x.target]) revert TargetNotListed(x.target);
        (bool ok, bytes memory ret) = x.target.call(x.data);
        if (!ok) assembly ("memory-safe") { revert(add(ret, 0x20), mload(ret)) }
    }

    /// @dev Steps 5-6: the surplus per receive token (CTR-DEX-21), the payouts, conservation over every token (a
    ///      sold-only or intermediate leftover fails there: a route bug, not something to assign).
    function _exchangeOut(ExchangePlan calldata p, Tok[] memory t, Calc[] memory c) private {
        for (uint256 i; i < t.length; ++i) {
            Tok memory x = t[i];
            if (x.floors == 0) continue;
            uint256 bal = IERC20(x.token).balanceOf(address(this));
            uint256 keep = x.snap + x.refunds + x.floors;
            if (bal < keep) revert InsufficientOutput(x.token);
            x.excess = bal - keep;
        }
        for (uint256 i; i < p.legs.length; ++i) {
            ExchangeLeg calldata l = p.legs[i];
            Tok memory x = _tok(t, l.o.receiveToken);
            uint256 share = x.floorsLeft == c[i].recv ? x.excess - x.paid : Math.mulDiv(x.excess, c[i].recv, x.floors);
            x.floorsLeft -= c[i].recv;
            x.paid += share;
            _payExchange(p.ref, l, c[i], share);
        }
        for (uint256 i; i < t.length; ++i) {
            if (IERC20(t[i].token).balanceOf(address(this)) != t[i].snap) revert ConservationBroken(t[i].token);
        }
    }

    function _payExchange(bytes32 ref, ExchangeLeg calldata l, Calc memory c, uint256 surplus) private {
        (address to,,) = _payLeg(l.sellToken, l.o, c, surplus, msg.sender);
        uint256 limit = Math.mulDiv(c.sold, l.o.receiveAmount, l.o.amount, Math.Rounding.Ceil);
        _emitExchangeLeg(ref, l.o.from, to, c, surplus, limit);
    }

    function _emitExchangeLeg(bytes32 ref, address from, address to, Calc memory c, uint256 surplus, uint256 limit)
        private
    {
        emit ExchangeLegSettled(ref, c.h, from, to, c.sold, c.recv, surplus, c.fee, c.refund, limit);
    }

    /// @dev The entry of `token`, added in the first free slot if absent (`t` is sized for every token of the plan).
    function _tok(Tok[] memory t, address token) private pure returns (Tok memory x) {
        for (uint256 i; i < t.length; ++i) {
            x = t[i];
            if (x.token == token) return x;
            if (x.token == address(0)) {
                x.token = token;
                return x;
            }
        }
    }

    function _send(address token, address to, uint256 amount) private {
        if (amount != 0) IERC20(token).safeTransfer(to, amount);
    }
}
