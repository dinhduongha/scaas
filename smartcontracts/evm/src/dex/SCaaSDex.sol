// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {ISCaaSDex, IExchangeExecutor} from "./ISCaaSDex.sol";
import {ITradeToken} from "../trade/ITradeToken.sol";
import {IOpenFactory} from "../factory/IOpenFactory.sol";
import {IFactoryToken} from "../factory/IFactoryToken.sol";
import {ChainEnvCode} from "../factory/ChainEnvCode.sol";
import {SaltedEIP712, SaltedEIP712Core} from "../common/SaltedEIP712.sol";
import {SigCheck} from "../common/SigCheck.sol";
import {TradeLib} from "../trade/TradeLib.sol";
import {IUALedger} from "../metatx/IUALedger.sol";
import {UAKinds} from "../ua/UAKinds.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";
import {DexPuller} from "./DexPuller.sol";
import {TokenCall} from "./TokenCall.sol";
import {GovernanceUse} from "../governance/GovernanceBase.sol";
import {SCaaSDexGovernance} from "./SCaaSDexAdmin.sol";
import {SCaaSDexCore} from "./SCaaSDexCore.sol";
import {ImplArgs, ITokenModule} from "../metatx/ITokenModule.sol";
import {IGovernance} from "../governance/IGovernance.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {GovernanceBits} from "../governance/GovernanceBits.sol";
import {GovernanceLib} from "../governance/GovernanceLib.sol";
import {IRescuable} from "../governance/IRescuable.sol";
import {MetaTxLib} from "../common/MetaTxLib.sol";

/// @title `SCaaSDex` (CTR-DEX-16, -17, -11, -03, -24, -18, -22, -08, -20, -21, -23): an EIP-1167 clone made by
///        `OpenFactory.createDex`.
/// @notice One settlement = one taker against 1..n makers at each maker's signed price (rounded in the maker's favour).
///         Every leg is pulled into the DEX through its sell token's `mtxTrade` (Path A: the exact fill, the token
///         checks every signed bound; Path B, `ESCROW`: the whole amount, the DEX checks the matched part and refunds
///         the rest), every party is paid in the same call, each order's fee `⌈receiveFill·fee/10⁶⌉` is charged once on
///         its aggregate receive and split between the submitter and the treasury, and the DEX's balance of both
///         tokens is unchanged at the end (`ConservationBroken`). Each settlement is atomic; one that fails emits
///         `MatchFailed` (its first 256 bytes of revert data) and the others still run; a starved ERC-1271 check
///         (`SigCheckGasStarved`) reverts the whole call. A holder of `LISTING` lists markets and targets, a holder of `FEE_ROUTING`
///         sets the fee split, never an amount.
///         An outside-token leg (CTR-DEX-18) is the same `TradeOrder` signed in this DEX's domain as `DexOrder`: the DEX
///         runs the token's checks (`TradeLib`, its own `scaas.trade` state), the signature (`SigCheck`, ERC-1271
///         capped by codehash, CTR-DEX-08) and pulls the fill through its `DexPuller` (CTR-DEX-22); `ESCROW` is refused.
///         Exchange path (CTR-DEX-20): the same orders against AMM routes instead of makers, each at a floor the
///         submitter commits to; every output above the floors is paid to the signers (CTR-DEX-21); interactions may
///         not call the DEX, the puller or any `mtxTrade` / `restorePulled`, nor call `increaseAllowance` or Permit2
///         `approve` (controller ruling, pending the owner; other allowance-raising calls are not tracked),
///         listed targets only when a leg or the `LISTING` holder asks (CTR-DEX-23), and every allowance an `approve` interaction
///         grants is set back to 0 before the payout. Legs (CTR-DEX-26; ua-mtx-merge T6, R12): a leg is tagged —
///         shape 0 a `TradeOrder`, only on an outside token; shape 1 a `UATradeOrder` (ids as `bytes32`), only on a
///         SCaaS token, native or derived — and read into one form (`UATradeOrder` in memory, a native id
///         zero-padded); a SCaaS leg is pulled through the token's `mtxTrade` and emits `UALegSettled`, an outside one
///         `LegSettled`; a registry is asked of the sell token only for a derived seller (C); a derived party is paid
///         and refunded by the token's `transferToUA` from the DEX's own balance; self-trade is over ids; a UA leg's
///         starved verify (`UAVerifyGas`) reverts the whole `mtxSettle`. Hybrid (`mtxHybrid` /
///         `mtxHybridVia`, spec §4): one listed-market taker against 0..n makers at their own price and the rest of
///         its sell routed outside, in one atomic plan; the taker alone gets the output above `outsideFloor`.
///         T66b (spec 2026-11-09-t66b-library-organisation.md §4.2, owner 2026-11-09 ruling (a)): the 22 governance entries
///         forward by DELEGATECALL to the admin module D (`SCaaSDexGovernanceModule`, `modules()`); the governance hooks are
///         `SCaaSDexGovernance`'s, shared with D. Liquidity (CTR-DEX-30, -31): `mtxLiquidity` forwards to the liquidity
///         module `SCaaSDexLiquidityModule` under this DEX's guard; the shared bodies (`_interact`, `_route`, `_send`, `_sendTo`,
///         `_bal`, `_tokenFailed`, `_ledgerOn`, `_cap`) and the state accessor are `SCaaSDexCore`'s.
contract SCaaSDex is ISCaaSDex, SaltedEIP712, SCaaSDexGovernance, SCaaSDexCore, IGovernance {
    uint8 internal constant ESCROW = 2;



    /// @notice The factory, at the same address on every chain (chain-neutral spec §2.1): a chain-neutral immutable.
    address public immutable FACTORY;

    /// @notice T66b §4.5: a module (`implArgs`) has no code; or it is of another group or factory.
    error ModuleMissing(uint256 i);
    error ModuleMismatch(uint256 i);

    /// @dev The governance module (`SCaaSDexGovernanceModule`, group 10) and the liquidity module
    ///      (`SCaaSDexLiquidityModule`, group 11), from `implArgs` in that order.
    address private immutable _MD;
    address private immutable _ML;

    /// @dev Per leg, computed before any transfer.
    struct Calc {
        bytes32 h;
        uint256 sold;    // matched sell fill
        uint256 recv;    // gross receive
        uint256 fee;     // dexFee on recv
        uint256 refund;  // Path B: amount - sold
        bool outside;    // an outside-token leg (`DexOrder`), from the DEX's listing
        bool ua;         // shape 1: a `UATradeOrder`
        ITradeToken.UATradeOrder o; // the decoded order, ids as `bytes32` (shape 0: the address zero-padded)
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
    /// @dev The factory's append (`OpenFactory.deployDexImplementation`, chain-neutral spec §2.1): its address and
    ///      `implArgs = abi.encode(ImplArgs([D]))` (T66b §4.5), D checked here: code (`ModuleMissing`), its group and
    ///      this factory (`ModuleMismatch`). The chain values (`chain_uid`, the router, the `SmartKeyAccount`
    ///      implementation) are the clone's env, in its code (CTR-TOK-29).
    constructor(address factory_, bytes memory implArgs) SaltedEIP712Core("SCaaS Dex", "1", bytes32(0)) {
        FACTORY = factory_;
        _s().initialized = true;
        address[] memory ms = abi.decode(implArgs, (ImplArgs)).modules;
        if (ms.length != 2) revert ModuleMissing(ms.length);
        _MD = _module(ms, 0, GROUP_GOVERNANCE, factory_);
        _ML = _module(ms, 1, GROUP_LIQUIDITY, factory_);
    }

    /// @dev Module `i` of `implArgs`: code (`ModuleMissing`), its group and this factory (`ModuleMismatch`).
    function _module(address[] memory ms, uint256 i, uint8 group, address factory_) private view returns (address m) {
        m = ms[i];
        if (m.code.length == 0) revert ModuleMissing(i);
        if (ITokenModule(m).moduleGroup() != group || ITokenModule(m).factory() != factory_) revert ModuleMismatch(i);
    }


    // ------------------------------------------------------------------ init and governance (CTR-DEX-24, CTR-DEX-03, CTR-GOV-01)

    /// @notice `initArgs = abi.encode(DexConfig)` (plan 5g-Z2: the factory forwards the creator's bytes), on a clone
    ///         carrying its env (`EnvMissing`).
    function initialize(bytes32, uint64, bytes calldata initArgs) external {
        if (msg.sender != FACTORY) revert NotFactory();
        ChainEnvCode.requirePresent();
        DexConfig memory cfg = abi.decode(initArgs, (DexConfig));
        DexStorage storage s = _s();
        if (s.initialized) revert AlreadyInitialized();
        s.initialized = true;
        GovernanceLib.Roles memory none;
        GovernanceLib.init(GovernanceBits.DEX_BITS, 0, cfg.admin, cfg.grantDelay, address(0), none, GovernanceBits.DEX_BITS,
            GovernanceBits.DEX_BITS, 0, address(0)); // no contract-only bit: no registry read
        if (cfg.admin != 0) { // the admin holds both bits from creation (B-27: `grantRole` would only propose)
            GovernanceLib.initHolder(GovernanceBits.LISTING, cfg.admin, GovernanceBits.DEX_BITS, 0, address(0));
            GovernanceLib.initHolder(GovernanceBits.FEE_ROUTING, cfg.admin, GovernanceBits.DEX_BITS, 0, address(0));
        }
        s.listedOnly = cfg.listedOnly;
        address p = address(new DexPuller(cfg.rescueTo)); // its `rescueTo` serves `rescue` here too (Fable D P3-5)
        // the tokens' rule (`GovernanceLib.init`): a pool would swallow a stray, the DEX or the puller keep it (M-2)
        address r = cfg.rescueTo;
        if (r == MetaTxLib.UA_POOL || r == MetaTxLib.SHIELD_POOL || r == address(this) || r == p) {
            revert IRescuable.RescueConfigInvalid();
        }
        s.puller = p;
        _setFeeSplit(s, cfg.relayerSharePpm, cfg.treasury);
    }

    /// @notice B-31: `IGovernance` and `IERC165`, as on a token.
    function supportsInterface(bytes4 id) external pure returns (bool) {
        return id == type(IERC165).interfaceId || id == type(IGovernance).interfaceId;
    }

    function _power(uint8 bit) private returns (DexStorage storage) {
        GovernanceUse.use(bit, _govSubject(), 0);
        return _s();
    }

    /// @notice Lists or delists the pair and records each token's kind from the factory (never from a leg).
    function setMarket(address base, address quote, bool listed) external governed {
        DexStorage storage s = _power(GovernanceBits.LISTING);
        if (base == quote || base == address(0) || quote == address(0)) revert BadMarket(base, quote); // C6-9
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

    function setFeeSplit(uint32 relayerSharePpm_, address treasury_) external governed {
        _setFeeSplit(_power(GovernanceBits.FEE_ROUTING), relayerSharePpm_, treasury_);
    }

    /// @notice Lists or delists an interaction target or an executor (CTR-DEX-23).
    function setExchangeTarget(address target, bool listed) external governed {
        _power(GovernanceBits.LISTING).exchangeTarget[target] = listed;
        emit ExchangeTargetSet(target, listed);
    }

    /// @notice DEX-wide listed-only mode for the exchange path (CTR-DEX-23); a leg's `LISTED_POOLS` asks the same.
    function setListedOnly(bool on) external governed {
        _power(GovernanceBits.LISTING).listedOnly = on;
        emit ListedOnlySet(on);
    }

    function _setFeeSplit(DexStorage storage s, uint32 ppm, address t) private {
        if (ppm > PPM || (ppm < PPM && (t == address(0) || t == address(this)))) revert FeeSplitInvalid(ppm, t);
        s.relayerSharePpm = ppm;
        s.treasury = t;
        emit FeeSplitSet(ppm, t);
    }

    /// @dev SCaaS iff the factory made it from a registered (version ≠ 0), non-deprecated implementation.
    function _classify(address token) private view returns (uint8) {
        IOpenFactory f = IOpenFactory(FACTORY);
        if (!f.isToken(token)) return KIND_OUTSIDE;
        (IOpenFactory.TokenKind k, uint64 v) = f.versionOf(token);
        return v != 0 && !f.isTokenDeprecated(k, v) ? KIND_SCAAS : KIND_OUTSIDE;
    }

    function _pair(address a, address b) private pure returns (bytes32) {
        return a < b ? keccak256(abi.encode(a, b)) : keccak256(abi.encode(b, a));
    }

    // ------------------------------------------------------------------ views

    function relayerSharePpm() external view returns (uint32) { return _s().relayerSharePpm; }
    function treasury() external view returns (address) { return _s().treasury; }
    function listedOnly() external view returns (bool) { return _s().listedOnly; }
    function marketListed(address a, address b) external view returns (bool) { return _s().listed[_pair(a, b)]; }
    function tokenKind(address token) external view returns (uint8) { return _s().kind[token]; }
    function tokenKnown(address token) external view returns (bool) { return _s().listings[token] != 0; }
    function exchangeTarget(address target) external view returns (bool) { return _s().exchangeTarget[target]; }
    function factory() external view returns (address) { return FACTORY; }
    /// @notice 0 on the implementation (it carries no env).
    function chainUid() external view returns (bytes32) { return _chainUidRaw(); }
    /// @notice This chain's `SmartKeyAccount` implementation (0 = none), as the tokens expose it; the deploy checks they agree.
    function SMART_KEY_ACCOUNT_IMPL() external view returns (address) { return ChainEnvCode.smartKeyAccountImpl(); }

    /// @notice This instance's env, decoded from its code; all zero on the implementation (CTR-TOK-29).
    function chainEnv() external view returns (IFactoryToken.ChainEnv memory) { return ChainEnvCode.decode(); }

    /// @notice The DEX's checks of an env, by the factory at release deployment: none (it had no constructor check).
    function validateEnv(IFactoryToken.ChainEnv calldata) external pure {}

    function _chainUidInCode() internal pure override returns (bool) { return true; }

    function _chainUidRaw() internal view override returns (bytes32) { return ChainEnvCode.chainUid(); }

    /// @notice ERC-5267 under the clone's `chain_uid` (`ChainUidZero` on the implementation).
    function _eip712DomainBody() internal view override returns (
        bytes1, string memory, string memory, uint256, address, bytes32, uint256[] memory
    ) {
        return _eip712DomainUnder(_chainUid());
    }

    /// @dev No cache (chain-neutral spec §2.4): rebuilt under the clone's `chain_uid` on every call.
    function _domainSeparatorV4() internal view override returns (bytes32) { return _separator(_chainUid()); }

    function puller() external view returns (address) { return _s().puller; }

    /// @notice Anyone, no signature, not an `mtx*` (Fable D P3-5; `DexPuller.rescue`'s rule, CTR-DEX-22): the DEX's whole
    ///         balance of `token` to `rescueTo` (`DexConfig.rescueTo`, held by the puller; 0 = no rescue, `RescueOff`). The
    ///         entry guard keeps it out of a running settlement or plan: only a stray between calls moves.
    function rescue(address token) external nonReentrant {
        address to = DexPuller(_s().puller).rescueTo();
        if (to == address(0)) revert DexPuller.RescueOff();
        uint256 amount = IERC20(token).balanceOf(address(this));
        _send(token, to, amount);
        emit IRescuable.Rescued(token, to, amount);
    }
    function pulled(bytes32 orderHash) external view returns (uint256) { return TradeLib.$().pulled[orderHash]; }
    function minNonce(address from, uint256 batch) external view returns (uint256) {
        return TradeLib.$().minNonce[TradeLib.pad(from)][batch];
    }

    function dexOrderDigest(address sellToken, ITradeToken.TradeOrder calldata o) external view returns (bytes32) {
        return _dexOrderDigest(sellToken, o);
    }

    function _dexOrderDigest(address sellToken, ITradeToken.TradeOrder memory o) private view returns (bytes32) {
        return _hashTypedDataV4(_dexOrderHash(sellToken, o));
    }

    /// @notice Forwarded to the liquidity module (spec 2026-11-10-dex-liquidity.md §9.3 lever (b), owner 2026-11-10): the
    ///         DEX-domain cancels and their digest views share its signature check. The cancel nests the `DexOrder` the
    ///         order was signed as (TS-D19); `pulled` stays keyed by the order digest.
    function cancelDexOrderDigest(address, ITradeToken.TradeOrder calldata) external view returns (bytes32 r) {
        _forwardView(_ML);
    }

    function invalidateNoncesDigest(address, uint256, uint256) external view returns (bytes32 r) { _forwardView(_ML); }

    // ------------------------------------------------------------------ outside-token cancels (CTR-DEX-18, -02)

    /// @notice Never expire; a closed order or a bad signature skips that item (the batch does not revert); a starved
    ///         ERC-1271 check reverts the call (CTR-DEX-08). The body in the liquidity module, under this guard (S1 variant).
    function mtxCancelOrders(DexOrder[] calldata, bytes[] calldata) external nonReentrant { _forwardML(); }

    function mtxInvalidateNonces(address, uint256, uint256, bytes calldata) external nonReentrant { _forwardML(); }

    // ------------------------------------------------------------------ settle (CTR-DEX-16, CTR-DEX-26)

    /// @notice Each settlement atomic; at least one must succeed, else the call reverts (the relayer's simulation
    ///         catches it). A failed settlement emits `MatchFailed` with at most `MAX_REASON` bytes of its revert data;
    ///         `SigCheckGasStarved` and a UA leg's `UAVerifyGas` revert the whole call (CTR-DEX-08, CTR-DEX-26: the
    ///         submitter's gas, not the signature, failed). Only the DEX, a SCaaS token or the registry can raise them:
    ///         every `transfer`, `transferFrom` and `balanceOf` the DEX makes into any token, SCaaS tokens included
    ///         (`_send`, `_bal`, the puller), drops the token's revert data (W-O); one that ran out of gas stays empty.
    function mtxSettle(Settlement[] calldata ss) external nonReentrant returns (bool[] memory ok) {
        ok = new bool[](ss.length);
        bool any;
        for (uint256 i; i < ss.length; ++i) {
            ok[i] = _selfCall(abi.encodeCall(this.settleOne, (ss[i], msg.sender)), ss[i].ref, false);
            any = any || ok[i];
        }
        if (!any) revert NothingSettled();
    }

    /// @dev PD3, the one isolated item of `mtxSettle` and `mtxExchangeBatch`: a self-call with all remaining gas, at
    ///      most `MAX_REASON` bytes of its revert data kept; `SigCheckGasStarved` / `UAVerifyGas` revert the whole call
    ///      with it; anything else is `MatchFailed` (`exchange` false) or `ExchangeFailed` (true) and the next item runs.
    function _selfCall(bytes memory data, bytes32 ref, bool exchange) private returns (bool success) {
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
        if (success) return true;
        if (reason.length >= 4
            && (bytes4(reason) == SigCheckGasStarved.selector || bytes4(reason) == UAVerifyGas.selector)) {
            assembly ("memory-safe") { revert(add(reason, 0x20), mload(reason)) }
        }
        if (exchange) emit ExchangeFailed(ref, reason);
        else emit MatchFailed(ref, reason);
    }

    /// @notice Only through `mtxSettle` (the self-call isolates one settlement); `submitter` is the real caller.
    function settleOne(Settlement calldata s, address submitter) external {
        if (msg.sender != address(this)) revert NotSelf();
        uint256 n = s.makers.length;
        if (n == 0) revert NoMakers();
        Calc memory taker = _decode(s.taker.sellToken, s.taker.shape, s.taker.order, s.taker.uaOrder);
        address tokenA = s.taker.sellToken;      // the taker sells A, the makers sell B
        address tokenB = taker.o.receiveToken;
        _checkMarket(tokenA, tokenB);
        (Calc[] memory makers, uint256 takerSell, uint256 takerRecv) =
            _makers(s.makers, taker.o.from, tokenA, tokenB, submitter);
        if (s.taker.fill != takerSell) revert FillMismatch(takerSell, s.taker.fill);
        _calc(taker, tokenA, submitter, takerSell, takerRecv);
        uint256 balA = _bal(tokenA);
        uint256 balB = _bal(tokenB);
        _pullLeg(tokenA, taker, s.taker, submitter);
        for (uint256 i; i < n; ++i) _pullLeg(tokenB, makers[i], s.makers[i], submitter);
        _pay(s.ref, tokenA, taker, submitter);
        for (uint256 i; i < n; ++i) _pay(s.ref, tokenB, makers[i], submitter);
        if (_bal(tokenA) != balA) revert ConservationBroken(tokenA);
        if (_bal(tokenB) != balB) revert ConservationBroken(tokenB);
    }

    /// @dev The makers of a settlement or a hybrid: each sells B and receives A; no maker's `from` is the taker's
    ///      (makers may share a signer); no order twice. Returns their legs, Σ receive (what the taker sells them) and
    ///      Σ fill (what the taker receives from them).
    function _makers(DexLeg[] calldata ms, bytes32 takerFrom, address tokenA, address tokenB, address submitter)
        private view returns (Calc[] memory makers, uint256 takerSell, uint256 takerRecv)
    {
        makers = new Calc[](ms.length);
        for (uint256 i; i < ms.length; ++i) {
            DexLeg calldata m = ms[i];
            Calc memory c = _decode(m.sellToken, m.shape, m.order, m.uaOrder);
            if (m.sellToken != tokenB || c.o.receiveToken != tokenA) revert TokenMismatch();
            if (c.o.from == takerFrom) revert SelfTrade(c.o.from);
            // a maker sells `fill` at its own price: it receives `⌈fill·receiveAmount/amount⌉` (in its favour)
            uint256 recv = Math.mulDiv(m.fill, c.o.receiveAmount, c.o.amount, Math.Rounding.Ceil);
            _calc(c, tokenB, submitter, m.fill, recv);
            makers[i] = c;
            for (uint256 j; j < i; ++j) if (makers[j].h == c.h) revert DuplicateOrder(c.h);
            takerSell += c.recv;
            takerRecv += c.sold;
        }
    }

    function _checkMarket(address a, address b) private view {
        DexStorage storage s = _s();
        if (a == b) revert TokenMismatch();
        if (!s.listed[_pair(a, b)]) revert MarketNotListed(a, b);
    }

    /// @dev A leg's order in the one form, and its kind from the listing (never from the leg): shape 0 a `TradeOrder`
    ///      (a native id is its address zero-padded, the same word), only on an outside token (`LegShapeUnknown(0)` on a
    ///      SCaaS token, R12); shape 1 a `UATradeOrder`, only on a SCaaS token, whose registry is asked only for a
    ///      derived seller (C; a UA holds no other token, CTR-DEX-26).
    function _decode(address sellToken, uint8 shape, ITradeToken.TradeOrder calldata order,
        ITradeToken.UATradeOrder calldata uaOrder) private view returns (Calc memory c)
    {
        if (shape > 1) revert LegShapeUnknown(shape);
        c.outside = _s().kind[sellToken] != KIND_SCAAS;
        if (shape == 0) {
            if (!c.outside) revert LegShapeUnknown(shape);
            c.o = TradeLib.core(order);
        } else {
            if (c.outside || (!UAKinds.inNativeSpace(uaOrder.from) && IUALedger(sellToken).registry() == address(0))) {
                revert UALegNotLedger(sellToken);
            }
            c.ua = true;
            c.o = uaOrder;
        }
    }


    /// @dev The shape-0 view of a decoded `TradeOrder` (the same memory words; only ever on a shape-0 leg).
    function _native(ITradeToken.UATradeOrder memory o) private pure returns (ITradeToken.TradeOrder memory t) {
        assembly ("memory-safe") { t := o }
    }

    /// @dev Relayer binding, `dex`, the order hash in its signing domain (an outside leg is a `DexOrder`, never
    ///      `ESCROW`), the fee on the aggregate receive (the floor on the exchange path); Path B: the DEX's own checks
    ///      on the matched part. Path A bounds are checked at the pull, by the token or by `TradeLib` on the DEX.
    function _calc(Calc memory c, address sellToken, address submitter, uint256 sold, uint256 recv) private view {
        ITradeToken.UATradeOrder memory o = c.o;
        if (o.relayer != address(0) && o.relayer != submitter) revert WrongRelayer(submitter);
        if (o.dex != address(this)) revert DexMismatch(o.dex);
        if (c.ua) c.h = ITradeToken(sellToken).tradeOrderDigest(o);
        else c.h = _dexOrderDigest(sellToken, _native(o));
        if (c.outside && o.flags & ESCROW != 0) revert BadFlags(c.h); // pulled exactly into the DEX: nothing to escrow
        c.sold = sold;
        c.recv = recv;
        c.fee = Math.mulDiv(recv, o.fee, PPM, Math.Rounding.Ceil);
        if (o.flags & ESCROW != 0) {
            // the token pulls `amount` once (Path B); the DEX checks what the token cannot see
            if (sold > o.amount) revert Overfill(c.h);
            if (sold != o.amount && sold < o.minFill) revert BelowMinFill(c.h);
            if (TradeLib.mulGt(sold, o.receiveAmount, recv, o.amount)) revert PriceLimit(c.h);
            c.refund = o.amount - sold;
        }
    }

    function _pullLeg(address sellToken, Calc memory c, DexLeg calldata l, address submitter) private {
        _pull(sellToken, c, l.sig, l.auth, submitter);
    }

    function _pull(address sellToken, Calc memory c, bytes calldata sig, IUARegistry.UASig calldata auth, address submitter)
        private
    {
        ITradeToken.UATradeOrder memory o = c.o;
        ITradeToken.TradeFill memory f = o.flags & ESCROW != 0
            ? ITradeToken.TradeFill(o.amount, 0, 0, submitter)
            : ITradeToken.TradeFill(c.sold, c.recv, c.fee, submitter);
        if (c.ua) return ITradeToken(sellToken).mtxTrade(o, auth, f);
        // outside token: the DEX runs the token's checks on its own state (the signature once, CTR-DEX-15 step 4),
        // then pulls through the puller
        TradeLib.precheck(o, f, c.h, address(this), sellToken);
        address from = TradeLib.addr(o.from);
        if (TradeLib.$().pulled[c.h] == 0 && !SigCheck.isValid(from, c.h, sig, _cap(from))) revert BadSignature(c.h);
        DexPuller(_s().puller).pull(sellToken, from, TradeLib.record(o, f, c.h, false));
    }

    function _pay(bytes32 ref, address sellToken, Calc memory c, address submitter) private {
        (bytes32 to, uint256 relayerShare, uint256 treasuryShare) = _payLeg(sellToken, c, 0, submitter);
        if (c.ua) {
            emit UALegSettled(ref, c.h, c.o.from, to, c.sold, c.recv - c.fee, c.fee, c.refund, relayerShare,
                treasuryShare);
        } else {
            emit LegSettled(ref, c.h, TradeLib.addr(c.o.from), TradeLib.addr(to), c.sold, c.recv - c.fee, c.fee,
                c.refund, relayerShare, treasuryShare);
        }
    }

    /// @dev Proceeds net of the fee, plus `surplus`, to `destination` (or `from`), the fee split, the Path B refund.
    function _payLeg(address sellToken, Calc memory c, uint256 surplus, address submitter)
        private returns (bytes32 to, uint256 relayerShare, uint256 treasuryShare)
    {
        DexStorage storage s = _s();
        ITradeToken.UATradeOrder memory o = c.o;
        to = o.destination == 0 ? o.from : o.destination;
        relayerShare = Math.mulDiv(c.fee, s.relayerSharePpm, PPM);
        treasuryShare = c.fee - relayerShare;
        _sendTo(o.receiveToken, to, c.recv - c.fee + surplus);
        _send(o.receiveToken, submitter, relayerShare);
        _send(o.receiveToken, s.treasury, treasuryShare);
        _sendTo(sellToken, o.from, c.refund);
    }

    // ------------------------------------------------------------------ exchange path (CTR-DEX-20, -21, -23)

    /// @notice Path (a): the DEX makes each interaction (never on itself or its puller, never `mtxTrade` (the retired
    ///         `uaTrade` and address `mtxTrade` too), `restorePulled`, `increaseAllowance` or Permit2 `approve`
    ///         (controller ruling, pending the owner), listed when a leg or the `LISTING` holder asks); a failing one reverts the plan with `InteractionFailed` (index, target, at most 256 bytes of its data). Every allowance an `approve`
    ///         interaction granted is set back to 0 after the last interaction (controller ruling: the DEX keeps no
    ///         allowance past the route).
    function mtxExchange(ExchangePlan calldata p, Interaction[] calldata xs) external nonReentrant {
        _exchange(p, xs, msg.sender);
    }

    /// @notice Path (a) plans, each isolated as a settlement of `mtxSettle` (spec §5, DX10): one self-call
    ///         `exchangeOne` per plan; a failed plan emits `ExchangeFailed` (at most `MAX_REASON` bytes of its revert
    ///         data) and the next one runs; `SigCheckGasStarved` / `UAVerifyGas` revert the whole call; no plan settled
    ///         ⇒ `NothingSettled`. A later plan sees the state the earlier ones left (`pulled`, balances).
    function mtxExchangeBatch(ExchangePlan[] calldata ps, Interaction[][] calldata xs)
        external nonReentrant returns (bool[] memory ok)
    {
        if (ps.length != xs.length) revert LengthMismatch();
        ok = new bool[](ps.length);
        bool any;
        for (uint256 i; i < ps.length; ++i) {
            ok[i] = _selfCall(abi.encodeCall(this.exchangeOne, (ps[i], xs[i], msg.sender)), ps[i].ref, true);
            any = any || ok[i];
        }
        if (!any) revert NothingSettled();
    }

    /// @notice Only through `mtxExchangeBatch` (the batch holds the reentrancy guard); `submitter` is the real caller.
    function exchangeOne(ExchangePlan calldata p, Interaction[] calldata xs, address submitter) external {
        if (msg.sender != address(this)) revert NotSelf();
        _exchange(p, xs, submitter);
    }

    function _exchange(ExchangePlan calldata p, Interaction[] calldata xs, address submitter) private {
        (Tok[] memory t, Calc[] memory c, bool onlyListed) = _exchangeIn(p, submitter);
        _route(xs, onlyListed);
        _exchangeOut(p, t, c, submitter);
    }


    /// @notice Path (b): the sold fills go to `executor` (listed when a leg or the `LISTING` holder asks), which must transfer at
    ///         least the floors to the DEX inside `exchangeCallback`; re-entry hits `nonReentrant`, a `mtxTrade` or a
    ///         puller call from it fails (it is neither `o.dex` nor the DEX).
    // At the stack limit (via_ir off): add no locals here; move _flows + hand-out + callback into a helper first.
    function mtxExchangeVia(ExchangePlan calldata p, address executor, bytes calldata data) external nonReentrant {
        (Tok[] memory t, Calc[] memory c, bool onlyListed) = _exchangeIn(p, msg.sender);
        if (onlyListed && !_s().exchangeTarget[executor]) revert TargetNotListed(executor);
        (address[] memory tokensOut, uint256[] memory amountsOut, address[] memory tokensIn, uint256[] memory amountsIn)
            = _flows(t);
        for (uint256 i; i < tokensOut.length; ++i) _send(tokensOut[i], executor, amountsOut[i]);
        IExchangeExecutor(executor).exchangeCallback(p.ref, tokensOut, amountsOut, tokensIn, amountsIn, data);
        _exchangeOut(p, t, c, msg.sender);
    }

    // ------------------------------------------------------------------ hybrid (spec §4; DX2, DX5-DX9)

    /// @notice Path (a) of a hybrid: one listed-market taker against 0..n makers at their own price, the rest of its
    ///         sell through the DEX's interactions (as `mtxExchange`); the taker gets its floor less its fee plus every
    ///         unit the route returns above `outsideFloor`.
    function mtxHybrid(HybridPlan calldata p, Interaction[] calldata xs) external nonReentrant {
        (Tok[] memory t, Calc memory taker, Calc[] memory makers, bool onlyListed) = _hybridIn(p, msg.sender);
        _route(xs, onlyListed);
        _hybridOut(p, t, taker, makers, msg.sender);
    }

    /// @notice Path (b) of a hybrid: `outsideSell` of A to `executor` (listed when the taker or the `LISTING` holder asks), which
    ///         must pay at least `outsideFloor` of B to the DEX in `exchangeCallback`.
    function mtxHybridVia(HybridPlan calldata p, address executor, bytes calldata data) external nonReentrant {
        (Tok[] memory t, Calc memory taker, Calc[] memory makers, bool onlyListed) = _hybridIn(p, msg.sender);
        if (onlyListed && !_s().exchangeTarget[executor]) revert TargetNotListed(executor);
        _hybridCall(p, executor, data, t[0].token, t[1].token);
        _hybridOut(p, t, taker, makers, msg.sender);
    }

    function _hybridCall(HybridPlan calldata p, address executor, bytes calldata data, address tokenA, address tokenB)
        private
    {
        _send(tokenA, executor, p.outsideSell);
        IExchangeExecutor(executor).exchangeCallback(p.ref, _one(tokenA), _one(p.outsideSell), _one(tokenB),
            _one(p.outsideFloor), data);
    }

    function _one(address a) private pure returns (address[] memory x) {
        x = new address[](1);
        x[0] = a;
    }

    function _one(uint256 a) private pure returns (uint256[] memory x) {
        x = new uint256[](1);
        x[0] = a;
    }

    /// @dev Spec §4.2 steps 1-3: the check step (`settleOne`'s makers; the taker `fill == Σ maker receive +
    ///      outsideSell`, its floor `Σ maker fill + outsideFloor` with the fee on it), then the exchange path's
    ///      snapshot, pulls and pull check. `t[0]` is A (sold by the taker), `t[1]` B (sold by the makers; the taker's
    ///      floor), then the `extraTokens`. `LISTED_POOLS` is read from the taker only (DX8).
    function _hybridIn(HybridPlan calldata p, address submitter)
        private returns (Tok[] memory t, Calc memory taker, Calc[] memory makers, bool onlyListed)
    {
        taker = _decode(p.taker.sellToken, p.taker.shape, p.taker.order, p.taker.uaOrder);
        address tokenA = p.taker.sellToken;
        address tokenB = taker.o.receiveToken;
        _checkMarket(tokenA, tokenB);
        uint256 sell;
        uint256 recv;
        (makers, sell, recv) = _makers(p.makers, taker.o.from, tokenA, tokenB, submitter);
        sell += p.outsideSell;
        if (p.taker.fill != sell) revert FillMismatch(sell, p.taker.fill);
        _calc(taker, tokenA, submitter, sell, recv + p.outsideFloor);
        onlyListed = _s().listedOnly || taker.o.flags & LISTED_POOLS != 0;
        t = new Tok[](2 + p.extraTokens.length);
        (t[0].token, t[0].sold, t[0].refunds) = (tokenA, taker.sold, taker.refund);
        Tok memory b = t[1];
        (b.token, b.floors) = (tokenB, taker.recv);
        for (uint256 i; i < makers.length; ++i) {
            b.sold += makers[i].sold;
            b.refunds += makers[i].refund;
        }
        for (uint256 i; i < p.extraTokens.length; ++i) _tok(t, p.extraTokens[i]);
        _snap(t);
        _pullLeg(tokenA, taker, p.taker, submitter);
        for (uint256 i; i < makers.length; ++i) _pullLeg(tokenB, makers[i], p.makers[i], submitter);
        _checkPulled(t);
    }

    /// @dev Spec §4.2 steps 5-7: B's output at least `outsideFloor` (`InsufficientOutput`; the excess is the taker's
    ///      surplus: B has one receiver); A at least `base` = snapshot + the makers' receive + the taker's Path B
    ///      refund, the rest the route's `leftover`, at most `outsideSell` (`ConservationBroken(A)`). DX7: a leftover
    ///      is refunded to the taker fee-free if its sold part still satisfies its order (`_takerSoldCheck`), then
    ///      restored to the order's capacity (not an IOC one: it stays closed); a SCaaS leg's restore moves the leftover
    ///      itself (Fable B P2-1), so the DEX pays it only for an outside or IOC leg; the makers paid as in `mtxSettle`,
    ///      the taker as on the exchange path; conservation over every token.
    function _hybridOut(HybridPlan calldata p, Tok[] memory t, Calc memory taker, Calc[] memory makers,
        address submitter) private
    {
        _excess(t);
        Tok memory a = t[0];
        uint256 bal = _bal(a.token);
        uint256 base = a.snap + a.refunds + taker.sold - p.outsideSell;
        if (bal < base) revert ConservationBroken(a.token);
        uint256 leftover = bal - base;
        if (leftover > p.outsideSell) revert ConservationBroken(a.token);
        bool restore = leftover != 0 && taker.o.flags & TradeLib.IOC == 0;
        if (leftover != 0) {
            _takerSoldCheck(taker, leftover);
            taker.sold -= leftover;
            if (!(restore && taker.ua)) taker.refund += leftover; // a SCaaS leg's restore is its refund (B P2-1)
        }
        for (uint256 i; i < makers.length; ++i) _pay(p.ref, t[1].token, makers[i], submitter);
        _payExchange(p.ref, a.token, taker, t[1].excess, submitter);
        if (restore) _restorePulled(a.token, taker, leftover);
        _conserve(t);
    }

    /// @dev DX7 (PD5): the taker's sold part `taker.sold − leftover` must satisfy its signed order, else the hybrid
    ///      reverts with its hash: > 0 (`ZeroFill`), ≥ `minFill` (`BelowMinFill`; never the remainder clause: the sold
    ///      part is below a fill the token allowed), within the limit on the floor `taker.recv` (`PriceLimit`; implied
    ///      by the token's check of the larger fill at the pull, kept anyway).
    function _takerSoldCheck(Calc memory taker, uint256 leftover) internal pure {
        uint256 sold = taker.sold - leftover;
        ITradeToken.UATradeOrder memory o = taker.o;
        if (sold == 0) revert ZeroFill(taker.h);
        if (sold < o.minFill) revert BelowMinFill(taker.h);
        if (TradeLib.mulGt(sold, o.receiveAmount, taker.recv, o.amount)) revert PriceLimit(taker.h);
    }

    /// @dev DX7: the refunded leftover is fillable again — the SCaaS token's `restorePulled` (which moves it from this
    ///      DEX to the taker's `from`, B P2-1), or this DEX's own `TradeLib` state for an outside token.
    function _restorePulled(address tokenA, Calc memory c, uint256 amount) private {
        if (c.ua) ITradeToken(tokenA).restorePulled(c.o, amount);
        else TradeLib.restore(c.o, c.h, amount, address(this));
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
    function _exchangeIn(ExchangePlan calldata p, address submitter) private returns (Tok[] memory t, Calc[] memory c, bool onlyListed) {
        DexStorage storage s = _s();
        uint256 n = p.legs.length;
        if (n == 0) revert NoLegs();
        onlyListed = s.listedOnly;
        t = new Tok[](2 * n + p.extraTokens.length);
        c = new Calc[](n);
        for (uint256 i; i < n; ++i) {
            ExchangeLeg calldata l = p.legs[i];
            Calc memory ci = _decode(l.sellToken, l.shape, l.order, l.uaOrder);
            address rt = ci.o.receiveToken;
            if (s.listings[l.sellToken] == 0) revert TokenNotKnown(l.sellToken);
            if (s.listings[rt] == 0) revert TokenNotKnown(rt);
            for (uint256 j; j < i; ++j) if (c[j].o.from == ci.o.from) revert SelfTrade(ci.o.from);
            _calc(ci, l.sellToken, submitter, l.sellFill, l.receiveFill);
            c[i] = ci;
            if (ci.o.flags & LISTED_POOLS != 0) onlyListed = true;
            Tok memory ts = _tok(t, l.sellToken);
            ts.sold += ci.sold;
            ts.refunds += ci.refund;
            _tok(t, rt).floors += ci.recv;
        }
        for (uint256 i; i < p.extraTokens.length; ++i) _tok(t, p.extraTokens[i]);
        _snap(t);
        for (uint256 i; i < n; ++i) _pull(p.legs[i].sellToken, c[i], p.legs[i].sig, p.legs[i].auth, submitter);
        _checkPulled(t);
    }

    /// @dev Trims `t` to its entries and snapshots the DEX's balance of each.
    function _snap(Tok[] memory t) private view {
        uint256 nt;
        while (nt < t.length && t[nt].token != address(0)) ++nt;
        assembly ("memory-safe") { mstore(t, nt) }
        for (uint256 i; i < nt; ++i) {
            t[i].snap = _bal(t[i].token);
            t[i].floorsLeft = t[i].floors;
        }
    }

    /// @dev After the pulls: each token's balance rose by exactly what was pulled.
    function _checkPulled(Tok[] memory t) private view {
        for (uint256 i; i < t.length; ++i) {
            Tok memory x = t[i];
            if (_bal(x.token) != x.snap + x.sold + x.refunds) revert ConservationBroken(x.token);
        }
    }


    /// @dev Steps 5-6: the surplus per receive token (CTR-DEX-21), the payouts, conservation over every token (a
    ///      sold-only or intermediate leftover fails there: a route bug, not something to assign).
    function _exchangeOut(ExchangePlan calldata p, Tok[] memory t, Calc[] memory c, address submitter) private {
        _excess(t);
        for (uint256 i; i < p.legs.length; ++i) {
            Tok memory x = _tok(t, c[i].o.receiveToken);
            uint256 share = x.floorsLeft == c[i].recv ? x.excess - x.paid : Math.mulDiv(x.excess, c[i].recv, x.floors);
            x.floorsLeft -= c[i].recv;
            x.paid += share;
            _payExchange(p.ref, p.legs[i].sellToken, c[i], share, submitter);
        }
        _conserve(t);
    }

    /// @dev Per receive token: its balance must cover the snapshot, the refunds and the floors (`InsufficientOutput`);
    ///      the rest is the excess (CTR-DEX-21).
    function _excess(Tok[] memory t) private view {
        for (uint256 i; i < t.length; ++i) {
            Tok memory x = t[i];
            if (x.floors == 0) continue;
            uint256 bal = _bal(x.token);
            uint256 keep = x.snap + x.refunds + x.floors;
            if (bal < keep) revert InsufficientOutput(x.token);
            x.excess = bal - keep;
        }
    }

    /// @dev After the payouts: every token back at its snapshot.
    function _conserve(Tok[] memory t) private view {
        for (uint256 i; i < t.length; ++i) {
            if (_bal(t[i].token) != t[i].snap) revert ConservationBroken(t[i].token);
        }
    }

    function _payExchange(bytes32 ref, address sellToken, Calc memory c, uint256 surplus, address submitter) private {
        (bytes32 to,,) = _payLeg(sellToken, c, surplus, submitter);
        uint256 limit = Math.mulDiv(c.sold, c.o.receiveAmount, c.o.amount, Math.Rounding.Ceil);
        if (c.ua) {
            emit UAExchangeLegSettled(ref, c.h, c.o.from, to, c.sold, c.recv, surplus, c.fee, c.refund, limit);
        } else {
            emit ExchangeLegSettled(ref, c.h, TradeLib.addr(c.o.from), TradeLib.addr(to), c.sold, c.recv, surplus,
                c.fee, c.refund, limit);
        }
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


    // ------------------------------------------------------------------ governance: forwarded to D (T66b §4.2, S1, S2)

    /// @notice The governance and liquidity modules (§4.5; `OpenFactory` refuses a release whose module is not pinned in the env).
    function modules() external view returns (address[] memory m) {
        m = new address[](2);
        (m[0], m[1]) = (_MD, _ML);
    }

    // ------------------------------------------------------------------ liquidity: forwarded to the liquidity module

    /// @notice CTR-DEX-30: the plan runs in `SCaaSDexLiquidityModule` under this entry's guard. An S1 variant (spec
    ///         2026-11-10-dex-liquidity.md §9.2): the modifier around a DELEGATECALL with a normal return (nothing to
    ///         return), the module's revert data verbatim.
    function mtxLiquidity(LiquidityPlan calldata, Interaction[] calldata) external nonReentrant { _forwardML(); }

    /// @dev The S1 variant's body: DELEGATECALL of this call's calldata to the liquidity module, its revert data verbatim,
    ///      a normal return (the entries it serves return nothing); the caller's `nonReentrant` holds the guard.
    function _forwardML() private {
        (bool ok, bytes memory ret) = _ML.delegatecall(msg.data);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 32), mload(ret))
            }
        }
    }

    /// @notice No guard (S2): a token's capability check reads it while `mtxLiquidity` holds the guard.
    function liquidityOrderDigest(ITradeToken.LiquidityOrder calldata) external view returns (bytes32 r) {
        _forwardView(_ML);
    }

    function GOV_ROUTER() external view returns (address r) { _forwardView(_MD); }
    function features() external view override returns (uint256 r) { _forwardView(_MD); }
    function lockedFeatures() external view override returns (uint256 r) { _forwardView(_MD); }
    function admin() external view override returns (bytes32 r) { _forwardView(_MD); }
    function pendingAdmin() external view override returns (bytes32 r) { _forwardView(_MD); }
    function hasRole(uint8, bytes32) external view override returns (bool r) { _forwardView(_MD); }
    function validBits() external pure override returns (uint256 r) { _forwardPure(); }
    function holderCount(uint8) external view override returns (uint256 r) { _forwardView(_MD); }
    function grantDelay() external view override returns (uint64 r) { _forwardView(_MD); }
    function lastProposedAt() external view override returns (uint64 r) { _forwardView(_MD); }

    function pendingGrant(uint8, bytes32) external view override returns (uint64 a, bytes32 b, bytes32 c, bool d) {
        _forwardView(_MD);
    }

    function grantOf(uint8, bytes32) external view override returns (Grant memory g) { _forwardView(_MD); }

    function bitLabel(uint8) external view override returns (BitType t, bytes4 s, string memory l) {
        _forwardView(_MD);
    }
    function grantRole(uint8, bytes32) external override { _forward(); }
    function setGrant(uint8, bytes32, GrantTerms calldata) external override { _forward(); }
    function cancelGrant(uint8, bytes32) external override { _forward(); }
    function revokeRole(uint8, bytes32) external override { _forward(); }
    function renounceRole(uint8) external override { _forward(); }
    function disableFeature(uint8) external override { _forward(); }
    function transferAdmin(bytes32) external override { _forward(); }
    function acceptAdmin() external override { _forward(); }
    function renounceAdmin() external override { _forward(); }

    /// @dev S1: today's `governed` entry: `_guardIn` (on the DEX the transient guard's check), DELEGATECALL of this call's
    ///      calldata to D, its revert data verbatim on failure, `_guardOut`, its return data verbatim (never a modifier
    ///      with an assembly return, Fable P1-1).
    function _forward() private {
        bool outer = _guardIn();
        (bool ok, bytes memory ret) = _MD.delegatecall(msg.data);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 32), mload(ret))
            }
        }
        _guardOut(outer);
        assembly ("memory-safe") {
            return(add(ret, 32), mload(ret))
        }
    }

    /// @dev S2: a view entry, the same copy and return without a guard, `view` by the registry's R2 cast.
    function _forwardRaw(address d) private {
        (bool ok, bytes memory ret) = d.delegatecall(msg.data);
        assembly ("memory-safe") {
            if iszero(ok) { revert(add(ret, 32), mload(ret)) }
            return(add(ret, 32), mload(ret))
        }
    }

    function _forwardView(address m) private view {
        function(address) f = _forwardRaw;
        function(address) view v;
        assembly ("memory-safe") {
            v := f
        }
        v(m);
    }

    function _forwardViewD() private view { _forwardView(_MD); }

    /// @dev S2: `validBits`, `pure` as before: the immutable's read and the forward under the same cast.
    function _forwardPure() private pure {
        function() view f = _forwardViewD;
        function() pure p;
        assembly ("memory-safe") {
            p := f
        }
        p();
    }
}
