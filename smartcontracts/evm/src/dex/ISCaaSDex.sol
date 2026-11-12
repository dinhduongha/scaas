// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ITradeToken} from "../trade/ITradeToken.sol";
import {IUARegistry} from "../ua/IUARegistry.sol";

/// @title The DEX side of `TradeOrder` and `UATradeOrder` (CTR-DEX-16, -17, -11, -03, -24, -18, -22, -08, -20, -21,
///        -23, -26): one taker against many makers per settlement, or a plan of orders against AMM routes (the exchange
///        path); every leg pulled into the DEX (a SCaaS token's `UATradeOrder` through its `mtxTrade`, an outside
///        token's `TradeOrder` through the `DexPuller` against a `DexOrder`), every party, fee share, surplus and refund paid in the same
///        call (a derived UA by `transferToUA`), and the DEX's balance of every token unchanged at the end.
interface ISCaaSDex {
    /// @notice Written once by `initialize` (CTR-DEX-24). `relayerSharePpm` of every fee goes to the submitter, the
    ///         rest to `treasury`. `listedOnly`: every exchange target or executor must be listed (CTR-DEX-23).
    ///         `grantDelay`: the admin's two calls (spec §1.6), at most 30 days. `rescueTo`: the `DexPuller`'s rescue
    ///         destination (spec §6.2), immutable, 0 = `RescueLib.SCAAS_DEV_RESCUE` (CTR-GOV-25); the DEX's own `rescue`
    ///         sends a stray there too (Fable D P3-5).
    struct DexConfig {
        bytes32 admin;
        uint32 relayerSharePpm;
        address treasury;
        bool listedOnly;
        uint64 grantDelay;
        address rescueTo;
    }

    /// @notice One order in one settlement; `fill` = its `sellFill` in this call (Path B: the matched part). Tagged
    ///         (CTR-DEX-26; ua-mtx-merge T6, R12): `shape` 0 = an outside token's `TradeOrder` in `order`, signed as
    ///         `DexOrder` in `sig`; 1 = a SCaaS token's `UATradeOrder` in `uaOrder`, authorized in `auth` (a derived
    ///         signer's registry auth, a native id's own signature in `auth.signature`). The members of the other shape
    ///         stay zero; nothing reads them (Appendix X row 20).
    struct DexLeg {
        address sellToken;
        uint8 shape;
        ITradeToken.TradeOrder order;
        ITradeToken.UATradeOrder uaOrder;
        bytes sig;
        IUARegistry.UASig auth;
        uint256 fill;
    }

    /// @notice An outside-token order (CTR-DEX-18): the same `TradeOrder`, signed in the DEX's domain as
    ///         `DexOrder(address sellToken,TradeOrder order)`, `order.dex` = this DEX.
    struct DexOrder {
        address sellToken;
        ITradeToken.TradeOrder order;
    }

    /// @notice `ref` is the submitter's, echoed in events only; taker/makers is a call-time arrangement.
    struct Settlement {
        bytes32 ref;
        DexLeg taker;
        DexLeg[] makers;
    }

    /// @notice One order on the exchange path (CTR-DEX-20): `sellFill` of its sell token in this call (Path B: the
    ///         matched part), `receiveFill` the floor the submitter commits to; the order gets the floor plus its share
    ///         of the surplus (CTR-DEX-21).
    struct ExchangeLeg {
        address sellToken;
        uint8 shape;
        ITradeToken.TradeOrder order;
        ITradeToken.UATradeOrder uaOrder;
        bytes sig;
        IUARegistry.UASig auth;
        uint256 sellFill;
        uint256 receiveFill;
    }

    /// @notice A call the DEX makes on path (a); no value: the DEX holds no native coin.
    struct Interaction {
        address target;
        bytes data;
    }

    /// @notice One route, atomic. `extraTokens`: intermediate hop tokens that pass through the DEX (snapshotted; each
    ///         must end at its snapshot).
    struct ExchangePlan {
        bytes32 ref;
        ExchangeLeg[] legs;
        address[] extraTokens;
    }

    /// @notice One listed-market taker against 0..n makers at the makers' own prices, the rest of the taker's sell
    ///         routed outside (spec §4, DX2, DX5). `taker` sells A (= `taker.sellToken`) and receives B (its order's
    ///         `receiveToken`), `taker.fill == Σ maker receive + outsideSell`; each maker sells B, receives A, `fill` =
    ///         its `sellFill`; `outsideSell` of A goes to the route, which must return at least `outsideFloor` of B;
    ///         `extraTokens` are intermediate hop tokens (snapshotted; each must end at its snapshot).
    struct HybridPlan {
        bytes32 ref;
        DexLeg taker;
        DexLeg[] makers;
        uint256 outsideSell;
        uint256 outsideFloor;
        address[] extraTokens;
    }

    /// @notice A signed liquidity order and how this call executes it (CTR-DEX-30, spec 2026-11-10-dex-liquidity.md §4.1).
    ///         `auth`: a derived signer's registry auth, a native signer's signature in `auth.signature`; `pull[i]` the
    ///         amount of input `i` pulled (`0 < pull[i] <= order.inputs[i].amount`); `positionId` the received position's
    ///         id, 0 iff none is received; `extraTokens` intermediate hop tokens (<= 8, distinct, disjoint from the order's
    ///         tokens and its manager; each must end at its snapshot).
    struct LiquidityPlan {
        bytes32 ref;
        ITradeToken.LiquidityOrder order;
        IUARegistry.UASig auth;
        uint256[] pull;
        uint256 positionId;
        address[] extraTokens;
    }

    event MarketSet(address indexed base, address indexed quote, bool listed);
    event FeeSplitSet(uint32 relayerSharePpm, address treasury);
    /// @notice `received` is net of the DEX fee: the party gets `receiveFill - dexFee`, so `received + dexFee` is the gross
    ///         and `relayerShare + treasuryShare == dexFee`. `destination` is where `received` went.
    event LegSettled(bytes32 indexed ref, bytes32 indexed orderHash, address indexed from, address destination,
        uint256 sold, uint256 received, uint256 dexFee, uint256 refund, uint256 relayerShare, uint256 treasuryShare);
    /// @notice `LegSettled` of a shape-1 leg, every SCaaS leg (CTR-DEX-26, R18): ids, a native signer zero-padded;
    ///         `destination` is where `received` went. `LegSettled` is an outside leg's.
    event UALegSettled(bytes32 indexed ref, bytes32 indexed orderHash, bytes32 indexed from, bytes32 destination,
        uint256 sold, uint256 received, uint256 dexFee, uint256 refund, uint256 relayerShare, uint256 treasuryShare);
    /// @notice `reason` = the failed settlement's revert data, at most its first 256 bytes.
    event MatchFailed(bytes32 indexed ref, bytes reason);
    /// @notice `mtxExchangeBatch`: `reason` = the failed plan's revert data, at most its first 256 bytes.
    event ExchangeFailed(bytes32 indexed ref, bytes reason);
    /// @notice Raised by `TradeLib` on outside-token legs and DEX-side cancels (same as `ITradeToken`), listed for the ABI.
    event TradeFilled(bytes32 indexed orderHash, address indexed from, uint256 sellFill, uint256 receiveFill,
        uint256 dexFee);
    event OrderCancelled(bytes32 indexed orderHash, address indexed from);
    event PullRestored(bytes32 indexed orderHash, uint256 amount);
    event NoncesInvalidated(address indexed from, uint256 indexed batch, uint256 minNonce);
    event ExchangeTargetSet(address indexed target, bool listed);
    event ListedOnlySet(bool on);
    /// @notice `receivedFloor` is the gross floor (`receiveFill`): the party gets `receivedFloor - dexFee + surplus`;
    ///         `limitReceive = ceil(sold · receiveAmount / amount)` is what the signed price guarantees for `sold`.
    event ExchangeLegSettled(bytes32 indexed ref, bytes32 indexed orderHash, address indexed from, address destination,
        uint256 sold, uint256 receivedFloor, uint256 surplus, uint256 dexFee, uint256 refund, uint256 limitReceive);
    /// @notice `ExchangeLegSettled` of a shape-1 leg (CTR-DEX-26).
    event UAExchangeLegSettled(bytes32 indexed ref, bytes32 indexed orderHash, bytes32 indexed from,
        bytes32 destination, uint256 sold, uint256 receivedFloor, uint256 surplus, uint256 dexFee, uint256 refund,
        uint256 limitReceive);

    error NotFactory();
    error AlreadyInitialized();
    error FeeSplitInvalid(uint32 relayerSharePpm, address treasury);
    error NotSelf();
    error NothingSettled();
    error NoMakers();
    error WrongRelayer(address submitter);
    error DexMismatch(address dex);
    error TokenMismatch();
    /// @notice Over ids: a native order and its zero-padded id are one party (CTR-DEX-26).
    error SelfTrade(bytes32 from);
    /// @notice A leg tag other than 0 (`TradeOrder`, an outside token) or 1 (`UATradeOrder`, a SCaaS token), or a
    ///         shape-0 leg selling a SCaaS token (R12).
    error LegShapeUnknown(uint8 shape);
    /// @notice A shape-1 leg whose sell token is not a SCaaS token, or a derived seller's on a SCaaS token whose UA
    ///         ledger is off (a UA holds no other token; C).
    error UALegNotLedger(address token);
    /// @notice A payout or refund to a derived UA in a token that is not a SCaaS token with its UA ledger on.
    error UAReceiveNotLedger(address token);
    error DuplicateOrder(bytes32 orderHash);
    error MarketNotListed(address tokenA, address tokenB);
    /// @notice `setMarket` with equal or zero tokens (C6-9).
    error BadMarket(address base, address quote);
    /// @notice An outside leg or a DEX-side cancel whose signature does not verify (ECDSA, or ERC-1271 under its cap);
    ///         the argument is the digest that was checked.
    error BadSignature(bytes32 digest);
    error LengthMismatch();
    /// @notice Raised by `TradeLib` on outside-token legs (same selectors as `ITradeToken`), listed for the ABI.
    error NotDex(address caller);
    error DexNotContract(address dex);
    error SelfOrder(bytes32 orderHash);
    error OrderExpired(bytes32 orderHash);
    error NonceInvalidated(bytes32 orderHash);
    error NonceAboveCap(bytes32 orderHash);
    error BadFlags(bytes32 orderHash);
    error ZeroAmount(bytes32 orderHash);
    error BadMinFill(bytes32 orderHash);
    error FeeAboveCap(bytes32 orderHash);
    error OrderClosed(bytes32 orderHash);
    error ZeroFill(bytes32 orderHash);
    error FeeAboveSigned(bytes32 orderHash);
    error EscrowFillShape(bytes32 orderHash);
    error RestoreExceedsPull(bytes32 orderHash);
    error MinNonceNotIncreasing(uint256 current, uint256 requested);
    error MinNonceAboveCap(uint256 requested);
    /// @notice `SigCheck`'s: the submitter left too little gas for a capped ERC-1271 call (CTR-DEX-08); it reverts the
    ///         whole `mtxSettle` or `mtxExchangeBatch`, never only one item. The registry's `UAVerifyGas()` (a UA
    ///         leg's verify could not get its cap) does the same (CTR-DEX-26).
    error SigCheckGasStarved(uint256 cap, uint256 gasLeft);
    error UAVerifyGas();
    /// @notice A path (a) interaction failed (CTR-DEX-20): its position, target and at most 256 bytes of its revert
    ///         data, so a target cannot forge `SigCheckGasStarved` / `UAVerifyGas` or return a bomb.
    error InteractionFailed(uint256 index, address target, bytes reason);
    error FillMismatch(uint256 expected, uint256 got);
    /// @notice Path B checks the DEX makes on the matched part (the token checks Path A itself).
    error BelowMinFill(bytes32 orderHash);
    error PriceLimit(bytes32 orderHash);
    error Overfill(bytes32 orderHash);
    error ConservationBroken(address token);
    /// @notice Exchange path (CTR-DEX-20, -21, -23).
    error NoLegs();
    error TokenNotKnown(address token);
    error ForbiddenTarget(address target);
    error ForbiddenSelector(address target, bytes4 selector);
    error TargetNotListed(address target);
    error InsufficientOutput(address token);
    /// @notice Liquidity (CTR-DEX-30, -31): `code` 1 no input or no output, 2 more than eight, 3 a zero, repeated or shared
    ///         token or a zero maximum, 4 the position fields disagree, 5 a recipient that is the DEX, its puller, a plan
    ///         token or the manager; 6 is a token's (not exactly one input).
    error LiquidityShape(uint8 code);
    error PositionNotReceived(uint256 id);
    error PositionReaderNotListed(address reader);
    error PositionMismatch(uint256 id);
    error PositionBelowMin(uint256 id, uint128 liquidity);
    error PositionNotDelivered(uint256 id);
    error PositionUnreadable(address reader);

    /// @notice A liquidity order executed (CTR-DEX-30 step 9): per input what was pulled and refunded (a refund may exceed
    ///         its pull: fees a position collected), per output what reached the DEX net of the fee and the fee; the
    ///         received position and its liquidity (0, 0 when none).
    event LiquiditySettled(bytes32 indexed ref, bytes32 indexed orderHash, bytes32 indexed from, bytes32 recipient,
        uint256[] pulled, uint256[] refunded, uint256[] received, uint256[] dexFees, uint256 positionId, uint128 liquidity);

    /// @notice Factory only, in the clone's creating call, on a clone carrying its env (`IFactoryToken.EnvMissing`);
    ///         `creatorId` the creator's UA id (S3); `initArgs = abi.encode(DexConfig)` (plan 5g-Z2).
    function initialize(bytes32 creatorId, uint64 version, bytes calldata initArgs) external;
    function setMarket(address base, address quote, bool listed) external;
    function setFeeSplit(uint32 relayerSharePpm, address treasury) external;
    function mtxSettle(Settlement[] calldata s) external returns (bool[] memory ok);
    /// @notice Outside-token orders (CTR-DEX-18, CTR-DEX-02): closed or bad-signature items are skipped.
    function mtxCancelOrders(DexOrder[] calldata orders, bytes[] calldata sigs) external;
    function mtxInvalidateNonces(address from, uint256 batch, uint256 newMin, bytes calldata sig) external;
    /// @notice Exchange path (a): the DEX makes each interaction itself (CTR-DEX-20, -23).
    function mtxExchange(ExchangePlan calldata p, Interaction[] calldata interactions) external;
    /// @notice Exchange path (b): the pulled sell fills go to `executor`, which pays the DEX back in its callback.
    function mtxExchangeVia(ExchangePlan calldata p, address executor, bytes calldata data) external;
    /// @notice Path (a) plans, one isolated self-call each (spec §5, DX10): a failed plan emits `ExchangeFailed`, the
    ///         others still settle; `SigCheckGasStarved` / `UAVerifyGas` revert the whole call; `NothingSettled` when
    ///         no plan settles; `LengthMismatch` unless `ps.length == interactions.length`.
    function mtxExchangeBatch(ExchangePlan[] calldata ps, Interaction[][] calldata interactions)
        external returns (bool[] memory ok);
    /// @notice The DEX only (`NotSelf`): one plan of `mtxExchangeBatch`, `submitter` its caller.
    function exchangeOne(ExchangePlan calldata p, Interaction[] calldata interactions, address submitter) external;
    /// @notice Hybrid path (a): makers at their own price (`⌈fill · receiveAmount / amount⌉`, `mtxSettle`'s fee and
    ///         self-trade rule), the rest through the DEX's own interactions; the taker gets its floor
    ///         (`Σ maker fill + outsideFloor`, the fee once on it) plus everything the route returns above
    ///         `outsideFloor`, fee-free. `LISTED_POOLS` is read from the taker only. A part of `outsideSell` the route
    ///         leaves (DX7) is refunded to the taker, fee-free, if its sold part still meets its order (`ZeroFill`,
    ///         `BelowMinFill`, `PriceLimit` with its hash, else the plan reverts), and restored to its capacity.
    function mtxHybrid(HybridPlan calldata p, Interaction[] calldata interactions) external;
    /// @notice Hybrid path (b): `outsideSell` of A goes to `executor`, which must pay at least `outsideFloor` of B to
    ///         the DEX in `exchangeCallback(ref, [A], [outsideSell], [B], [outsideFloor], data)`.
    function mtxHybridVia(HybridPlan calldata p, address executor, bytes calldata data) external;
    /// @notice Liquidity (CTR-DEX-30): one signed `LiquidityOrder`, atomic: check, snapshot, pull (SCaaS inputs through each
    ///         token's `mtxLiquidityPull`, outside inputs and a given position through the puller), the interactions
    ///         (CTR-DEX-23), the received position against its listed reader, the outputs at their minima at the DEX after
    ///         the fee and at the recipient, the refunds, conservation. Forwarded to the liquidity module under the guard.
    function mtxLiquidity(LiquidityPlan calldata p, Interaction[] calldata interactions) external;
    /// @notice `h` of a liquidity order in this DEX's domain; no guard (a token's capability check reads it mid-plan).
    function liquidityOrderDigest(ITradeToken.LiquidityOrder calldata o) external view returns (bytes32);
    function setExchangeTarget(address target, bool listed) external;
    function setListedOnly(bool on) external;

    function dexOrderDigest(address sellToken, ITradeToken.TradeOrder calldata o) external view returns (bytes32);
    /// @notice `CancelDexOrder(DexOrder order)`: the digest `mtxCancelOrders` checks.
    function cancelDexOrderDigest(address sellToken, ITradeToken.TradeOrder calldata o) external view returns (bytes32);
    function invalidateNoncesDigest(address from, uint256 batch, uint256 newMin) external view returns (bytes32);
    /// @notice Fill state of outside-token orders, kept by the DEX (`h` = the `DexOrder` digest).
    function pulled(bytes32 orderHash) external view returns (uint256);
    function minNonce(address from, uint256 batch) external view returns (uint256);
    /// @notice The `DexPuller` holders of outside tokens approve (CTR-DEX-22), deployed by `initialize`.
    function puller() external view returns (address);
    /// @notice Anyone: the DEX's whole balance of `token` to the puller's `rescueTo` (never 0, CTR-GOV-25), the puller's rule
    ///         (Fable D P3-5); under the entry guard, so never inside a running settlement or plan.
    function rescue(address token) external;

    function relayerSharePpm() external view returns (uint32);
    function treasury() external view returns (address);
    function listedOnly() external view returns (bool);
    function marketListed(address a, address b) external view returns (bool);
    /// @notice A side of at least one listed market: the exchange path takes only known tokens.
    function tokenKnown(address token) external view returns (bool);
    function exchangeTarget(address target) external view returns (bool);
    /// @notice 0 unknown, 1 SCaaS (made by the factory from a registered, non-deprecated version), 2 outside.
    function tokenKind(address token) external view returns (uint8);
    function factory() external view returns (address);
    function chainUid() external view returns (bytes32);
}

/// @notice An executor of `mtxExchangeVia` (CTR-DEX-20 (b)): it has received `amountsOut` of `tokensOut` and must
///         transfer at least `amountsIn` of `tokensIn` (the floors) to the DEX before it returns; anything more is
///         surplus for the signers.
interface IExchangeExecutor {
    function exchangeCallback(bytes32 ref, address[] calldata tokensOut, uint256[] calldata amountsOut,
        address[] calldata tokensIn, uint256[] calldata amountsIn, bytes calldata data) external;
}
