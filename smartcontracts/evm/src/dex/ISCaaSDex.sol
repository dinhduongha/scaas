// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {ITradeToken} from "../trade/ITradeToken.sol";

/// @title The DEX side of `TradeOrder` (CTR-DEX-16, -17, -11, -03, -24, -18, -22, -08, -20, -21, -23): one taker against
///        many makers per settlement, or a plan of orders against AMM routes (the exchange path); every leg pulled into
///        the DEX (a SCaaS token through its `mtxTrade`, an outside token through the `DexPuller` against a `DexOrder`),
///        every party, fee share, surplus and refund paid in the same call, and the DEX's balance of every token
///        unchanged at the end.
interface ISCaaSDex {
    /// @notice Written once by `initialize` (CTR-DEX-24). `relayerSharePpm` of every fee goes to the submitter, the
    ///         rest to `treasury`. `listedOnly`: every exchange target or executor must be listed (CTR-DEX-23).
    struct DexConfig {
        address admin;
        uint32 relayerSharePpm;
        address treasury;
        bool listedOnly;
    }

    /// @notice One order in one settlement; `fill` = its `sellFill` in this call (Path B: the matched part).
    struct Leg {
        address sellToken;
        ITradeToken.TradeOrder o;
        bytes sig;
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
        Leg taker;
        Leg[] makers;
    }

    /// @notice One order on the exchange path (CTR-DEX-20): `sellFill` of its sell token in this call (Path B: the
    ///         matched part), `receiveFill` the floor the submitter commits to; the order gets the floor plus its share
    ///         of the surplus (CTR-DEX-21).
    struct ExchangeLeg {
        address sellToken;
        ITradeToken.TradeOrder o;
        bytes sig;
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

    event MarketSet(address indexed base, address indexed quote, bool listed);
    event FeeSplitSet(uint32 relayerSharePpm, address treasury);
    /// @notice `received` is net of the DEX fee: the party gets `receiveFill - dexFee`, so `received + dexFee` is the gross
    ///         and `relayerShare + treasuryShare == dexFee`. `destination` is where `received` went.
    event LegSettled(bytes32 indexed ref, bytes32 indexed orderHash, address indexed from, address destination,
        uint256 sold, uint256 received, uint256 dexFee, uint256 refund, uint256 relayerShare, uint256 treasuryShare);
    /// @notice `reason` = the failed settlement's revert data, at most its first 256 bytes.
    event MatchFailed(bytes32 indexed ref, bytes reason);
    /// @notice Raised by `TradeLib` on outside-token legs and DEX-side cancels (same as `ITradeToken`), listed for the ABI.
    event TradeFilled(bytes32 indexed orderHash, address indexed from, uint256 sellFill, uint256 receiveFill,
        uint256 dexFee);
    event OrderCancelled(bytes32 indexed orderHash, address indexed from);
    event NoncesInvalidated(address indexed from, uint256 indexed batch, uint256 minNonce);
    event ExchangeTargetSet(address indexed target, bool listed);
    event ListedOnlySet(bool on);
    /// @notice `receivedFloor` is the gross floor (`receiveFill`): the party gets `receivedFloor - dexFee + surplus`;
    ///         `limitReceive = ceil(sold · receiveAmount / amount)` is what the signed price guarantees for `sold`.
    event ExchangeLegSettled(bytes32 indexed ref, bytes32 indexed orderHash, address indexed from, address destination,
        uint256 sold, uint256 receivedFloor, uint256 surplus, uint256 dexFee, uint256 refund, uint256 limitReceive);

    error NotFactory();
    error AlreadyInitialized();
    error NotAdmin(address caller);
    error FeeSplitInvalid(uint32 relayerSharePpm, address treasury);
    error NotSelf();
    error NothingSettled();
    error NoMakers();
    error WrongRelayer(address submitter);
    error DexMismatch(address dex);
    error TokenMismatch();
    error SelfTrade(address from);
    error DuplicateOrder(bytes32 orderHash);
    error MarketNotListed(address tokenA, address tokenB);
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
    error BadFlags(bytes32 orderHash);
    error ZeroAmount(bytes32 orderHash);
    error BadMinFill(bytes32 orderHash);
    error FeeAboveCap(bytes32 orderHash);
    error OrderClosed(bytes32 orderHash);
    error ZeroFill(bytes32 orderHash);
    error FeeAboveSigned(bytes32 orderHash);
    error EscrowFillShape(bytes32 orderHash);
    error MinNonceNotIncreasing(uint256 current, uint256 requested);
    error MinNonceAboveCap(uint256 requested);
    /// @notice `SigCheck`'s: the submitter left too little gas for a capped ERC-1271 call (CTR-DEX-08); it reverts the
    ///         whole `mtxSettle`, never only one settlement.
    error SigCheckGasStarved(uint256 cap, uint256 gasLeft);
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

    function initialize(address creator, uint64 version, DexConfig calldata cfg) external;
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
    function setExchangeTarget(address target, bool listed) external;
    function setListedOnly(bool on) external;

    function dexOrderDigest(address sellToken, ITradeToken.TradeOrder calldata o) external view returns (bytes32);
    function cancelOrderDigest(bytes32 orderHash) external view returns (bytes32);
    function invalidateNoncesDigest(address from, uint256 batch, uint256 newMin) external view returns (bytes32);
    /// @notice Fill state of outside-token orders, kept by the DEX (`h` = the `DexOrder` digest).
    function pulled(bytes32 orderHash) external view returns (uint256);
    function minNonce(address from, uint256 batch) external view returns (uint256);
    /// @notice The `DexPuller` holders of outside tokens approve (CTR-DEX-22), deployed by `initialize`.
    function puller() external view returns (address);

    function admin() external view returns (address);
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
