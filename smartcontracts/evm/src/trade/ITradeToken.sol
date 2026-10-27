// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

/// @title The token's side of the DEX (CTR-DEX-13, CTR-DEX-15, CTR-DEX-02): a role-free signed `TradeOrder`, checked by
///        the sell token against the fill figures its `dex` passes; funds move only into `dex`, never by allowance.
/// @notice Events and errors raised by `TradeLib` (an external library) are declared here so that they are in the
///         token ABI. Every error carries the order hash where it has one.
interface ITradeToken {
    /// @notice Signed in the sell token's own domain. `nonce` is not consumed per fill: it is the cancel handle of its
    ///         lane (`batch`, distinct from the meta-tx lane of the same name).
    struct TradeOrder {
        address from;          // signer; this token's balance is sold
        address receiveToken;  // what the signer receives
        uint256 amount;        // at most this much of THIS token in total
        uint256 receiveAmount; // signed price limit: `amount` for at least `receiveAmount` (gross, before the DEX fee)
        uint256 minFill;       // per settlement; effective = max(minFill, ceil(amount/2)); = amount => fill-or-kill
        uint256 fee;           // DEX fee rate in ppm on what the signer receives; <= 10 000 (1 %)
        address relayer;       // the only submitter allowed (0 = anyone)
        address dex;           // the only contract that may pull, and the only recipient; a contract
        address destination;   // receives the proceeds in receiveToken; 0 = from
        uint8 flags;           // IOC 1 | ESCROW 2 (Path B; implies IOC) | LISTED_POOLS 4 (not read by the token)
        uint256 batch;         // order lane (minNonce)
        uint256 nonce;         // valid while nonce >= minNonce[from][batch]
        uint256 validUntil;
    }

    /// @notice A UA's order (CTR-DEX-25): `TradeOrder` with `from` and `destination` as ids (a native address
    ///         zero-padded, or a registered SIGNING UA), signed in the sell token's domain under the UA purpose `trade`
    ///         (a native id signs the digest itself). The same 13 ABI words as `TradeOrder`, in the same order.
    struct UATradeOrder {
        bytes32 from;
        address receiveToken;
        uint256 amount;
        uint256 receiveAmount;
        uint256 minFill;
        uint256 fee;
        address relayer;
        address dex;
        bytes32 destination; // receives the proceeds in receiveToken (a derived id: by `transferToUA`); 0 = from
        uint8 flags;
        uint256 batch;       // order lane: one `minNonce` per id across `TradeOrder` and `UATradeOrder`
        uint256 nonce;
        uint256 validUntil;
    }

    /// @notice What the DEX passes: the fill of THIS order (Path B: `amount`, 0, 0) and its own `msg.sender`.
    struct TradeFill {
        uint256 sellFill;
        uint256 receiveFill;
        uint256 dexFee;
        address submitter;
    }

    event TradeFilled(bytes32 indexed orderHash, address indexed from, uint256 sellFill, uint256 receiveFill,
        uint256 dexFee);
    event OrderCancelled(bytes32 indexed orderHash, address indexed from);
    event NoncesInvalidated(address indexed from, uint256 indexed batch, uint256 minNonce);
    /// @notice The `UATradeOrder` twins (CTR-DEX-25), by entry point: a padded native signer gets these too.
    event UATradeFilled(bytes32 indexed orderHash, bytes32 indexed from, uint256 sellFill, uint256 receiveFill,
        uint256 dexFee);
    event UAOrderCancelled(bytes32 indexed orderHash, bytes32 indexed from);
    event UANoncesInvalidated(bytes32 indexed from, uint256 indexed batch, uint256 minNonce);

    error NotDex(address caller);
    error DexNotContract(address dex);
    error SelfOrder(bytes32 orderHash);
    error WrongRelayer(bytes32 orderHash, address submitter);
    error OrderExpired(bytes32 orderHash);
    error NonceInvalidated(bytes32 orderHash);
    error NonceAboveCap(bytes32 orderHash);
    error BadFlags(bytes32 orderHash);
    error ZeroAmount(bytes32 orderHash);
    error BadMinFill(bytes32 orderHash);
    error FeeAboveCap(bytes32 orderHash);
    error OrderClosed(bytes32 orderHash);
    error ZeroFill(bytes32 orderHash);
    error Overfill(bytes32 orderHash);
    error BelowMinFill(bytes32 orderHash);
    error PriceLimit(bytes32 orderHash);
    error FeeAboveSigned(bytes32 orderHash);
    error EscrowFillShape(bytes32 orderHash);
    /// @notice `mtxInvalidateNonces`: strictly increasing, at most `2^128`.
    error MinNonceNotIncreasing(uint256 current, uint256 requested);
    error MinNonceAboveCap(uint256 requested);

    /// @notice Verify `o` (signature, bounds) and move the fill from `o.from` to `o.dex`; only `o.dex` may call.
    function mtxTrade(TradeOrder calldata o, bytes calldata sig, TradeFill calldata f) external;
    /// @notice `CancelOrder(bytes32 orderHash)` signed by `o.from`: closes the order forever; already closed = no-op.
    function mtxCancelOrder(TradeOrder calldata o, bytes calldata sig) external;
    /// @notice `InvalidateNonces(address from,uint256 batch,uint256 minNonce)` signed by `from`.
    function mtxInvalidateNonces(address from, uint256 batch, uint256 newMin, bytes calldata sig) external;

    /// @notice CTR-DEX-25: `mtxTrade` for a `UATradeOrder`; step 4 through the UA rule (a derived `from` by
    ///         `requireAuthorized(from, trade, h, auth)`), skipped when `pulled[h] ≠ 0`; the fill moves by the UA ledger.
    function uaTrade(UATradeOrder calldata o, bytes calldata auth, TradeFill calldata f) external;
    /// @notice `CancelOrder(uaTradeOrderDigest(o))` under `trade`; never expires; already closed = no-op.
    function uaCancelOrder(UATradeOrder calldata o, bytes calldata auth) external;
    /// @notice `UAInvalidateNonces(from, batch, minNonce)` under `trade`; raises the one floor of the id.
    function uaInvalidateNonces(bytes32 from, uint256 batch, uint256 newMin, bytes calldata auth) external;

    function tradeOrderDigest(TradeOrder calldata o) external view returns (bytes32);
    function uaTradeOrderDigest(UATradeOrder calldata o) external view returns (bytes32);
    function uaInvalidateNoncesDigest(bytes32 from, uint256 batch, uint256 newMin) external view returns (bytes32);
    function uaMinNonce(bytes32 from, uint256 batch) external view returns (uint256);
    function cancelOrderDigest(bytes32 orderHash) external view returns (bytes32);
    function invalidateNoncesDigest(address from, uint256 batch, uint256 newMin) external view returns (bytes32);
    function pulled(bytes32 orderHash) external view returns (uint256);
    function minNonce(address from, uint256 batch) external view returns (uint256);
}
