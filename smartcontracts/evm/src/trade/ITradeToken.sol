// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
pragma solidity ^0.8.24;

import {IUARegistry} from "../ua/IUARegistry.sol";

/// @title The token's side of the DEX (CTR-DEX-13, CTR-DEX-15, CTR-DEX-25, CTR-DEX-02): a role-free signed `UATradeOrder`,
///        checked by the sell token against the fill figures its `dex` passes; funds move only into `dex`, never by
///        allowance. ua-mtx-merge T6 (R12, R38): a SCaaS token's order is a `UATradeOrder` for every subject (a native
///        address zero-padded, by its own key, no registry; a derived UA through the registry); the address
///        `TradeOrder` entries and views are in legacy/ua-mtx-merge/. `TradeOrder` stays for the DEX's outside legs.
/// @notice Events and errors raised by `TradeLib` (an external library) are declared here so that they are in the
///         token ABI. Every error carries the order hash where it has one.
interface ITradeToken {
    /// @notice An outside token's order (CTR-DEX-18, R37): signed in the DEX's domain, nested in `DexOrder`; no SCaaS
    ///         token takes it (T6). `nonce` is not consumed per fill: it is the cancel handle of its lane (`batch`,
    ///         distinct from the meta-tx lane of the same name).
    struct TradeOrder {
        address from;          // signer; this token's balance is sold
        address receiveToken;  // what the signer receives
        uint256 amount;        // at most this much of THIS token in total
        uint256 receiveAmount; // signed price limit: `amount` for at least `receiveAmount` (gross, before the DEX fee)
        uint256 minFill;       // per settlement, unless the fill closes the remainder; = amount => fill-or-kill (CTR-DEX-14)
        uint256 fee;           // DEX fee rate in ppm on what the signer receives; <= 10 000 (1 %)
        address relayer;       // the only submitter allowed (0 = anyone)
        address dex;           // the only contract that may pull, and the only recipient; a contract
        address destination;   // receives the proceeds in receiveToken; 0 = from
        uint8 flags;           // IOC 1 | ESCROW 2 (Path B; implies IOC) | LISTED_POOLS 4 (not read by the token)
        uint256 batch;         // order lane (minNonce)
        uint256 nonce;         // valid while nonce >= minNonce[from][batch]
        uint256 validUntil;
    }

    /// @notice A SCaaS token's order (CTR-DEX-25, CTR-DEX-26 shape 1, R12): `TradeOrder` with `from` and `destination`
    ///         as ids (a native address zero-padded, or a registered SIGNING UA), signed in the sell token's domain under
    ///         the UA purpose `trade` (a native id signs the digest itself). The same 13 ABI words as `TradeOrder`, in
    ///         the same order. `nonce` is not consumed per fill: it is the cancel handle of its lane `batch` (one
    ///         `minNonce` per id, a store apart from the meta-tx nonces).
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
        uint256 batch;       // order lane: one `minNonce` per id
        uint256 nonce;
        uint256 validUntil;
    }

    /// @notice A wrap by signature (CTR-TOK-20, TS-D19, R39), signed in the underlying's domain: `UATradeOrder` without
    ///         `dex`, the wrapped token being both what the signer receives and the only contract that may pull. The
    ///         address `WrapOrder` is in legacy/ua-mtx-merge/.
    struct UAWrapOrder {
        bytes32 from;
        address wrappedToken;
        uint256 amount;
        uint256 minMinted;
        uint256 minFill;
        uint256 fee;
        address relayer;
        bytes32 destination;
        uint8 flags;
        uint256 batch;
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

    /// @notice Raised by `TradeLib` on the DEX's outside legs only (no SCaaS token emits them after T6, R18).
    event TradeFilled(bytes32 indexed orderHash, address indexed from, uint256 sellFill, uint256 receiveFill,
        uint256 dexFee);
    event OrderCancelled(bytes32 indexed orderHash, address indexed from);
    event NoncesInvalidated(address indexed from, uint256 indexed batch, uint256 minNonce);
    /// @notice The token's trade events (R18): every subject, a native signer zero-padded.
    event UATradeFilled(bytes32 indexed orderHash, bytes32 indexed from, uint256 sellFill, uint256 receiveFill,
        uint256 dexFee);
    event UAOrderCancelled(bytes32 indexed orderHash, bytes32 indexed from);
    event UANoncesInvalidated(bytes32 indexed from, uint256 indexed batch, uint256 minNonce);
    /// @notice `o.dex` gave back `amount` of what it pulled for `h` in this transaction (DX7: a hybrid's unsold
    ///         remainder, refunded to the signer); `pulled[h]` is lower by `amount`.
    event PullRestored(bytes32 indexed orderHash, uint256 amount);

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
    /// @notice `restorePulled` above what `o.dex` pulled for the order in this transaction.
    error RestoreExceedsPull(bytes32 orderHash);
    /// @notice `mtxInvalidateNonces`: strictly increasing, at most `2^128`.
    error MinNonceNotIncreasing(uint256 current, uint256 requested);
    error MinNonceAboveCap(uint256 requested);

    /// @notice CTR-DEX-15, CTR-DEX-25 (R38): verify `o` and move the fill from `o.from` to `o.dex`; only `o.dex` may
    ///         call. Step 4 through the UA rule under `trade` (a native id by its own key, no registry; a derived one by
    ///         `requireAuthorized`, `UALedgerOff` at `registry() == 0`), skipped when `pulled[h] ≠ 0`.
    function mtxTrade(UATradeOrder calldata o, IUARegistry.UASig calldata auth, TradeFill calldata f) external;
    /// @notice `CancelUAOrder(UATradeOrder order)` (`CancelUAWrapOrder` for a wrap, `dex == receiveToken`) under
    ///         `trade`: closes the order forever; never expires; already closed = no-op.
    function mtxCancelOrder(UATradeOrder calldata o, IUARegistry.UASig calldata auth) external;
    /// @notice `UAInvalidateNonces(from, batch, minNonce)` under `trade`; raises the one floor of the id.
    function mtxInvalidateNonces(bytes32 from, uint256 batch, uint256 newMin, IUARegistry.UASig calldata auth) external;

    /// @notice DX7 (owner 2026-10-30): only `o.dex`, at most what it pulled for the order in THIS transaction (a
    ///         transient counter kept on every pull, EIP-1153); lowers `pulled[h]` by `amount` (the refunded part is
    ///         fillable again). An IOC order stays closed (`OrderClosed`); a cancel in the same transaction clears the
    ///         counter.
    function restorePulled(UATradeOrder calldata o, uint256 amount) external;

    /// @notice The order's digest, the key of `pulled`: a `UATradeOrder`, or a `UAWrapOrder` when `dex == receiveToken`.
    function tradeOrderDigest(UATradeOrder calldata o) external view returns (bytes32);
    function cancelOrderDigest(UATradeOrder calldata o) external view returns (bytes32);
    function invalidateNoncesDigest(bytes32 from, uint256 batch, uint256 newMin) external view returns (bytes32);
    function pulled(bytes32 orderHash) external view returns (uint256);
    function minNonce(bytes32 from, uint256 batch) external view returns (uint256);
}
