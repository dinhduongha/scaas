//! ABI — copied from `smartcontracts/evm/src` (`IMetaTx`, `IERC20MetaTx`, `IERC20Payment`, `ITradeToken`, `MetaTxLib`,
//! `ISCaaSDex`, `MandateWallet`, `IUARegistry`), never inferred: one wrong `indexed` is one wrong topic. Pinned by the forge KATs
//! (`metatx_kat.json`, `metatransfer_kat.json`, `dex_order_kat.json`, `uatrade_kat.json`: digests and relayed calldata). The
//! named typed entries are not here: they are data, `crate::typed`.
// `sol!` builds a constructor per event; `LegSettled` / `UALegSettled` have ten fields.
#![allow(clippy::too_many_arguments)]

use alloy::sol;
use alloy::sol_types::SolInterface;

sol! {
    /// `MetaTxLib.MetaTransaction` (CTR-MTX-15): the signed call of one of the contract's own allowlisted functions.
    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct MetaTransaction {
        address from; bytes data; uint256 batch; uint256 nonce; uint256 validUntil; uint32 mode;
        address relayer; uint256 fee; address feeRecipient;
    }

    /// `MetaTxLib.MetaTransfer` (CTR-MTX-23): a token transfer (`entryRef = 0`) or payment.
    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct MetaTransfer {
        address from; address to; uint256 value; bytes32 entryRef; uint256 batch; uint256 nonce; uint256 validUntil;
        uint32 mode; address relayer; uint256 fee; address feeRecipient;
    }

    /// `MetaTxLib.UAMetaTransaction` (CTR-UA-19/26): `MetaTransaction` with `from` as an id (a native address
    /// zero-padded, or a registered SIGNING UA), signed under the UA purpose `metatx`.
    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct UAMetaTransaction {
        bytes32 from; bytes data; uint256 batch; uint256 nonce; uint256 validUntil; uint32 mode;
        address relayer; uint256 fee; address feeRecipient;
    }

    /// `MetaTxLib.UAMetaTransfer` (CTR-UA-26): `MetaTransfer` on the UA ledger, `from` and `to` ids.
    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct UAMetaTransfer {
        bytes32 from; bytes32 to; uint256 value; bytes32 entryRef; uint256 batch; uint256 nonce; uint256 validUntil;
        uint32 mode; address relayer; uint256 fee; address feeRecipient;
    }

    /// `MetaTxLib.PayMeta` (pay-meta-tax spec §3.1, plan T83): the last parameter of every pay entry, unsigned; its
    /// commitment `metaPayId` is the signed `entryRef`. `payNo` 32 bytes (0 = none; recommended a right-aligned UUIDv7),
    /// `save` the payer's choice to store the payment's record on chain (`paymentsOf`).
    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct PayMeta {
        bytes32 salt; bytes32 payNo; bool save; uint16 schema; bytes body;
    }

    /// `ITradeToken.TradeOrder` (CTR-DEX-13): signed in the sell token's domain (a `DexOrder` for an outside token).
    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct TradeOrder {
        address from; address receiveToken; uint256 amount; uint256 receiveAmount; uint256 minFill; uint256 fee;
        address relayer; address dex; address destination; uint8 flags; uint256 batch; uint256 nonce;
        uint256 validUntil;
    }

    /// `ITradeToken.TradeFill`: what the DEX asks the sell token to pull for one leg (`mtxTrade`).
    #[derive(Debug, PartialEq, Eq)]
    struct TradeFill { uint256 sellFill; uint256 receiveFill; uint256 dexFee; address submitter; }

    /// `ITradeToken.UATradeOrder` (CTR-DEX-25): `TradeOrder` with `from` / `destination` as ids (a native address
    /// zero-padded, or a SIGNING UA), signed under the UA purpose `trade`. The same 13 ABI words in the same order.
    #[derive(Debug, PartialEq, Eq)]
    struct UATradeOrder {
        bytes32 from; address receiveToken; uint256 amount; uint256 receiveAmount; uint256 minFill; uint256 fee;
        address relayer; address dex; bytes32 destination; uint8 flags; uint256 batch; uint256 nonce;
        uint256 validUntil;
    }

    /// `IUARegistry.InnerSig` / `MemberSig` / `UASig` (typed-signing R1): a UA's authorization, explicit fields on every named entry.
    /// `InnerSig` has no list: the type is two levels deep, and that is the depth bound of a decode (owner 2026-11-02).
    #[derive(Debug, PartialEq, Eq)]
    struct InnerSig { uint16 index; bytes sig; }
    #[derive(Debug, PartialEq, Eq)]
    struct MemberSig { uint16 index; InnerSig[] members; bytes sig; }
    #[derive(Debug, PartialEq, Eq)]
    struct UASig { bytes keyData; bytes signature; MemberSig[] members; }

    /// `ISCaaSDex.DexLeg` (CTR-DEX-26, typed-signing C6): one order in one settlement, explicit fields; `shape` 0 reads
    /// `order` + `sig`, 1 reads `uaOrder` + `auth`, the other pair stays zero; `fill` = its sell fill in this call.
    #[derive(Debug, PartialEq, Eq)]
    struct DexLeg {
        address sellToken; uint8 shape; TradeOrder order; UATradeOrder uaOrder; bytes sig; UASig auth; uint256 fill;
    }

    /// `ISCaaSDex.ExchangeLeg` (CTR-DEX-20, -26): an exchange-path order, tagged as `DexLeg`.
    #[derive(Debug, PartialEq, Eq)]
    struct ExchangeLeg {
        address sellToken; uint8 shape; TradeOrder order; UATradeOrder uaOrder; bytes sig; UASig auth; uint256 sellFill;
        uint256 receiveFill;
    }

    /// `ISCaaSDex.ExchangePlan` / `Interaction` (CTR-DEX-20): the exchange path's argument shapes.
    #[derive(Debug, PartialEq, Eq)]
    struct ExchangePlan { bytes32 ref; ExchangeLeg[] legs; address[] extraTokens; }
    #[derive(Debug, PartialEq, Eq)]
    struct Interaction { address target; bytes data; }
    /// `ISCaaSDex.HybridPlan`: makers at their own price plus an outside part (floor `outsideFloor`).
    #[derive(Debug, PartialEq, Eq)]
    struct HybridPlan { bytes32 ref; DexLeg taker; DexLeg[] makers; uint256 outsideSell; uint256 outsideFloor; address[] extraTokens; }

    /// `ITradeToken.LiquidityToken` / `LiquidityOrder` and `ISCaaSDex.LiquidityPlan` (CTR-DEX-30): one signed order in the DEX's
    /// domain, every field named; `int24` ticks sign-extended.
    #[derive(Debug, PartialEq, Eq)]
    struct LiquidityToken { address token; uint256 amount; }
    #[derive(Debug, PartialEq, Eq)]
    struct LiquidityOrder {
        bytes32 from; LiquidityToken[] inputs; LiquidityToken[] outputs; address positionManager; address positionReader;
        uint256 positionIn; bytes32 positionPool; int24 tickLower; int24 tickUpper; uint128 minLiquidity; bytes32 recipient;
        uint256 fee; address relayer; uint8 flags; uint256 batch; uint256 nonce; uint256 validUntil;
    }
    #[derive(Debug, PartialEq, Eq)]
    struct LiquidityPlan { bytes32 ref; LiquidityOrder order; UASig auth; uint256[] pull; uint256 positionId; address[] extraTokens; }

    /// An outside-token order (CTR-DEX-18): the `TradeOrder` signed in the DEX's domain with its sell token.
    #[derive(Debug, PartialEq, Eq)]
    struct DexOrder { address sellToken; TradeOrder order; }

    /// One taker against one or more makers (CTR-DEX-16); `ref` is the submitter's (the venue's trade tag).
    #[derive(Debug, PartialEq, Eq)]
    struct Settlement { bytes32 ref; DexLeg taker; DexLeg[] makers; }

    /// The nested cancels (typed-signing C6): the whole order is signed, a SCaaS token's `UATradeOrder` in its domain under the
    /// UA purpose `trade` (`CancelUAOrder`, `UAInvalidateNonces`, R12), an outside token's `DexOrder` in the DEX's (`CancelDexOrder`,
    /// `InvalidateNonces`). The token's address `CancelOrder` is in `legacy/ua-mtx-merge/abi.rs`.
    struct CancelUAOrder { UATradeOrder order; }
    struct UAInvalidateNonces { bytes32 from; uint256 batch; uint256 minNonce; }
    struct CancelDexOrder { DexOrder order; }
    struct InvalidateNonces { address from; uint256 batch; uint256 minNonce; }

    /// A token's DEX-only liquidity pull (CTR-DEX-30): never a job; its selector is the ERC-165 id the pre-check asks.
    #[derive(Debug)]
    interface ILiquidityPull {
        function mtxLiquidityPull(LiquidityOrder o, UASig auth, uint256 amount, address submitter) external;
    }

    /// `SCaaSDex` (a clone per DEX, `createDex`): what the venue sends and reads.
    #[derive(Debug)]
    interface ISCaaSDex {
        function mtxSettle(Settlement[] s) external returns (bool[] ok);
        function mtxExchange(ExchangePlan p, Interaction[] interactions) external;
        function mtxExchangeVia(ExchangePlan p, address executor, bytes data) external;
        function mtxExchangeBatch(ExchangePlan[] ps, Interaction[][] interactions) external returns (bool[] ok);
        function exchangeOne(ExchangePlan p, Interaction[] interactions, address submitter) external;
        function mtxHybrid(HybridPlan p, Interaction[] interactions) external;
        function mtxHybridVia(HybridPlan p, address executor, bytes data) external;
        function mtxLiquidity(LiquidityPlan p, Interaction[] interactions) external;
        function modules() external view returns (address[] m);
        function liquidityOrderDigest(LiquidityOrder o) external view returns (bytes32);
        event LiquiditySettled(bytes32 indexed ref, bytes32 indexed orderHash, bytes32 indexed from, bytes32 recipient,
            uint256[] pulled, uint256[] refunded, uint256[] received, uint256[] dexFees, uint256 positionId, uint128 liquidity);
        event ExchangeFailed(bytes32 indexed ref, bytes reason);
        function settleOne(Settlement s, address submitter) external;
        function mtxCancelOrders(DexOrder[] orders, bytes[] sigs) external;
        function mtxInvalidateNonces(address from, uint256 batch, uint256 newMin, bytes sig) external;
        function dexOrderDigest(address sellToken, TradeOrder o) external view returns (bytes32);
        function cancelDexOrderDigest(address sellToken, TradeOrder o) external view returns (bytes32);
        function invalidateNoncesDigest(address from, uint256 batch, uint256 newMin) external view returns (bytes32);
        function pulled(bytes32 orderHash) external view returns (uint256);
        function minNonce(address from, uint256 batch) external view returns (uint256);
        function puller() external view returns (address);
        function marketListed(address a, address b) external view returns (bool);
        function tokenKind(address token) external view returns (uint8);
        /// CTR-DEX-32: the exchange path's known-token check on a closed DEX; its factory and `features()` (bit 29
        /// `CLOSED_MARKETS`), which the venue reads
        function tokenKnown(address token) external view returns (bool);
        function factory() external view returns (address);
        function features() external view returns (uint256);
        function chainUid() external view returns (bytes32);
        function SMART_KEY_ACCOUNT_IMPL() external view returns (address);
        event LegSettled(bytes32 indexed ref, bytes32 indexed orderHash, address indexed from, address destination,
            uint256 sold, uint256 received, uint256 dexFee, uint256 refund, uint256 relayerShare, uint256 treasuryShare);
        /// `LegSettled` of a shape-1 leg (CTR-DEX-26): `from` and `destination` are ids.
        event UALegSettled(bytes32 indexed ref, bytes32 indexed orderHash, bytes32 indexed from, bytes32 destination,
            uint256 sold, uint256 received, uint256 dexFee, uint256 refund, uint256 relayerShare, uint256 treasuryShare);
        event MatchFailed(bytes32 indexed ref, bytes reason);
        event TradeFilled(bytes32 indexed orderHash, address indexed from, uint256 sellFill, uint256 receiveFill,
            uint256 dexFee);
        event OrderCancelled(bytes32 indexed orderHash, address indexed from);
        event NoncesInvalidated(address indexed from, uint256 indexed batch, uint256 minNonce);
        error NothingSettled();
        error NoMakers();
        error WrongRelayer(address submitter);
        error DexMismatch(address dex);
        error TokenMismatch();
        error SelfTrade(bytes32 from);
        error LegShapeUnknown(uint8 shape);
        error UALegNotLedger(address token);
        error UAReceiveNotLedger(address token);
        error UAVerifyGas();
        error DuplicateOrder(bytes32 orderHash);
        error MarketNotListed(address tokenA, address tokenB);
        error BadSignature(bytes32 digest);
        error LengthMismatch();
        error FillMismatch(uint256 expected, uint256 got);
        error ConservationBroken(address token);
        error NotSelf();
        error InteractionFailed(uint256 index, address target, bytes reason);
        /// A token's T7 (`ITradeToken.NotLiquidityDex`), bubbled by `mtxLiquidity`: named, so a starved one is requeued
        /// (`guard::liquidity_starved`), never `dead` as raw hex.
        error NotLiquidityDex(address caller);
    }

    /// Every SCaaS contract on `MetaTxBase` (`IMetaTx`) plus the address surface: `SmartKeyAccount`'s (`IMetaTxAddress`: `mtxNonce`,
    /// `mtxDigest`, `mtxExecute`), the events and errors. ua-mtx-merge: the token's address forms here (`MetaTransfer`, `mtxPayMeta`
    /// on addresses) are no token entry any more; the gateway door, the mesh and the Hedera adapter still read them until T15, T16,
    /// T18 move them (`IMtxIds`). The order side is `ITradeToken`'s on ids (T17, R12, R38): `UATradeOrder`, `UASig`, `minNonce` by id.
    #[derive(Debug)]
    interface IToken {
        function mtxNonce(address from, uint256 batch) external view returns (uint256);
        /// The chain's own digests: a live oracle for the local ones (`tests/e2e.rs`); the node reads neither to run a job.
        function mtxDigest(MetaTransaction m) external view returns (bytes32);
        function mtxTransferDigest(MetaTransfer t) external view returns (bytes32);
        function mtxExecute(MetaTransaction m, bytes signature) external returns (bytes);
        function mtxExecuteTransfer(MetaTransfer t, bytes signature) external returns (bool);
        /// pay-meta-tax spec §3.2 (`IMetaTokenV2`, plan T83): emitted by every pay entry before the payment's events,
        /// `payNo` indexed; the v2 form (`string payNo`) is in `legacy/ua-mtx-merge/t83/abi.rs`, the old
        /// `PaymentMeta(bytes32, bytes)` and the address `mtxPayMeta` in `legacy/ua-mtx-merge/3e/abi.rs`.
        event PaymentMeta(bytes32 indexed payId, bytes32 indexed payNo, bool save, uint16 schema, bytes body);
        function mtxSelectors() external view returns (bytes4[] selectors, uint8[] feeClass, uint8[] amountArg);
        function chainUid() external view returns (bytes32);
        function supportedModes() external view returns (uint32);
        function balanceOf(address who) external view returns (uint256);
        function transfer(address to, uint256 value) external returns (bool);
        function mtxTrade(UATradeOrder o, UASig auth, TradeFill f) external;
        function mtxCancelOrder(UATradeOrder o, UASig auth) external;
        /// `ITradeToken`'s order events (R18): `from` is the id (a native address zero-padded).
        event UAOrderCancelled(bytes32 indexed orderHash, bytes32 indexed from);
        event UANoncesInvalidated(bytes32 indexed from, uint256 indexed batch, uint256 minNonce);
        function allowance(address owner, address spender) external view returns (uint256);
        function tradeOrderDigest(UATradeOrder o) external view returns (bytes32);
        function cancelOrderDigest(UATradeOrder o) external view returns (bytes32);
        function eip712Domain() external view returns (bytes1 fields, string name, string version, uint256 chainId,
            address verifyingContract, bytes32 salt, uint256[] extensions);
        function invalidateNoncesDigest(bytes32 from, uint256 batch, uint256 newMin) external view returns (bytes32);
        function pulled(bytes32 orderHash) external view returns (uint256);
        function minNonce(bytes32 from, uint256 batch) external view returns (uint256);
        event MetaTransactionExecuted(address indexed from, address indexed relayer, uint256 indexed batch,
            uint256 nonce, bytes32 digest, address feeRecipient, uint256 fee);
        event PaymentSettled(address indexed from, address indexed to, uint256 amount, uint256 feeAmount,
            address feeRecipient, bytes32 indexed entryRef);
        event Transfer(address indexed from, address indexed to, uint256 value);
        error MetaTxExpired(uint256 validUntil, uint256 nowTs);
        error MetaTxBadNonce(uint256 expected, uint256 got);
        error MetaTxBadSignature();
        error MetaTxUnauthorizedRelayer(address allowed, address caller);
        error MetaTxUnknownMode(uint32 mode);
        error MtxSelectorNotAllowed(bytes4 selector);
        error MtxDataShape(bytes4 selector);
        error MtxFeeClass(bytes4 selector, uint32 mode);
        error Reentrancy();
        error SelfSender();
        error MetaTxInsufficientForFee(uint256 needed, uint256 available);
        error PayToZero();
        error TransferToSelf();
        error FeeRecipientIsPayee();
        error ModeFeeInvalid(uint32 mode);
        error ModeUnknownBits(uint32 mode);
        error SigCheckGasStarved(uint256 cap, uint256 gasLeft);
        error NotDex(address caller);
        error DexNotContract(address dex);
        error SelfOrder(bytes32 orderHash);
        error WrongRelayer(bytes32 orderHash, address submitter);
        error OrderExpired(bytes32 orderHash);
        error NonceInvalidated(bytes32 orderHash);
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
        error MinNonceNotIncreasing(uint256 current, uint256 requested);
        error MinNonceAboveCap(uint256 requested);
        /// `IMetaTokenV2`'s `PayMeta` refusals (pay-meta-tax spec §3.2)
        error PayMetaShape();
        error PayMetaMismatch(bytes32 entryRef, bytes32 payId);
        /// plan T83: a saved pay of `amount >= 2^192` (`PayRecord.amount` is a `uint192`)
        error PayRecordAmount(uint256 amount);
    }

    /// `IUALedger` (CTR-UA-18/19/26): the UA ledger of every SCaaS token, off while `registry()` is 0 (a derived side then reverts
    /// `UALedgerOff`). Its signed entries are `IMtxIds`: they run for a native id at `registry() == 0` (ua-mtx-merge C, R9).
    #[derive(Debug)]
    interface IUALedger {
        function registry() external view returns (address);
        function transferToUA(bytes32 to, uint256 amount) external returns (bool);
        function balanceOfUA(bytes32 ua) external view returns (uint256);
        event UAMetaTransactionExecuted(bytes32 indexed from, address indexed relayer, uint256 indexed batch,
            uint256 nonce, bytes32 digest, address feeRecipient, uint256 fee);
        event UAPaymentSettled(bytes32 indexed from, bytes32 indexed to, uint256 amount, uint256 feeAmount,
            address feeRecipient, bytes32 indexed entryRef);
        event UANonceCancelled(bytes32 indexed ua, uint256 indexed batch, uint256 newNonce);
        error UALedgerOff();
        error UAPoolNotPayable();
        error UANotRegistered(bytes32 ua);
        error UAKindNotAccepted(bytes32 ua, uint16 kind);
        error UAInsufficientBalance(bytes32 ua, uint256 balance, uint256 needed);
        error MetaTxUnknownOp(bytes4 selector);
        /// `UAKinds` / `IUARegistry`: a starved verify, a refused signature.
        error UAVerifyGas();
        error UAUnauthorized(bytes32 ua);
    }

    /// The merged entries on ids (ua-mtx-merge, CTR-MTX-30) the node relays and reads on a token, the router and the mandate
    /// wallets (`UAMetaTxBase`, `IUALedgerViews`, `IERC20MetaTx`, `IMetaTokenV2`, `ITradeToken`): one form for a native id (an
    /// address zero-padded, its own key, no registry) and a derived UA; one nonce map. `SmartKeyAccount` keeps `IToken`'s
    /// address entries (`mtxNonce(address)`).
    #[derive(Debug)]
    interface IMtxIds {
        function mtxNonce(bytes32 from, uint256 batch) external view returns (uint256);
        function mtxDigest(UAMetaTransaction m) external view returns (bytes32);
        function mtxTransferDigest(UAMetaTransfer t) external view returns (bytes32);
        function mtxExecute(UAMetaTransaction m, UASig auth) external returns (bytes);
        function mtxExecuteTransfer(UAMetaTransfer t, UASig auth) external returns (bool);
        /// pay-meta-tax spec §2.1 (`IMetaTokenV2`): the payment `t`, its `PayMeta` last; `entryRef == metaPayId(meta)`.
        function mtxPay(UAMetaTransfer t, UASig auth, PayMeta meta) external returns (bool);
        /// pay-meta-tax spec §5.3 (kinds 8-13): the payer signs `UAPayWithTax{payment, taxMode, tax}`.
        function mtxPayWithTax(UAMetaTransfer t, uint8 taxMode, uint256 tax, UASig auth, PayMeta meta) external returns (bool);
        /// `ITradeToken.mtxInvalidateNonces` on ids (R12, R38); the DEX's keeps addresses and `bytes`.
        function mtxInvalidateNonces(bytes32 from, uint256 batch, uint256 newMin, UASig auth) external;
    }

    /// `RelayFeeRouter` (CTR-MTX-27, ua-mtx-merge T2 / R28): a token fee to the relayer for a fee-less call; `from` and `payee` ids
    /// (one `relay`, the old `uaRelay` under this name; the address `relay` is in `legacy/ua-mtx-merge/abi.rs`).
    #[derive(Debug)]
    interface IRelayFeeRouter {
        function relay(address target, bytes callData, address token, bytes32 from, bytes32 payee, uint256 value,
            uint256 batch, uint256 nonce, uint256 validUntil, UASig auth) external;
        function relayRef(address target, bytes callData) external view returns (bytes32);
        function EXECUTOR() external view returns (address);
        event RelayFeePaid(bytes32 indexed ref, address indexed target, address indexed token, bytes32 payer,
            bytes32 payee, uint256 amount);
        error RelayFeeShape();
        error RelayTargetNoCode(address target);
    }

    /// A service of the contract kind `service` (proposed NODE-JOB-25, spec 2026-11-09-service-pull §3.1, §8): each entry's
    /// selector, its `<Op>`'s EIP-712 `encodeType`, the token it pulls (0: `<Op>` names it in `address token`); its domain is
    /// ERC-5267 `eip712Domain()` (`IToken`'s).
    #[derive(Debug)]
    interface IServicePull {
        function servicePullEntries() external view returns (bytes4[] selectors, string[] opTypes, address[] tokens);
    }

    /// The OP-stack `GasPriceOracle` predeploy (`0x420…0F`): the L1 data fee of a transaction's bytes.
    #[derive(Debug)]
    interface IGasPriceOracle {
        function getL1Fee(bytes _data) external view returns (uint256);
    }

    /// `UARegistry`'s five writes (accounts.md §1.8, UA-8; CTR-UA-07: anyone may relay them): the call-table rows on
    /// `ua_registry`, and `register` / `registerMsig`'s `pqzPop` for the split rule ([`crate::guard::UA_REGISTER_SPLIT`]).
    /// typed-signing R1 (TS-D10 … TS-D12): the explicit ABI — `registerMsig` with a typed structure and `MemberSig[]`,
    /// `KemKey`, `UASig`; a hash-committed KEM key is filled by `setKemKey(ua, 0, kem, UASig())`. R1b (TS-D13):
    /// `registerWebAuthn` / `registerMuSig2` / `registerFrost` with typed keys (`register` takes the packed key data of those kinds too, same bytes and id; it refuses only `msig`).
    #[derive(Debug)]
    interface IUARegistry {
        struct KemKey { uint8 scheme; bytes mlkemEk; bytes32 x25519; }
        struct UAAttrs { bytes pqzKey; bytes32 pqzPopHash; KemKey kem; bytes32 kemPkHash; }
        struct MsigMember { uint16 kind; bytes32 id; uint16 weight; }
        struct MsigStructure { uint16 threshold; MsigMember[] members; }
        struct WebAuthnKey { bytes32 x; bytes32 y; bytes32 rpIdHash; }
        struct MuSig2Key { bytes aggKey; bytes[] memberKeys; }
        struct FrostMember { bytes[] commitments; bytes r; bytes32 z; }
        struct FrostKey { bytes groupKey; uint16 threshold; FrostMember[] members; }
        function register(uint16 kind, bytes keyData, UAAttrs attrs, bytes pop, bytes pqzPop) external returns (bytes32);
        function registerMsig(MsigStructure structure, UAAttrs attrs, MemberSig[] pop, bytes pqzPop) external returns (bytes32);
        function registerWebAuthn(WebAuthnKey key, UAAttrs attrs, bytes pop, bytes pqzPop) external returns (bytes32);
        function registerMuSig2(uint16 kind, MuSig2Key key, UAAttrs attrs, bytes pop, bytes pqzPop) external returns (bytes32);
        function registerFrost(uint16 kind, FrostKey key, UAAttrs attrs, bytes pop, bytes pqzPop) external returns (bytes32);
        function setKemKey(bytes32 ua, uint64 version, KemKey kem, UASig sig) external;
        // group 3g (KV-1): the record of a key version; version 0 the key registered later, v >= 1 a rotation
        function storePqzPop(bytes32 ua, uint64 version, bytes pqzPop) external;
        function setPqzKey(bytes32 ua, uint64 version, bytes pqzKey, bytes32 pqzPopHash, UASig sig) external;
        /// Group 3g (KV-3): the current version (the highest eligible), any version, the latest stored.
        function pqzKeyOf(bytes32 ua) external view returns (uint64 version, address ptr, bytes32 pqzPopHash, bool proven);
        function pqzKeyAt(bytes32 ua, uint64 version) external view returns (address ptr, bytes32 pqzPopHash, bool proven);
        function pqzKeyLatest(bytes32 ua) external view returns (uint64);
        event UAPqzPopStored(bytes32 indexed ua, uint64 indexed version, uint8 checkedPqzPop, bytes pqzPop);
        event UAPqzKeyAdded(bytes32 indexed ua, uint64 indexed version, bytes32 pqzKeyHash, bytes32 pqzPopHash, bytes pqzKey, bytes sig);
        event UAPqzKeyCurrent(bytes32 indexed ua, uint64 indexed version);
        function acceptMembership(bytes32 ua, MemberSig memberSig) external;
        /// A derived id's authorization under a purpose (CTR-UA-07): reverts `UAUnauthorized(ua)` when it is not one; the venue
        /// asks it for a derived seller's order, as the token's `authorize` does.
        function requireAuthorized(bytes32 ua, bytes32 purposeTag, bytes32 digest, UASig auth) external view;
    }

    /// A PQZ token's key-version surface (group 3g, spec 2026-11-06-pqz-key-versions §3, §7.3): the errors the node names
    /// (`PQZ_KEY_STALE`, `PQZ_KEY_VERSION_UNKNOWN`, `PQZ_KEY_REUSED`, `PQZ_KEY_ROTATED` over `ProofRejected`), the auditor a
    /// debit's copies go to, and the version events the indexer reads.
    #[derive(Debug)]
    interface IPqzToken {
        function auditorUA() external view returns (bytes32);
        event Credited(bytes32 indexed ua, uint64 indexed index, uint64 keyVersion, bytes32 entryRef);
        event Debited(bytes32 indexed ua, uint64 keyVersion, uint64 rolled, uint64 floor, address blob);
        event PqzRolledOver(bytes32 indexed ua, uint64 indexed keyVersion, uint64 rolled, uint32 accUnits, bytes32 accHash);
        error SelfTransfer();
        error ProofRejected();
        error KeyReused(bytes32 ua);
        error StaleKeyVersion(bytes32 ua, uint64 keyVersion, uint64 current);
        error KeyVersionUnknown(bytes32 ua, uint64 keyVersion);

        // ---- group 3f, PQZ verifier mode (spec 2026-11-06-attested-verify §4-§5): what the node rebuilds a `PqzVerdict` from,
        // the verifier's events, and its errors (named, [`pqz_verdict_refusal`])
        #[derive(PartialEq, Eq)]
        struct PqzVerdict { address token; uint256 chainId; bytes32 proofSystemId; bytes32 statementHash; bytes32 proofHash;
            uint32 pqzVerifierEpoch; uint64 validUntil; }
        #[derive(PartialEq, Eq)]
        struct PqzSignedVerdict { PqzVerdict pqzVerdict; UASig sig; }
        // round 3t (CTR-PQZ-36): + the verifier fee, its immutable cap, a live pending increase and its `eta`
        struct PqzVerifyConfig { uint8 pqzVerifyMode; bytes32 verifier; bool fixed_; uint32 pqzVerifierEpoch; bytes32 pending;
            uint64 eta; uint64 noticePeriod; uint64 verifierFee; uint64 verifierFeeMax; uint64 verifierFeePending; uint64 verifierFeeEta; }
        function pqzVerifyConfig() external view returns (PqzVerifyConfig memory);
        function proofSystemId() external view returns (bytes32);
        /// The relayed op's binding (`TAG_UA_ENVELOPE`, every envelope field but `data`): the `binding` of the statement views.
        function envelopeBinding(UAMetaTransaction m) external view returns (bytes32);
        event PqzVerified(bytes32 statementHash, bytes32 proofHash, bytes32 verifier, uint32 pqzVerifierEpoch);
        event PqzVerifierProposed(bytes32 current, bytes32 next, uint64 eta);
        event PqzVerifierSet(bytes32 previous, bytes32 next, uint32 pqzVerifierEpoch);
        event PqzVerifierCancelled(bytes32 next);
        // group 3h (pqz-proof-path spec §4, §5, §9.2): the mode the next debit runs under, its change, the logged P
        function proofStore() external view returns (uint8);
        event ProofStoreSet(uint8 previous, uint8 next);
        event PqzDebitProof(address indexed blob, bytes32 indexed ua, uint64 indexed sendCounter, bytes header, bytes proof);
        error PqzVerifyModeInvalid(uint8 mode);
        error PqzVerifyConfigInvalid();
        error PqzVerifierUnregistered(bytes32 ua);
        error PqzVerifierKind(uint16 kind);
        error PqzVerifierFixed();
        error PqzVerifierSame();
        error PqzVerifierChanged();
        error PqzVerifierRevoked();
        error PqzVerifierNotReady(uint64 eta);
        error PqzVerifierPending(bytes32 pending);
        error PqzVerdictRequired();
        error PqzVerdictRejected();
        error PqzVerdictMismatch(uint8 field);
        // ---- round 3t (CTR-PQZ-36, verifier fee spec §7, §10): the admin's setter, its events and refusals
        function setVerifierFee(uint64 next) external;
        function confidentialFee() external view returns (uint256);
        event VerifierFeeProposed(uint64 current, uint64 next, uint64 eta);
        event VerifierFeeSet(uint64 previous, uint64 next);
        error VerifierFeeAboveMax(uint64 fee, uint64 max);
        error VerifierFeePending(uint64 pending);
        error VerifierFeeSame();
        error VerifierFeeNotReady(uint64 eta);
        /// `PqzAuth` refused (the holder's signature over the 20 header words): after a fee change, the fee word moved
        error AuthRejected();
    }

    /// `IPqzToken.sol`'s file-level event (the error of the same name is `IPqzToken`'s) and the confidential op events
    /// (`IConfidentialToken`) a `PqzVerified` joins (group 3f, spec §11.1).
    #[derive(Debug)]
    interface IPqzEvents {
        event PqzVerifierRevoked(bytes32 previous, uint32 pqzVerifierEpoch);
        event ConfidentialTransfer(bytes32 indexed entryRef, bytes32 indexed fromUA, bytes32 indexed toUA, bytes32 beneficiary,
            uint256 fee, uint64 sendCounter, address blob);
        event ConfidentialTransferMulti(bytes32 indexed entryRef, bytes32 indexed fromUA, bytes32 indexed beneficiary, uint256 fee,
            uint64 sendCounter, bytes32[] recipients, uint8 mode, address blob);
        event Unshielded(bytes32 indexed ua, uint256 amount, bytes32 indexed recipient, address blob);
    }

    /// `MandateWallet` errors (CTR-ACC-06/07, CTR-ACC-12 in the merged form: ids): a job's revert reason names them, so the
    /// client re-reads `epoch(token)` and re-signs on `StaleEpoch`.
    #[derive(Debug)]
    interface IMandateWallet {
        error NotOwner();
        error NotDelegate();
        error NoMandate();
        error MandateExpired();
        error PayeeNotAllowed(bytes32 payee);
        error OverPaymentCap(uint256 amount, uint256 cap);
        error OverPeriodCap(uint256 wouldSpend, uint256 cap);
        error RefAlreadyPaid(bytes32 entryRef);
        error StaleEpoch(uint64 current, uint64 signed);
        error CallFailed(bytes reason);
        error ZeroOwner();
        error BadMandate();
        error PayFailed();
    }

    /// `IRegulatedToken` (regulated-kinds spec §3.1; kinds 8-13): the controls, the views the venue's pre-check reads
    /// (NODE-DEX-11), the events the indexer and the venue watch, and the errors the node names. Every function of the
    /// interface is here: [`regulated_interface_id`] is their XOR, as `type(IRegulatedToken).interfaceId`.
    #[derive(Debug)]
    interface IRegulatedToken {
        struct RegulatedConfig { address complianceRegistry; uint8 controls; uint64 requiredFlags; uint64 deniedFlags;
            bytes32 termsHash; uint64 pausedUntil; uint64 pauseCooldownUntil; }
        struct FreezeState { uint64 until; uint64 episodeStart; uint64 issuerCooldownUntil; bool recordBacked; bytes32 recordId; }
        struct OrderRecord { bytes32 subject; bytes32 beneficiary; uint64 freezeUntil; bool revoked; uint256 maxAmount; uint256 executed; }
        /// pay-meta-tax spec §6.2: `taxConfig()`, what the node reads to check a PERCENT tax before simulating.
        struct TaxConfig { bytes32 taxRecipient; bool enabled; uint32 ratePpm; uint32 pendingPpm; uint64 eta; uint32 effectivePpm;
            uint64 noticePeriod; }
        event AccountFrozen(bytes32 indexed account, bytes32 indexed ref, bytes32 recordId, uint64 until);
        event AccountUnfrozen(bytes32 indexed account, bytes32 indexed ref);
        event ForcedTransfer(bytes32 indexed recordId, bytes32 indexed from, bytes32 indexed to, uint256 amount);
        event Paused(bytes32 indexed ref, uint64 until);
        event Unpaused(bytes32 indexed ref);
        event OrderRecorded(bytes32 indexed recordId, bytes32 indexed orderId, bytes32 indexed subject, bytes32 beneficiary,
            uint256 maxAmount, uint64 freezeUntil, bytes32 documentHash);
        event OrderRevoked(bytes32 indexed recordId, bytes32 reasonRef);
        event OperatorTransfer(bytes32 indexed from, bytes32 indexed to, uint256 amount, bytes32 indexed ref);
        event TaxRateSet(uint32 ratePpm, uint64 effectiveAt);
        event TaxRecipientSet(bytes32 indexed taxRecipient);
        event PaymentTaxed(bytes32 indexed entryRef, bytes32 indexed payee, bytes32 indexed taxRecipient, bytes32 from,
            uint8 taxMode, uint256 tax, bytes32 digest);
        /// Round 3s (spec 2026-11-10-token-lists.md §6.1, CTR-GOV-24): one event per account of a list edit.
        event AllowedSet(bytes32 indexed account, bytes32 indexed by, bool on);
        event DeniedSet(bytes32 indexed account, bytes32 indexed by, bool on);
        error Frozen(bytes32 account);
        error NotAllowed(bytes32 account);
        error Denied(bytes32 account);
        error ListBatchInvalid(uint256 length);
        error ListAccountZero();
        error ComplianceRegistryNotSet();
        error ListHolderMissing(uint8 bit);
        error TokenPaused(uint64 until);
        error NotEligible(bytes32 account, uint8 reason);
        error FeeRecipientFrozen(bytes32 account);
        error RefRequired();
        error RegulatedConfigInvalid();
        error ComplianceRegistryCodeMismatch(address complianceRegistry, bytes32 codehash);
        error ComplianceRegistryRouterMismatch(address complianceRegistry, address got);
        error ComplianceRegistryUnavailable(address complianceRegistry);
        error ComplianceRegistryGasStarved(uint256 cap, uint256 left);
        error OrderExists(bytes32 recordId);
        error OrderUnknown(bytes32 recordId);
        error OrderInactive(bytes32 recordId);
        error SubjectNotFrozen(bytes32 subject);
        error OrderExceeded(uint256 remaining);
        error FreezeTooLong(uint64 maxUntil);
        error FreezeCooldown(uint64 until);
        error NotFrozen(bytes32 account);
        error AlreadyRecordFrozen(bytes32 account);
        error RecordFreezeShorter(uint64 until);
        error FreezeTargetRefused(bytes32 account);
        error PauseTooLong(uint64 until);
        error PauseCooldown(uint64 until);
        error ForceTargetRefused(bytes32 account);
        error OperatorTargetRefused(bytes32 account);
        error AmountZero();
        error NotPaused();
        error TaxRateInvalid(uint32 ratePpm);
        error TaxRecipientInvalid(bytes32 taxRecipient);
        error TaxModeInvalid(uint8 taxMode);
        error TaxExceedsAmount(uint256 tax, uint256 amount);
        error TaxMismatch(uint256 expected, uint256 got);
        error TaxRecipientIsPayee();
        function freeze(bytes32 account, bytes32 ref, bytes32 recordId) external;
        function unfreeze(bytes32 account, bytes32 ref) external;
        function forceTransfer(bytes32 recordId, uint256 amount) external;
        function pause(bytes32 ref, uint64 until) external;
        function unpause(bytes32 ref) external;
        function recordOrder(bytes32 orderId, bytes32 documentHash, bytes32 subject, bytes32 beneficiary, uint256 maxAmount,
            uint64 freezeUntil) external;
        function revokeOrder(bytes32 recordId, bytes32 reasonRef) external;
        function operatorTransfer(bytes32 from, bytes32 to, uint256 amount, bytes32 ref) external;
        function setTaxRate(uint32 ratePpm) external;
        function setTaxRecipient(bytes32 taxRecipient) external;
        function taxConfig() external view returns (TaxConfig);
        function mtxPayWithTax(UAMetaTransfer t, uint8 taxMode, uint256 tax, UASig auth, PayMeta meta) external returns (bool);
        function payWithTax(bytes32 to, uint256 amount, uint8 taxMode, uint256 tax, bytes32 entryRef, PayMeta meta)
            external returns (bool);
        function setAllowed(bytes32[] accounts, bool on) external;
        function setDenied(bytes32[] accounts, bool on) external;
        function listFlagsOf(bytes32 account) external view returns (uint8);
        function enableFeature(uint8 bit) external;
        function regulatedConfig() external view returns (RegulatedConfig);
        function freezeOf(bytes32 account) external view returns (FreezeState);
        function isFrozen(bytes32 account) external view returns (bool);
        function canReceive(bytes32 account) external view returns (bool ok, uint8 reason);
        function order(bytes32 recordId) external view returns (OrderRecord);
    }

    /// A body module's group (T66b §4.5): the liquidity mark of a DEX is a module of group 11 (CTR-DEX-30, spec §11).
    #[derive(Debug)]
    interface IModuleGroup {
        function moduleGroup() external view returns (uint8);
    }

    /// The registry's kind of a derived id (the verify budget of a liquidity plan).
    #[derive(Debug)]
    interface IUAKindOf {
        function kindOf(bytes32 ua) external view returns (uint16);
    }

    /// Group 3l (wrap limits spec 2026-11-10 §7, §9): the wrapped kinds' named refusals of a wrap or an unwrap under the
    /// limits, which a later block may lift (a window ends, a member is added, a redeemer is granted, a later wrap raises the
    /// entitlement): [`wrap_limit_refusal`].
    #[derive(Debug)]
    interface IWrapLimits {
        error WrapLimitExceeded(address underlying, uint8 limit, bytes32 account, uint256 amount, uint256 remaining);
        error WrapCapExceeded(address underlying, uint8 limit, uint256 amount, uint256 remaining);
        error UnwrapAboveNetWrapped(address underlying, bytes32 account, uint256 amount, uint256 entitlement);
        error WrapperNotListed(bytes32 account);
        error UnwrapperNotListed(bytes32 account);
        error WrapControlNeedsHybrid(uint8 bit);
        error WrapSubjectZero();
    }

    /// ERC-165 (`MetaTokenBase.supportsInterface`): a regulated kind answers [`regulated_interface_id`], kinds 0-5 do not (M-10).
    #[derive(Debug)]
    interface IERC165 {
        function supportsInterface(bytes4 id) external view returns (bool);
    }

    /// `IComplianceRegistry` (regulated-kinds spec §5; round 3r, spec 2026-11-10-admin-not-owner §5.3.1: the KYC provider): the
    /// two reads `canReceive` makes, read by the venue to compute `R` with `scaas_ua::regulated::can_receive` and to know the
    /// receiver's compliance row `validUntil` (NODE-DEX-11, `ATTESTATION_SHORTER`); its events and errors, decoded by name.
    #[derive(Debug)]
    interface IComplianceRegistry {
        event KycProviderSet(bytes32 indexed provider, uint32 indexed providerId, bool enabled);
        event ComplianceSet(bytes32 indexed account, uint64 flags, uint64 validUntil, uint32 indexed providerId);
        function complianceOf(bytes32 account) external view returns (uint64 flags, uint64 validUntil, uint32 providerId);
        function kycProviderEnabled(uint32 id) external view returns (bool);
        error AdminZero();
        error AdminUnreachable(bytes32 admin);
        error RouterNotContract(address govRouter);
        error NotKycProvider();
        error KycProviderZero();
        error TooManyRows(uint256 n);
        error LengthMismatch();
        error EligibleContractAdminOnly();
        error AdminWrittenSlot(bytes32 account);
    }

    /// `IOpenFactory.infoOf` (factory index spec §8.6): the record of a contract the chain's factory made, read for the generic
    /// factory-class rule (`guard::Rule::FactoryClass`; `PqChat` is class 3, topics spec P45); no owner since round 3r R1.
    #[derive(Debug)]
    interface IOpenFactory {
        struct Created {
            address addr; bytes32 creatorId; uint16 contractClass; uint16 kind; uint64 version;
            uint64 createdBlock; uint64 createdAt;
        }
        function infoOf(address c) external view returns (Created memory);
        /// CTR-DEX-18 / CTR-DEX-32: a token is SCaaS iff the factory made it from a registered release (`version != 0`).
        function versionOf(address token) external view returns (uint8 kind, uint64 version);
        /// Owner 2026-11-12: a generic release (`mtxCreateInstance` is checked against it before the simulation).
        struct ReleaseId { uint16 contractClass; uint16 kind; uint64 version; }
        struct ClassRelease {
            address implementation; uint16 envVersion; bytes32 envHash; uint64 usableFrom; bool deprecated; bytes4 initSelector;
            bytes4 interfaceId;
        }
        function classReleaseOf(ReleaseId calldata id) external view returns (ClassRelease memory);
    }

    /// `IGovernance`'s events the indexer reads (M-08) and the errors of a role or a pending the node names (§3.1).
    #[derive(Debug)]
    interface IGovernance {
        event RoleRevoked(uint8 indexed bit, bytes32 indexed account, bytes32 indexed sender);
        event FeatureDisabled(uint8 indexed bit, bytes32 indexed by);
        event FeatureEnabled(uint8 indexed bit, bytes32 indexed by);
        event RelaxProposed(uint8 indexed bit, bytes32 indexed account, uint8 action, bytes32 proposer, uint64 eta);
        error MissingRole(uint8 bit, bytes32 account);
        error RoleNotContract(uint8 bit, bytes32 account);
        error RoleConflict(uint8 bit, bytes32 account);
        error GrantTermsMismatch(uint8 bit, bytes32 account);
        error GrantNotReady(uint8 bit, bytes32 account, uint64 eta);
        error NotProposer(uint8 bit, bytes32 account, bytes32 proposer);
        error FeatureInvalidForKind(uint8 bit);
        error FeatureLocked(uint8 bit);
        error FeatureNotSet(uint8 bit);
        error FeatureNotEnableable(uint8 bit);
        error FeatureNotDisableable(uint8 bit);
        error FeatureAlreadySet(uint8 bit);
        error GrantExhausted(uint8 field);
        error GrantExpired(uint8 bit, bytes32 holder);
        error GrantBarred(uint8 bit, bytes32 account);
    }
}

/// `type(IRegulatedToken).interfaceId`: the XOR of its functions' selectors.
pub fn regulated_interface_id() -> [u8; 4] {
    use alloy::sol_types::SolInterface;
    IRegulatedToken::IRegulatedTokenCalls::selectors().fold([0u8; 4], |a, s| std::array::from_fn(|i| a[i] ^ s[i]))
}

/// A regulated token's refusal that a later block may lift (regulated-kinds spec §7): the account is frozen, the token
/// paused, the receiver not eligible, the fee recipient frozen, the registry unreadable, or (round 3s) a party off the allow
/// list or on the deny list, which a list edit lifts. The node names it and never
/// reports the job `dead` for it while its payload may still land (another relayer, after an unfreeze, an unpause or an
/// attestation); it is never counted against the subject's or a maker's grief score (asset-suite §2.7, F-16). `reason`
/// is a `decode_revert` string.
pub fn regulated_refusal(reason: &str) -> Option<&'static str> {
    const LIFTABLE: [&str; 8] = ["Frozen", "TokenPaused", "NotEligible", "FeeRecipientFrozen", "ComplianceRegistryUnavailable",
        "ComplianceRegistryGasStarved", "NotAllowed", "Denied"];
    let name = reason.split(['(', ' ', '{']).next().unwrap_or_default();
    LIFTABLE.into_iter().find(|n| *n == name)
}

/// Round 3s (spec 2026-11-10-token-lists.md §9, Fable P3-8): a list refusal of the job's own subject (`Denied(subject)`,
/// `NotAllowed(subject)`, the token's answer at simulation, so a dormant list refuses nothing): refused by name (`DENIED`,
/// `NOT_ALLOWED`), zero sends, never back in the queue with no grief score; another party's list refusal stays liftable
/// ([`regulated_refusal`]).
pub fn own_list_refusal(reason: &str, subject: alloy::primitives::B256) -> Option<&'static str> {
    let (name, rest) = reason.split_once('(')?;
    let code = match name {
        "Denied" => "DENIED",
        "NotAllowed" => "NOT_ALLOWED",
        _ => return None,
    };
    // `decode_revert`'s form: `Denied(Denied { account: 0x… })`
    let i = rest.find("0x")?;
    let a: alloy::primitives::B256 = rest.get(i..i + 66)?.parse().ok()?;
    (a == subject).then_some(code)
}

/// Group 3l (wrap limits spec §9, NODE-LANE-09's class): a wrap or an unwrap a wrap limit refuses at simulation. A window ends,
/// a member is added, a redeemer is granted or a later wrap raises the entitlement, so the payload may still land: the job stays
/// `queued` with `WRAP_LIMIT_REFUSED: <named error>`, never `dead` (expiry or the attempt cap ends it), and no grief score.
/// `WrapControlNeedsHybrid` (a creation refusal, permanent) is not in the class. `reason` is a `decode_revert` string.
pub fn wrap_limit_refusal(reason: &str) -> Option<&'static str> {
    const LIFTABLE: [&str; 5] = ["WrapLimitExceeded", "WrapCapExceeded", "UnwrapAboveNetWrapped", "WrapperNotListed", "UnwrapperNotListed"];
    let name = reason.split(['(', ' ', '{']).next().unwrap_or_default();
    LIFTABLE.into_iter().find(|n| *n == name)
}

/// What a PQZ token's key-version refusal means for a job (group 3g, spec §7.3), from a `decode_revert` string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PqzRefusal {
    /// `StaleKeyVersion`: a stale version pays no one else; `current` never goes down, so it never lands: `PQZ_KEY_STALE`.
    Stale,
    /// `KeyVersionUnknown`: a version above current, which may become current (its proof stored): `PQZ_KEY_VERSION_UNKNOWN`,
    /// back in the queue.
    Unknown,
    /// `KeyReused`: two equal keys in one statement, never valid: `PQZ_KEY_REUSED`.
    Reused,
    /// `ProofRejected`: a proof built for a party's key before its rotation is `PQZ_KEY_ROTATED` only after an indexed
    /// `UAPqzKeyCurrent` of that party since intake ([`crate::submit`]); otherwise the plain revert.
    ProofRejected,
}

/// `pqzVerifyMode` 1 (spec §3): proofs accepted on the verifier UA's `PqzVerdict`; 0 `PRECOMPILE`.
pub const PQZ_OFFCHAIN: u8 = 1;
/// Group 3h (pqz-proof-path spec §4): `proofStore()` `LOG`, each debit's proof as a `PqzDebitProof` event (0 `NONE`: calldata only).
pub const PROOF_STORE_LOG: u8 = 1;

/// Group 3f (spec §11.1): a PQZ verifier mode refusal by name, and whether the op may still land (`true`: another verdict, the
/// verifier's next epoch, an `eta` reached, a registration: back in the queue, never `dead`) or never (`false`: the op's own
/// shape, a fixed verifier, the wrong mode). `reason` is a `decode_revert` string.
pub fn pqz_verdict_refusal(reason: &str) -> Option<(&'static str, bool)> {
    // round 3t (CTR-PQZ-36): the fee setter's `VerifierFeeNotReady` / `VerifierFeePending` liftable, `VerifierFeeAboveMax` /
    // `VerifierFeeSame` final
    const LIFTABLE: [&str; 9] = ["PqzVerdictMismatch", "PqzVerdictRejected", "PqzVerifierRevoked", "PqzVerifierChanged",
        "PqzVerifierNotReady", "PqzVerifierPending", "PqzVerifierUnregistered", "VerifierFeeNotReady", "VerifierFeePending"];
    const FINAL: [&str; 8] = ["PqzVerifierFixed", "PqzVerifierSame", "PqzVerifierKind", "PqzVerdictRequired", "PqzVerifyModeInvalid",
        "PqzVerifyConfigInvalid", "VerifierFeeAboveMax", "VerifierFeeSame"];
    let name = reason.split(['(', ' ', '{']).next().unwrap_or_default();
    LIFTABLE.into_iter().find(|n| *n == name).map(|n| (n, true)).or_else(|| FINAL.into_iter().find(|n| *n == name).map(|n| (n, false)))
}

pub fn pqz_refusal(reason: &str) -> Option<PqzRefusal> {
    Some(match reason.split(['(', ' ', '{']).next().unwrap_or_default() {
        "StaleKeyVersion" => PqzRefusal::Stale,
        "KeyVersionUnknown" => PqzRefusal::Unknown,
        "KeyReused" => PqzRefusal::Reused,
        "ProofRejected" => PqzRefusal::ProofRejected,
        _ => return None,
    })
}

/// Readable error name for `last_error` on the client; raw hex when it is none of ours.
pub fn decode_revert(data: &[u8]) -> String {
    if let Ok(e) = IToken::ITokenErrors::abi_decode(data) {
        return format!("{e:?}");
    }
    if let Ok(e) = ISCaaSDex::ISCaaSDexErrors::abi_decode(data) {
        return format!("{e:?}");
    }
    if let Ok(e) = IMandateWallet::IMandateWalletErrors::abi_decode(data) {
        return format!("{e:?}");
    }
    if let Ok(e) = IRelayFeeRouter::IRelayFeeRouterErrors::abi_decode(data) {
        return format!("{e:?}");
    }
    if let Ok(e) = IUALedger::IUALedgerErrors::abi_decode(data) {
        return format!("{e:?}");
    }
    if let Ok(e) = IRegulatedToken::IRegulatedTokenErrors::abi_decode(data) {
        return format!("{e:?}");
    }
    if let Ok(e) = IWrapLimits::IWrapLimitsErrors::abi_decode(data) {
        return format!("{e:?}");
    }
    if let Ok(e) = IGovernance::IGovernanceErrors::abi_decode(data) {
        return format!("{e:?}");
    }
    if let Ok(e) = IComplianceRegistry::IComplianceRegistryErrors::abi_decode(data) {
        return format!("{e:?}");
    }
    if let Ok(e) = IPqzToken::IPqzTokenErrors::abi_decode(data) {
        return format!("{e:?}");
    }
    format!("revert 0x{}", alloy::hex::encode(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::U256;
    use alloy::sol_types::SolError;

    #[test]
    fn known_errors_are_named() {
        let e = IToken::MetaTxBadNonce { expected: U256::from(1), got: U256::ZERO }.abi_encode();
        assert!(decode_revert(&e).contains("MetaTxBadNonce"));
        let e = IMandateWallet::StaleEpoch { current: 2, signed: 1 }.abi_encode();
        assert!(decode_revert(&e).starts_with("StaleEpoch"), "{}", decode_revert(&e));
        let e = IToken::MinNonceNotIncreasing { current: U256::from(5), requested: U256::from(5) }.abi_encode();
        assert!(decode_revert(&e).starts_with("MinNonceNotIncreasing("));
        assert!(decode_revert(&[1, 2, 3]).starts_with("revert 0x"));
        // pay-meta-tax T42 (`tax_mismatch_after_rate_change_refused_by_name`): the pay and tax refusals are named
        let e = IRegulatedToken::TaxMismatch { expected: U256::from(50), got: U256::from(100) }.abi_encode();
        assert!(decode_revert(&e).starts_with("TaxMismatch"), "{}", decode_revert(&e));
        let e = IToken::PayMetaMismatch { entryRef: alloy::primitives::B256::ZERO, payId: alloy::primitives::B256::ZERO }.abi_encode();
        assert!(decode_revert(&e).starts_with("PayMetaMismatch"), "{}", decode_revert(&e));
        let e = IToken::PayRecordAmount { amount: U256::from(1) << 192 }.abi_encode();
        assert!(decode_revert(&e).starts_with("PayRecordAmount"), "{}", decode_revert(&e));
        assert!(decode_revert(&IRegulatedToken::TaxRecipientIsPayee {}.abi_encode()).starts_with("TaxRecipientIsPayee"));
    }

    /// `type(IRegulatedToken).interfaceId`: the XOR of its eighteen selectors (pay-meta-tax T39 / T40: + setTaxRate,
    /// setTaxRecipient, taxConfig, mtxPayWithTax, payWithTax; 0xf35dd87a -> 0xaf5683ea, the forge artifact's methodIdentifiers;
    /// plan T83, `PayMeta` v3 in the two tax entries' tuples: 0xaf5683ea -> 0x01a22b62; round 3s, spec 2026-11-10-token-lists.md
    /// §7, + setAllowed, setDenied, listFlagsOf, enableFeature: 0x01a22b62 -> 0x789ed7c4).
    #[test]
    fn own_list_refusal_names_the_subject_only() {
        let (s, o) = (alloy::primitives::B256::repeat_byte(0xa1), alloy::primitives::B256::repeat_byte(0xb2));
        let r = decode_revert(&IRegulatedToken::Denied { account: s }.abi_encode());
        assert_eq!(own_list_refusal(&r, s), Some("DENIED"), "{r}");
        assert_eq!(own_list_refusal(&r, o), None, "another party's: liftable");
        assert_eq!(regulated_refusal(&r), Some("Denied"));
        let r = decode_revert(&IRegulatedToken::NotAllowed { account: s }.abi_encode());
        assert_eq!(own_list_refusal(&r, s), Some("NOT_ALLOWED"), "{r}");
        assert_eq!(regulated_refusal(&r), Some("NotAllowed"));
        assert_eq!(own_list_refusal(&decode_revert(&IRegulatedToken::Frozen { account: s }.abi_encode()), s), None);
    }

    #[test]
    fn regulated_interface_id_is_the_xor_of_its_functions() {
        assert_eq!(regulated_interface_id(), [0x78, 0x9e, 0xd7, 0xc4]);
    }

    /// Group 3g (spec §7.3): the PQZ key-version reverts decode by name and classify; another revert is none of them.
    #[test]
    fn pqz_key_refusals_are_named() {
        let a = alloy::primitives::B256::repeat_byte(0xa1);
        for (data, name, want) in [
            (IPqzToken::StaleKeyVersion { ua: a, keyVersion: 1, current: 2 }.abi_encode(), "StaleKeyVersion", PqzRefusal::Stale),
            (IPqzToken::KeyVersionUnknown { ua: a, keyVersion: 3 }.abi_encode(), "KeyVersionUnknown", PqzRefusal::Unknown),
            (IPqzToken::KeyReused { ua: a }.abi_encode(), "KeyReused", PqzRefusal::Reused),
            (IPqzToken::ProofRejected {}.abi_encode(), "ProofRejected", PqzRefusal::ProofRejected),
        ] {
            let r = decode_revert(&data);
            assert!(r.starts_with(name), "{r}");
            assert_eq!(pqz_refusal(&r), Some(want), "{r}");
        }
        assert_eq!(pqz_refusal(&decode_revert(&IPqzToken::SelfTransfer {}.abi_encode())), None);
        assert_eq!(pqz_refusal("KeyReusedX(..)"), None);
    }

    /// Group 3f (spec §11.1): the thirteen PQZ verifier mode errors decode by name; the seven a later verdict, epoch, `eta` or
    /// registration may lift are back in the queue (never `dead`), the six of the op's own shape are not.
    #[test]
    fn pqz_verdict_refusals_are_named() {
        let a = alloy::primitives::B256::repeat_byte(0xa1);
        for (data, name, liftable) in [
            (IPqzToken::PqzVerdictMismatch { field: 5 }.abi_encode(), "PqzVerdictMismatch", true),
            (IPqzToken::PqzVerdictRejected {}.abi_encode(), "PqzVerdictRejected", true),
            (IPqzToken::PqzVerifierRevoked {}.abi_encode(), "PqzVerifierRevoked", true),
            (IPqzToken::PqzVerifierChanged {}.abi_encode(), "PqzVerifierChanged", true),
            (IPqzToken::PqzVerifierNotReady { eta: 9 }.abi_encode(), "PqzVerifierNotReady", true),
            (IPqzToken::PqzVerifierPending { pending: a }.abi_encode(), "PqzVerifierPending", true),
            (IPqzToken::PqzVerifierUnregistered { ua: a }.abi_encode(), "PqzVerifierUnregistered", true),
            (IPqzToken::PqzVerifierFixed {}.abi_encode(), "PqzVerifierFixed", false),
            (IPqzToken::PqzVerifierSame {}.abi_encode(), "PqzVerifierSame", false),
            (IPqzToken::PqzVerifierKind { kind: 0x0132 }.abi_encode(), "PqzVerifierKind", false),
            (IPqzToken::PqzVerdictRequired {}.abi_encode(), "PqzVerdictRequired", false),
            (IPqzToken::PqzVerifyModeInvalid { mode: 2 }.abi_encode(), "PqzVerifyModeInvalid", false),
            (IPqzToken::PqzVerifyConfigInvalid {}.abi_encode(), "PqzVerifyConfigInvalid", false),
        ] {
            let r = decode_revert(&data);
            assert!(r.starts_with(name), "{r}");
            assert_eq!(pqz_verdict_refusal(&r), Some((name, liftable)), "{r}");
        }
        assert_eq!(pqz_verdict_refusal(&decode_revert(&IPqzToken::ProofRejected {}.abi_encode())), None);
        assert_eq!(pqz_verdict_refusal("PqzVerdictMismatchX(..)"), None);
    }

    /// Group 3l (wrap limits spec §9): the five liftable wrap-limit refusals decode by name and are the class; the creation
    /// refusal and the subject check are named but not in it.
    #[test]
    fn wrap_limit_refusals_are_named() {
        let a = alloy::primitives::B256::repeat_byte(0xf1);
        let u = alloy::primitives::Address::repeat_byte(5);
        for (data, name) in [
            (IWrapLimits::WrapLimitExceeded { underlying: u, limit: 2, account: a, amount: U256::from(7), remaining: U256::ZERO }.abi_encode(), "WrapLimitExceeded"),
            (IWrapLimits::WrapCapExceeded { underlying: u, limit: 0, amount: U256::from(7), remaining: U256::ZERO }.abi_encode(), "WrapCapExceeded"),
            (IWrapLimits::UnwrapAboveNetWrapped { underlying: u, account: a, amount: U256::from(7), entitlement: U256::from(1) }.abi_encode(), "UnwrapAboveNetWrapped"),
            (IWrapLimits::WrapperNotListed { account: a }.abi_encode(), "WrapperNotListed"),
            (IWrapLimits::UnwrapperNotListed { account: a }.abi_encode(), "UnwrapperNotListed"),
        ] {
            let r = decode_revert(&data);
            assert!(r.starts_with(&format!("{name}(")), "{r}");
            assert_eq!(wrap_limit_refusal(&r), Some(name), "{r}");
            assert_eq!(regulated_refusal(&r), None, "{r}: not a regulated refusal");
        }
        for (data, name) in [
            (IWrapLimits::WrapControlNeedsHybrid { bit: 25 }.abi_encode(), "WrapControlNeedsHybrid"),
            (IWrapLimits::WrapSubjectZero {}.abi_encode(), "WrapSubjectZero"),
        ] {
            let r = decode_revert(&data);
            assert!(r.starts_with(name), "{r}");
            assert_eq!(wrap_limit_refusal(&r), None, "{name}: named, not liftable");
        }
        assert_eq!(wrap_limit_refusal("WrapLimitExceededX(..)"), None);
    }

    /// Regulated-kinds spec §7: every §3.1 error and `NotProposer` decoded by name; the six a later block may lift are the
    /// refusals the submit path and the venue keep apart from `dead` and from blame; the others are not.
    #[test]
    fn regulated_refusals_are_named() {
        let a = alloy::primitives::B256::repeat_byte(0xf1);
        for (data, name) in [
            (IRegulatedToken::Frozen { account: a }.abi_encode(), "Frozen"),
            (IRegulatedToken::TokenPaused { until: 7 }.abi_encode(), "TokenPaused"),
            (IRegulatedToken::NotEligible { account: a, reason: 1 }.abi_encode(), "NotEligible"),
            (IRegulatedToken::FeeRecipientFrozen { account: a }.abi_encode(), "FeeRecipientFrozen"),
            (IRegulatedToken::ComplianceRegistryUnavailable { complianceRegistry: alloy::primitives::Address::repeat_byte(5) }.abi_encode(),
                "ComplianceRegistryUnavailable"),
            (IRegulatedToken::ComplianceRegistryGasStarved { cap: U256::from(50_000), left: U256::from(1) }.abi_encode(),
                "ComplianceRegistryGasStarved"),
        ] {
            let r = decode_revert(&data);
            assert!(r.starts_with(&format!("{name}(")), "{r}");
            assert_eq!(regulated_refusal(&r), Some(name), "{r}");
        }
        for (data, name) in [
            (IGovernance::NotProposer { bit: 5, account: a, proposer: a }.abi_encode(), "NotProposer"),
            (IGovernance::MissingRole { bit: 5, account: a }.abi_encode(), "MissingRole"),
            (IRegulatedToken::RefRequired {}.abi_encode(), "RefRequired"),
            (IRegulatedToken::PauseCooldown { until: 1 }.abi_encode(), "PauseCooldown"),
            (IComplianceRegistry::AdminWrittenSlot { account: a }.abi_encode(), "AdminWrittenSlot"),
            (IComplianceRegistry::NotKycProvider {}.abi_encode(), "NotKycProvider"),
            (IRegulatedToken::ComplianceRegistryRouterMismatch { complianceRegistry: alloy::primitives::Address::repeat_byte(5),
                got: alloy::primitives::Address::repeat_byte(6) }.abi_encode(), "ComplianceRegistryRouterMismatch"),
        ] {
            let r = decode_revert(&data);
            assert!(r.starts_with(&format!("{name}(")), "{r}");
            assert_eq!(regulated_refusal(&r), None, "{name}: named, not liftable");
        }
        assert_eq!(regulated_refusal("FrozenX(..)"), None);
        assert_eq!(regulated_refusal(&decode_revert(&IWrapLimits::WrapperNotListed { account: a }.abi_encode())), None,
            "a wrap limit is its own class");
        assert_eq!(regulated_refusal("revert 0x1234"), None);
    }

    /// The node's reader of `smartcontracts/vectors/governance/regulated_kat.json` (regulated-kinds spec §7; forge writes it
    /// from a real kind-8 token): every refused transition's `error.data`, the contract's own bytes, decodes to the error its
    /// `sig` names; the `R` rows are what `scaas_ua::regulated::can_receive` answers (the venue's pre-check, NODE-DEX-11); the
    /// `recordId` rows are `record_id`'s.
    #[test]
    fn regulated_kat_rows_read_by_the_node() {
        use scaas_ua::regulated::{can_receive, record_id, Attestation};
        let p = format!("{}/../smartcontracts/vectors/governance/regulated_kat.json", env!("CARGO_MANIFEST_DIR"));
        let v: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        let w = |s: &serde_json::Value| -> [u8; 32] { s.as_str().unwrap().parse::<alloy::primitives::B256>().unwrap().0 };
        let n = |s: &serde_json::Value| -> u64 { s.as_str().unwrap().parse().unwrap() };
        let mut named = 0;
        for r in v["freeze"].as_array().unwrap().iter().filter(|r| !r["error"].is_null()) {
            let sig = r["error"]["sig"].as_str().unwrap();
            let data = alloy::hex::decode(r["error"]["data"].as_str().unwrap()).unwrap();
            let got = decode_revert(&data);
            assert!(got.starts_with(&format!("{}(", &sig[..sig.find('(').unwrap()])), "{}: {got} is not {sig}", r["name"]);
            named += 1;
        }
        assert_eq!(named, 17, "every refused freeze row");
        let rows = v["receiver"].as_array().unwrap();
        for r in rows {
            let a = Attestation { flags: n(&r["flags"]), valid_until: n(&r["validUntil"]), attester_enabled: r["kycProviderEnabled"].as_bool().unwrap() };
            let kyc = r["kyc"].as_bool().unwrap(); // round 3s: both masks under bit 28
            let (req, den) = (kyc.then(|| n(&r["requiredFlags"])), kyc.then(|| n(&r["deniedFlags"])));
            let got = can_receive(req, den, &a, n(&r["now"]));
            assert_eq!(got, (r["ok"].as_bool().unwrap(), r["reason"].as_u64().unwrap() as u8), "{}", r["name"]);
        }
        assert_eq!(rows.len(), 44);
        for r in v["recordId"].as_array().unwrap() {
            assert_eq!(record_id(&w(&r["orderId"]), &w(&r["subject"]), &w(&r["beneficiary"])), w(&r["recordId"]), "{}", r["name"]);
        }
    }
}
