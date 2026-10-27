//! ABI — copied from `smartcontracts/evm/src` (`IMetaTx`, `IERC20MetaTx`, `IERC20Payment`, `ITradeToken`, `MetaTxLib`,
//! `ISCaaSDex`, `MandateWallet`), never inferred: one wrong `indexed` is one wrong topic. Pinned by the forge KATs
//! (`metatx_kat.json`, `metatransfer_kat.json`, `trade_kat.json`, `dex_order_kat.json`: digests and relayed calldata).
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

    /// `ISCaaSDex.Leg` (CTR-DEX-26): one order in one settlement, tagged; `shape` 0 = `order` is
    /// `abi.encode(TradeOrder)`, 1 = `abi.encode(UATradeOrder)`; `fill` = its sell fill in this call.
    #[derive(Debug, PartialEq, Eq)]
    struct Leg { address sellToken; uint8 shape; bytes order; bytes sig; uint256 fill; }

    /// `ISCaaSDex.ExchangeLeg` (CTR-DEX-20, -26): an exchange-path order, tagged as `Leg`.
    #[derive(Debug, PartialEq, Eq)]
    struct ExchangeLeg { address sellToken; uint8 shape; bytes order; bytes sig; uint256 sellFill; uint256 receiveFill; }

    /// `ISCaaSDex.ExchangePlan` / `Interaction` (CTR-DEX-20): the exchange path's argument shapes.
    #[derive(Debug, PartialEq, Eq)]
    struct ExchangePlan { bytes32 ref; ExchangeLeg[] legs; address[] extraTokens; }
    #[derive(Debug, PartialEq, Eq)]
    struct Interaction { address target; bytes data; }

    /// An outside-token order (CTR-DEX-18): the `TradeOrder` signed in the DEX's domain with its sell token.
    #[derive(Debug, PartialEq, Eq)]
    struct DexOrder { address sellToken; TradeOrder order; }

    /// One taker against one or more makers (CTR-DEX-16); `ref` is the submitter's (the venue's trade tag).
    #[derive(Debug, PartialEq, Eq)]
    struct Settlement { bytes32 ref; Leg taker; Leg[] makers; }

    struct CancelOrder { bytes32 orderHash; }
    struct InvalidateNonces { address from; uint256 batch; uint256 minNonce; }

    /// `SCaaSDex` (a clone per DEX, `createDex`): what the venue sends and reads.
    #[derive(Debug)]
    interface ISCaaSDex {
        function mtxSettle(Settlement[] s) external returns (bool[] ok);
        function mtxExchange(ExchangePlan p, Interaction[] interactions) external;
        function mtxExchangeVia(ExchangePlan p, address executor, bytes data) external;
        function settleOne(Settlement s, address submitter) external;
        function mtxCancelOrders(DexOrder[] orders, bytes[] sigs) external;
        function mtxInvalidateNonces(address from, uint256 batch, uint256 newMin, bytes sig) external;
        function dexOrderDigest(address sellToken, TradeOrder o) external view returns (bytes32);
        function cancelOrderDigest(bytes32 orderHash) external view returns (bytes32);
        function invalidateNoncesDigest(address from, uint256 batch, uint256 newMin) external view returns (bytes32);
        function pulled(bytes32 orderHash) external view returns (uint256);
        function minNonce(address from, uint256 batch) external view returns (uint256);
        function puller() external view returns (address);
        function marketListed(address a, address b) external view returns (bool);
        function tokenKind(address token) external view returns (uint8);
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
    }

    /// Every SCaaS contract on `MetaTxBase` (`IMetaTx`) plus the token surface the node reads or relays.
    #[derive(Debug)]
    interface IToken {
        function mtxNonce(address from, uint256 batch) external view returns (uint256);
        function mtxDigest(MetaTransaction m) external view returns (bytes32);
        function mtxTransferDigest(MetaTransfer t) external view returns (bytes32);
        function mtxExecute(MetaTransaction m, bytes signature) external returns (bytes);
        function mtxExecuteTransfer(MetaTransfer t, bytes signature) external returns (bool);
        /// CTR-MTX-26 (`IMetaTokenV2`): `mtxPay` with `payId = metaPayId(salt, meta)`; `PaymentMeta` first.
        function mtxPayMeta(address from, address to, uint256 amount, bytes32 salt, bytes meta, uint256 validUntil,
            uint32 mode, address relayer, uint256 fee, address feeRecipient, bytes signature) external returns (bool);
        event PaymentMeta(bytes32 indexed payId, bytes meta);
        function mtxSelectors() external view returns (bytes4[] selectors, uint8[] feeClass, uint8[] amountArg);
        function chainUid() external view returns (bytes32);
        function supportedModes() external view returns (uint32);
        function balanceOf(address who) external view returns (uint256);
        function transfer(address to, uint256 value) external returns (bool);
        function mtxTrade(TradeOrder o, bytes sig, TradeFill f) external;
        function mtxCancelOrder(TradeOrder o, bytes sig) external;
        function mtxInvalidateNonces(address from, uint256 batch, uint256 newMin, bytes sig) external;
        function mtxWrap(address underlying, TradeOrder o, bytes sig) external;
        /// `ITradeToken.UANoncesInvalidated`: `uaInvalidateNonces`; `from` is the id (a native address zero-padded).
        event UANoncesInvalidated(bytes32 indexed from, uint256 indexed batch, uint256 minNonce);
        function allowance(address owner, address spender) external view returns (uint256);
        function tradeOrderDigest(TradeOrder o) external view returns (bytes32);
        function cancelOrderDigest(bytes32 orderHash) external view returns (bytes32);
        function invalidateNoncesDigest(address from, uint256 batch, uint256 newMin) external view returns (bytes32);
        function pulled(bytes32 orderHash) external view returns (uint256);
        function minNonce(address from, uint256 batch) external view returns (uint256);
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
    }

    /// `MtxRelayFee` (CTR-MTX-27): a token fee to the relayer for a fee-less call. `uaRelay` is not served (the node
    /// has no UA path on EVM).
    #[derive(Debug)]
    interface IMtxRelayFee {
        function relay(address target, bytes callData, address token, MetaTransfer t, bytes sig) external;
        function relayRef(address target, bytes callData) external view returns (bytes32);
        function EXECUTOR() external view returns (address);
        event RelayFeePaid(bytes32 indexed ref, address indexed target, address indexed token, bytes32 payer,
            bytes32 payee, uint256 amount);
        error RelayFeeShape();
        error RelayTargetNoCode(address target);
    }

    /// `MandateWallet` errors (CTR-ACC-06/07): a `call` job's revert reason names them, so the client re-reads
    /// `epoch(token)` and re-signs on `StaleEpoch`.
    #[derive(Debug)]
    interface IMandateWallet {
        error NotOwner();
        error NotDelegate();
        error NoMandate();
        error MandateExpired();
        error PayeeNotAllowed(address payee);
        error OverPaymentCap(uint256 amount, uint256 cap);
        error OverPeriodCap(uint256 wouldSpend, uint256 cap);
        error RefAlreadyPaid(bytes32 entryRef);
        error StaleEpoch(uint64 current, uint64 signed);
        error CallFailed(bytes reason);
        error PayFailed();
    }
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
    if let Ok(e) = IMtxRelayFee::IMtxRelayFeeErrors::abi_decode(data) {
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
    }
}
