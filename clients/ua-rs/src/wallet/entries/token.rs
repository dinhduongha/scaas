// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! T8a: the rows on the token kinds (`token`, and `zether` / `pqz` where the node's row names them too): the base ops, the
//! wraps, the pays (`mtxPay`, `mtxPayWithPayeeFee`, `mtxPayWithTax`, `PayMeta` last), the relay fee, the orders on ids. A copy
//! of `scaas-node/src/typed.rs` `TYPED`, held equal by `tests/entries.rs`.
use super::Def;

const T: &[&str] = &["token", "zether", "pqz"];
/// The ordered cancel on ids: the token kinds, the mandate wallet and the router.
const TWG: &[&str] = &["token", "zether", "pqz", "wallet", "gov_router"];

/// The transfer on ids (`mtxExecuteTransfer`, `POST /v1/ua-metatx`; owner 2026-11-18, ruling 6): the struct of `mtxPay`'s row,
/// its own entry; not a `/v1/op` row (the node's `ua_metatx` struct job), so not in [`super::entry_rows`].
pub(super) const IDS: Def = ("UAMetaTransfer", "mtxExecuteTransfer", T, "bytes32 from,bytes32 to,uint256 value,bytes32 entryRef,E", "$ @");

pub(super) const ROWS: &[Def] = &[
    ("UACancelNonce", "mtxCancelNonce", TWG, "bytes32 from,uint256 lane,E", ""),
    ("UABurn", "mtxBurn", T, "bytes32 from,uint256 amount,E", ""),
    ("Wrap", "mtxWrap", T, "address from,uint256 amount,E", ""),
    ("WrapLeg", "mtxWrapLeg", T, "address from,address underlying,uint256 amount,E", ""),
    ("UAUnwrap", "mtxUnwrap", T, "bytes32 from,uint256 wrapped,address recipient,uint256 minOut,E", ""),
    ("UAUnwrapLeg", "mtxUnwrapLeg", T, "bytes32 from,address underlying,uint256 wrapped,address recipient,uint256 minOut,E", ""),
    ("AddReserve", "mtxAddReserve", T, "address from,address underlying,uint256 amount,E", ""),
    ("WrapToUA", "mtxWrapToUA", T, "address from,address underlying,uint256 amount,bytes32 to,E", ""),
    ("UAUnwrapToUA", "mtxUnwrapToUA", T, "bytes32 from,address underlying,uint256 wrapped,bytes32 to,uint256 minOut,E", ""),
    ("UAMetaTransfer", "mtxPay", T, "bytes32 from,bytes32 to,uint256 value,bytes32 entryRef,E", "$ @ meta:PayMeta"),
    ("UAPayeeFee", "mtxPayWithPayeeFee", T, "UAMetaTransfer payment,uint256 fee,address feeRecipient,uint256 validUntil", "payment payerSig:UASig fee feeRecipient validUntil @ meta:PayMeta"),
    ("UAPayWithTax", "mtxPayWithTax", T, "UAMetaTransfer payment,uint8 taxMode,uint256 tax", "payment taxMode tax @ meta:PayMeta"),
    ("UARelayFee", "mtxRelayFee", T, "bytes32 from,address target,bytes32 callDataHash,bytes32 payee,uint256 value,uint256 batch,uint256 nonce,uint256 validUntil,address relayer", "from target callDataHash payee value batch nonce validUntil @"),
    ("UAWrapOrder", "mtxWrapOrder", T, "bytes32 from,address wrappedToken,uint256 amount,uint256 minMinted,uint256 minFill,uint256 fee,address relayer,bytes32 destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil", "underlying:address $ @"),
    ("CancelUAOrder", "mtxCancelOrder", T, "UATradeOrder order", "order @"),
    ("CancelUAWrapOrder", "mtxCancelOrder", T, "UAWrapOrder order", "wrap!order @"),
    ("UAInvalidateNonces", "mtxInvalidateNonces", T, "bytes32 from,uint256 batch,uint256 minNonce", "from batch minNonce @"),
];
