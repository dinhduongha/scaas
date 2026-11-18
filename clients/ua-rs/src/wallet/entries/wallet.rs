// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! T8d: the `MandateWallet` rows (`wallet`; Q6, MD-11): owner and delegate are ids; the pay takes the `PayMeta` its signed
//! `entryRef` commits to, last and unsigned. The ordered cancel `UACancelNonce` is in `token.rs` (its kinds name the wallet).
//! A copy of `scaas-node/src/typed.rs` `TYPED`, held equal by `tests/entries.rs`.
use super::Def;

const W: &[&str] = &["wallet"];

pub(super) const ROWS: &[Def] = &[
    ("UASetMandate", "mtxSetMandate", W, "bytes32 from,address token,bytes32 delegate,uint128 maxPerPayment,uint128 maxPerPeriod,uint64 periodSeconds,uint64 expiry,E", ""),
    ("UASetPayee", "mtxSetPayee", W, "bytes32 from,address token,bytes32 payee,bool allowed,E", ""),
    ("UARevokeMandate", "mtxRevokeMandate", W, "bytes32 from,address token,E", ""),
    ("UAPayUnderMandate", "mtxPayUnderMandate", W, "bytes32 from,address token,bytes32 payee,uint256 amount,bytes32 entryRef,uint64 epoch,E", "E token payee amount entryRef epoch @ meta:PayMeta"),
    ("UADelegateRevoke", "mtxDelegateRevoke", W, "bytes32 from,address token,uint64 epoch,E", ""),
    ("UAExecute", "mtxExecute", W, "bytes32 from,address target,uint256 value,bytes data,E", ""),
];
