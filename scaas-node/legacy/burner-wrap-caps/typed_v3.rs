// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The node's 25 router rows (`src/typed.rs` `TYPED`) as they stood at 3fa153e4, before the Change of CTR-GOV-28 in round
//! 3zb + 3zc (owner 2026-11-13, O5 / O6: every direct entry a role holder calls, and `setWrapLimits`, carries the target's
//! chain word) added `bytes32 chainUid` as the last op field (a job without it is now `BAD_PAYLOAD`, `args.chainUid: missing`).
//! (`"GR"`: the table's router domain.) Their vector rows: `smartcontracts/vectors/typed/legacy/burner-wrap-caps/typed_ops.json`.
//! Reference only; not built.
pub const ROUTER_ROWS_V3: [(&str, &str, &str, &str, &str); 25] = [
    ("UAMint", "mtxMint", "GR", "bytes32 from,address target,address to,uint256 amount,E", ""),
    ("UAMintToUA", "mtxMintToUA", "GR", "bytes32 from,address target,bytes32 to,uint256 amount,E", ""),
    ("UADisableWrap", "mtxDisableWrap", "GR", "bytes32 from,address target,address leg,bytes32 reason,E", ""),
    ("UAProposeRate", "mtxProposeRate", "GR", "bytes32 from,address target,address leg,uint96 num,uint96 den,E", ""),
    ("UACancelRate", "mtxCancelRate", "GR", "bytes32 from,address target,E", ""),
    ("UAExecuteRate", "mtxExecuteRate", "GR", "bytes32 from,address target,E", ""),
    ("UASetMarket", "mtxSetMarket", "GR", "bytes32 from,address target,address base,address quote,bool listed,E", ""),
    ("UASetExchangeTarget", "mtxSetExchangeTarget", "GR", "bytes32 from,address target,address exchangeTarget,bool listed,E", ""),
    ("UASetListedOnly", "mtxSetListedOnly", "GR", "bytes32 from,address target,bool on,E", ""),
    ("UASetFeeSplit", "mtxSetFeeSplit", "GR", "bytes32 from,address target,uint32 relayerSharePpm,address treasury,E", ""),
    ("UAFreeze", "mtxFreeze", "GR", "bytes32 from,address target,bytes32 account,bytes32 ref,bytes32 recordId,E", ""),
    ("UAUnfreeze", "mtxUnfreeze", "GR", "bytes32 from,address target,bytes32 account,bytes32 ref,E", ""),
    ("UAForceTransfer", "mtxForceTransfer", "GR", "bytes32 from,address target,bytes32 recordId,uint256 amount,E", ""),
    ("UAPause", "mtxPause", "GR", "bytes32 from,address target,bytes32 ref,uint64 until,E", ""),
    ("UAUnpause", "mtxUnpause", "GR", "bytes32 from,address target,bytes32 ref,E", ""),
    ("UARecordOrder", "mtxRecordOrder", "GR", "bytes32 from,address target,bytes32 orderId,bytes32 documentHash,bytes32 subject,bytes32 beneficiary,uint256 maxAmount,uint64 freezeUntil,E", ""),
    ("UARevokeOrder", "mtxRevokeOrder", "GR", "bytes32 from,address target,bytes32 recordId,bytes32 reasonRef,E", ""),
    ("UASetTaxRate", "mtxSetTaxRate", "GR", "bytes32 from,address target,uint32 ratePpm,E", ""),
    ("UASetTaxRecipient", "mtxSetTaxRecipient", "GR", "bytes32 from,address target,bytes32 taxRecipient,E", ""),
    ("UASetProofStore", "mtxSetProofStore", "GR", "bytes32 from,address target,uint8 next,E", ""),
    ("UAOperatorTransfer", "mtxOperatorTransfer", "GR", "bytes32 from,address target,bytes32 account,bytes32 to,uint256 amount,bytes32 ref,E", ""),
    ("UASetWrapLimits", "mtxSetWrapLimits", "GR", "bytes32 from,address target,WrapLegLimits[] legs,bool netUnwrap,bool wrapList,bool unwrapList,E", ""),
    ("UASetWrapMember", "mtxSetWrapMember", "GR", "bytes32 from,address target,bytes32 account,bool canWrap,bool canUnwrap,E", ""),
    ("UASetAllowed", "mtxSetAllowed", "GR", "bytes32 from,address target,bytes32[] accounts,bool on,E", ""),
    ("UASetDenied", "mtxSetDenied", "GR", "bytes32 from,address target,bytes32[] accounts,bool on,E", ""),
];
