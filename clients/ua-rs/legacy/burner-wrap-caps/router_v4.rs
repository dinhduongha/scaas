// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The ua-rs router rows as they stood at 3fa153e4, before the Change of CTR-GOV-28 in round 3zb + 3zc (owner 2026-11-13, O5 /
//! O6) added the target's chain word `bytes32 chainUid` as the last op field: `src/regulated.rs`'s eight controls and the two
//! lists, `src/wraplimit.rs`'s `UASetWrapLimits` and `UASetWrapMember`. Their vector rows:
//! `smartcontracts/vectors/typed/legacy/burner-wrap-caps/typed_ops.json`. Reference only; not built.
pub const REGULATED_OPS_V4: [(&str, &str); 8] = [
    ("UAFreeze", "bytes32 account,bytes32 ref,bytes32 recordId"),
    ("UAUnfreeze", "bytes32 account,bytes32 ref"),
    ("UAForceTransfer", "bytes32 recordId,uint256 amount"),
    ("UAPause", "bytes32 ref,uint64 until"),
    ("UAUnpause", "bytes32 ref"),
    ("UARecordOrder", "bytes32 orderId,bytes32 documentHash,bytes32 subject,bytes32 beneficiary,uint256 maxAmount,uint64 freezeUntil"),
    ("UARevokeOrder", "bytes32 recordId,bytes32 reasonRef"),
    ("UAOperatorTransfer", "bytes32 account,bytes32 to,uint256 amount,bytes32 ref"),
];
pub const SET_LIST_V4: &str = "UASetAllowed|UASetDenied(bytes32 from,address target,bytes32[] accounts,bool on,<E>)";
pub const SET_WRAP_LIMITS_V4: &str =
    "UASetWrapLimits(bytes32 from,address target,WrapLegLimits[] legs,bool netUnwrap,bool wrapList,bool unwrapList,<E>)<WrapLegLimits><WrapLimit>";
pub const SET_WRAP_MEMBER_V4: &str = "UASetWrapMember(bytes32 from,address target,bytes32 account,bool canWrap,bool canUnwrap,<E>)";
