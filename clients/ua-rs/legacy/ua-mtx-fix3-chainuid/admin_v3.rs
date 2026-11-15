// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The ua-rs rows as they stood at cac043bc, before CTR-GOV-28 (owner 2026-11-13) added the target's chain word
//! `bytes32 chainUid` as the last op field: `src/admin.rs`'s two registry rows, `src/regulated.rs`'s `UAEnableFeature` and
//! `src/pqzfee.rs`'s `UASetVerifierFee`. Their vector rows: `smartcontracts/vectors/typed/legacy/ua-mtx-fix3-chainuid/typed_ops.json`.
//! Reference only; not built.
pub const ADMIN_OPS_V3: [(&str, &str); 2] = [
    ("UASetKycProvider", "bytes32 provider,bool enabled"),
    ("UASetCompliance", "bytes32[] accounts,uint64[] flags,uint64[] until"),
];
pub const ENABLE_FEATURE_V3: &str = "UAEnableFeature(bytes32 from,address target,uint8 bit,<E>)";
pub const SET_VERIFIER_FEE_V3: &str = "UASetVerifierFee(bytes32 from,address target,uint64 next,<E>)";
