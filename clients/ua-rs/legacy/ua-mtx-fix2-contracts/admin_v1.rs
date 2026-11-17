// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The `UARenounceAdmin` row of `src/admin.rs`'s `ADMIN_OPS` as it stood at a18e9464, before Fable recheck-2 P3-1 (owner
//! 2026-11-12, CTR-GOV-27) added `bytes32 chainUid` (the target's chain word): no params after `bytes32 from,address target`.
//! Its vector row: `smartcontracts/vectors/typed/legacy/ua-mtx-fix2-contracts/typed_ops.json`. Reference only; not built.
pub const UA_RENOUNCE_ADMIN_V1: (&str, &str) = ("UARenounceAdmin", "");
