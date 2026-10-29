//! Shared NEAR contract code (auth checks, encodings).
pub mod auth;
pub mod hash;
pub mod holder;
pub mod metaop;
pub mod ua;
pub mod webauthn;

pub use auth::Auth;

/// T19 ruling A: the gas a call budgets per NEAR transfer to an account it does not control (a relayer lane, payer,
/// executor, target). nearcore charges a transfer to an implicit (64-hex / ETH-implicit) id as an account creation:
/// 0.825 Tgas at send + 7.525 Tgas prepaid for the receiving receipt = 8.35 Tgas measured on near-sandbox 2.14
/// (`runs/2026-10-29-near-sandbox-probes.txt`); pinned with a margin. Every refund / deposit return adds it.
pub const IMPLICIT_TRANSFER_GAS: near_sdk::Gas = near_sdk::Gas::from_tgas(10);

/// `tgas` Tgas plus one `IMPLICIT_TRANSFER_GAS`: the static gas of a call that carries one such transfer.
pub const fn with_transfer(tgas: u64) -> near_sdk::Gas {
    near_sdk::Gas::from_gas(tgas * 1_000_000_000_000 + IMPLICIT_TRANSFER_GAS.as_gas())
}
pub use holder::Holder;
pub use metaop::{MetaOp, Order};
