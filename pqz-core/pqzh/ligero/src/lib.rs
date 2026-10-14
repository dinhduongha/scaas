//! PQZH over Ligero (P6-PQZH, Ligero backend): R_REG, R_TX, R_TX0, R_BURN, R_DS and R_DR of PQ Zether proved by
//! Ligero over F_q itself (q = 2^42 - 215), challenges in F_q^4, Keccak-256 Merkle tree and transcript, zero knowledge.
//! See docs/research/pqzh-ligero.md. Statements are decoded by `pqz-stmt` (plan R2, D15); witness bytes as pqz-core
//! (pqz.h). Depends on `sha3` and `pqz-stmt` only (D11). Feature `bench` (default): the reference presets, the float
//! parameter model and soundness accounting, and the test client (`client`: pqz_bench.c's setup, mutations); the
//! production build (`--no-default-features`) has none of them.
#![cfg_attr(not(feature = "bench"), deny(clippy::float_arithmetic))]

#[cfg(feature = "bench")]
pub mod client;
pub mod cs;
pub mod fft;
pub mod fq;
pub mod ligero;
pub mod merkle;
pub mod ring;
pub mod transcript;

pub use cs::{RELS, form_of};
pub use ligero::{Params, prove, prove_unchecked, verify};
#[cfg(feature = "bench")]
pub use ligero::{breakdown, soundness};
pub use pqz_stmt::{self, Form, OP_BURN, OP_DISCLOSE_RECEIVER, OP_DISCLOSE_SENDER, OP_REGISTER, OP_TRANSFER};
