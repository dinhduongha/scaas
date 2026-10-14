//! PQZH over Ligero (P6-PQZH, Ligero backend): R_REG, R_TX, R_BURN, R_DS and R_DR of PQ Zether proved by Ligero over
//! F_q itself (q = 2^42 - 215), challenges in F_q^4, Keccak-256 Merkle tree and transcript, zero knowledge.
//! See docs/research/pqzh-ligero.md. Statement and witness bytes as pqz-core (`client::setup()`, xcheck/ligero.sh).
//! Depends on `sha3` only (P6e Task 6 prep: `ring`, `stmt` and `client` are copies of the Plonky3 crate's modules).

pub mod client;
pub mod cs;
pub mod fft;
pub mod fq;
pub mod ligero;
pub mod merkle;
pub mod ring;
pub mod stmt;
pub mod transcript;

pub use ligero::{Params, breakdown, prove, prove_unchecked, soundness, verify};
pub use stmt::{OP_BURN, OP_DISCLOSE_RECEIVER, OP_DISCLOSE_SENDER, OP_REGISTER, OP_TRANSFER, OPS};
