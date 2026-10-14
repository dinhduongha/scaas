//! PQZH over Ligero (P6-PQZH, Ligero backend): R_REG and R_TX of PQ Zether proved by Ligero over F_q itself
//! (q = 2^42 - 215), challenges in F_q^4, Keccak-256 Merkle tree and transcript, zero knowledge.
//! See docs/research/pqzh-ligero.md. Statement and witness bytes as pqz-core / pqzh (`pqzh::client::setup()`).

pub mod cs;
pub mod fft;
pub mod fq;
pub mod ligero;
pub mod merkle;
pub mod transcript;

pub use ligero::{Params, breakdown, prove, prove_unchecked, soundness, verify};
pub use pqzh::{OP_REGISTER, OP_TRANSFER};
