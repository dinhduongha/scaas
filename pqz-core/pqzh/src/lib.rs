//! PQZH prototype (P6-PQZH): R_REG and R_TX of PQ Zether proved by a STARK over Goldilocks (Plonky3, FRI, Keccak,
//! LogUp), design D1. See docs/research/pqzh-design.md and docs/research/pqzh-prototype.md.

pub mod air;
pub mod client;
pub mod config;
pub mod rel;
pub mod ring;

pub use config::Params;
pub use rel::{MAX_PROOF, OP_REGISTER, OP_TRANSFER, prove, verify};
