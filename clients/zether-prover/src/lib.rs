//! Zether client library (R34): R33 conf keys, lifted ElGamal + BSGS, Sigma + Bulletproofs
//! prover and a native verifier mirror, over bn254 and BLS12-381 G1.
//!
//! UNAUDITED — NOT FOR PRODUCTION FUNDS.

// (statement, proof, witness) tuples are the API shape; a type alias per curve adds nothing.
#![allow(clippy::type_complexity)]

pub mod abi;
pub mod api;
pub mod bulletproofs;
pub mod curve;
pub mod elgamal;
pub mod envelope;
pub mod keys;
pub mod nonce;
pub mod schnorr;
pub mod transcript;
pub mod vectors;
#[cfg(target_arch = "wasm32")]
pub mod wasm;
pub mod zether;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ZError {
    #[error("bad point: {0}")]
    BadPoint(&'static str),
    #[error("bad scalar (not canonical, zero, or wrong length)")]
    BadScalar,
    #[error("bad seed: {0}")]
    BadSeed(&'static str),
    #[error("plaintext outside [0, 2^bound_bits): negative, or larger than this device's BSGS bound (use zether-read-balance)")]
    DecryptBound,
    #[error("bsgs: {0}")]
    Bsgs(&'static str),
    #[error("witness out of range")]
    OutOfRange,
    #[error("malformed proof: {0}")]
    BadProof(&'static str),
    #[error("bad statement: {0}")]
    BadStatement(&'static str),
    #[error("verification failed: {0}")]
    Verify(&'static str),
    #[error("the transfer's known gas ({gas}) exceeds the EIP-7825 per-transaction cap ({cap}): BLS12-381, commit-reveal, auditor included, M >= {min_m}; use a bundle or no-bundle form, leave the auditor out, or send fewer recipients")]
    GasCap { gas: u64, cap: u64, min_m: usize },
}
