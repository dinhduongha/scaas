//! Zether client library (R34): R33 conf keys, lifted ElGamal + BSGS, Sigma + Bulletproofs
//! prover and a native verifier mirror, over bn254 and BLS12-381 G1.
//!
//! UNAUDITED — NOT FOR PRODUCTION FUNDS.

pub mod abi;
pub mod bulletproofs;
pub mod curve;
pub mod elgamal;
pub mod envelope;
pub mod keys;
pub mod nonce;
pub mod schnorr;
pub mod transcript;
pub mod zether;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ZError {
    #[error("bad point: {0}")]
    BadPoint(&'static str),
    #[error("bad scalar (not canonical, zero, or wrong length)")]
    BadScalar,
    #[error("bad seed: {0}")]
    BadSeed(&'static str),
    #[error("plaintext outside [0, 2^40): decryption bound exceeded (negative or too large)")]
    DecryptBound,
    #[error("witness out of range")]
    OutOfRange,
    #[error("malformed proof: {0}")]
    BadProof(&'static str),
    #[error("bad statement: {0}")]
    BadStatement(&'static str),
    #[error("verification failed: {0}")]
    Verify(&'static str),
}
