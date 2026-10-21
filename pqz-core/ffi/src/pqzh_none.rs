//! PQZH compiled out (feature `pqzh` off: every parameter set but n2048-kmax1024 until plan 5h Task 8c ports Ligero to
//! the set's q): the same API as `pqzh.rs`, fail-closed. A PQZH-id input is never valid in this build.

/// No PQZH verifier in this build: every PQZH-id input is invalid (`…00`).
pub fn verify(_op: u8, _stmt: &[u8], _proof: &[u8]) -> Result<bool, crate::NodeFault> {
    Ok(false)
}

/// No PQZH prover in this build.
#[cfg(feature = "prove")]
pub fn prove(_op: u8, _stmt: &[u8], _wit: &[u8], _rnd32: &[u8; 32]) -> Result<Vec<u8>, &'static str> {
    Err("PQZH is not compiled into this build (parameter set without PQZH until plan 5h Task 8c)")
}

/// No Ligero FFT in this build: the self-test's FFT part is empty and not ok (`selftest.json` records it).
pub fn fft_kat() -> (Vec<u8>, bool) {
    (Vec::new(), false)
}

/// No PQZH shapes in this build.
pub fn max_proof_len_multi(_m: usize, _aud: bool) -> usize {
    unreachable!("no PQZH in this build")
}

/// No Ligero verifier, no panics.
pub fn verify_panics() -> usize {
    0
}
