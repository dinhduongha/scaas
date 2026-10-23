//! PQZH: the Ligero crate (pure Rust, no global state, so no lock), behind this thin adapter. Everything that names
//! the Ligero API is here (on `pqz-stmt` with all six forms since P6e Tasks 6, 8).
use pqzh_ligero::Params;

/// The set's proven preset (pqz-core/params/sets/<set>/pqzh_set.rs; n2048-kmax1024: THE preset of the D3 id, radix 431,
/// n = 32,756, k = 817, t = 121, l = 695; n2304-kmax4096: preset B; n2560-kmax16384: THE preset's n / k, t = 122): a
/// `const fn`, no floats.
pub const PARAMS: Params = Params::proven();

/// The Ligero verifier (it catches its own panics; `crate::precompile` catches any other). `Err(NodeFault)` when one
/// of its buffers could not be reserved (review P-D, as PQZL's `Error::Memory`).
pub fn verify(op: u8, stmt: &[u8], proof: &[u8]) -> Result<bool, crate::NodeFault> {
    pqzh_ligero::try_verify(op, stmt, proof, &PARAMS).map_err(|_| crate::NodeFault)
}

/// Ligero's prover (hedged with the statement and witness, D6).
#[cfg(feature = "prove")]
pub fn prove(op: u8, stmt: &[u8], wit: &[u8], rnd32: &[u8; 32]) -> Result<Vec<u8>, &'static str> {
    pqzh_ligero::prove(op, stmt, wit, *rnd32, &PARAMS)
}

/// Ligero's exact proof-length bound of an op 7 shape (tests, bench).
pub fn max_proof_len_multi(m: usize, aud: bool) -> usize {
    PARAMS.max_proof_len(pqzh_ligero::Rel::Multi { m, aud })
}

/// Panics the Ligero verifier caught so far (tests).
pub fn verify_panics() -> usize {
    pqzh_ligero::ligero::VERIFY_PANICS.load(std::sync::atomic::Ordering::Relaxed)
}

/// One forward and inverse FFT over THE preset's 2k − 1 domain (n2 = 1,634 = 2·19·43, a domain at every set with PQZH)
/// of a fixed vector: the self-test's Ligero KAT (D13). Returns the forward output as EB-byte big-endian elements (6 at
/// n2048-kmax1024) and whether the inverse gave the input back.
pub fn fft_kat() -> (Vec<u8>, bool) {
    use pqzh_ligero::fft::Domain;
    use pqzh_ligero::fq::Fq;
    let n = 2 * 19 * 43;
    let d = Domain::new(n);
    let a: Vec<Fq> = (0..n as u64).map(|i| Fq((i * i * 0x9E37_79B9 + 1) % pqzh_ligero::fq::Q)).collect();
    let f = d.fft(&a);
    let mut out = Vec::with_capacity(pqzh_ligero::fq::EB * n);
    f.iter().for_each(|x| x.put(&mut out));
    (out, d.ifft(&f) == a)
}
