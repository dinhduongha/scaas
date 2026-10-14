//! PQZH: the Ligero crate (pure Rust, no global state, so no lock), behind this thin adapter. Everything that names
//! the Ligero API is here: when the crate moves onto `pqz-stmt` and gains `R_TX0` (P6e Tasks 6, 8, branch `p6e-b3`),
//! only this file changes.
use pqzh_ligero::Params;

/// THE preset of the D3 id (proven, radix 431, n = 32,756, k = 817, t = 121, l = 695), written out: `Params::proven()`
/// derives t with f64 arithmetic, and the verify path has no floats (plan Global Constraints). The unit test
/// `pqzh_params_are_the_preset` pins it to `Params::proven()`.
pub const PARAMS: Params = Params { n: 32756, k: 817, ell: 695, t: 121, pow_bits: 16, proven: true, johnson: false };

/// The Ligero verifier (it catches its own panics; `crate::precompile` catches any other).
pub fn verify(op: u8, stmt: &[u8], proof: &[u8]) -> bool {
    pqzh_ligero::verify(op, stmt, proof, &PARAMS)
}

/// Ligero's prover (hedged with the statement and witness, D6).
#[cfg(feature = "prove")]
pub fn prove(op: u8, stmt: &[u8], wit: &[u8], rnd32: &[u8; 32]) -> Result<Vec<u8>, &'static str> {
    pqzh_ligero::prove(op, stmt, wit, *rnd32, &PARAMS)
}

/// One forward and inverse FFT over the preset's 2k − 1 domain (n2 = 1,634 = 2·19·43) of a fixed vector: the
/// self-test's Ligero KAT (D13). Returns the forward output as 6-byte big-endian elements and whether the inverse
/// gave the input back.
pub fn fft_kat() -> (Vec<u8>, bool) {
    use pqzh_ligero::fft::Domain;
    use pqzh_ligero::fq::Fq;
    let n = 2 * 19 * 43;
    let d = Domain::new(n);
    let a: Vec<Fq> = (0..n as u64).map(|i| Fq((i * i * 0x9E37_79B9 + 1) % pqzh_ligero::fq::Q)).collect();
    let f = d.fft(&a);
    let mut out = Vec::with_capacity(6 * n);
    f.iter().for_each(|x| x.put(&mut out));
    (out, d.ifft(&f) == a)
}

#[cfg(test)]
mod tests {
    #[test]
    fn pqzh_params_are_the_preset() {
        assert_eq!(super::PARAMS, pqzh_ligero::Params::proven());
    }
}
