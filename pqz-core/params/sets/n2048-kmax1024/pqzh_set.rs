//! PQZH (Ligero, pqz-core/pqzh/ligero) constants of parameter set `n2048-kmax1024`, the frozen v3 set (q = 2^42 - 215); plan 5h Task 8c.
//! Hand-written for now (the set generator pqz-core/params/sets/gen_set.py takes it over later): a plain list.
//! Derivation: `python3 -I pqz-core/pqzh/ligero/ligero_params.py --set n2048-kmax1024` (factorisation of q - 1, the generator
//! and non-square checks, the preset); the crate's unit tests `fq::tests` / `fft::tests` assert every value.
//! The lattice constants (q, n, k, Delta, bit widths, bounds) are PQZL's, in ./rust/set.rs.
#![allow(dead_code)]
/// the prime factors of q - 1, with multiplicity
pub(crate) const QM1: &[u64] = &[2, 2, 2, 19, 43, 431, 1_561_243];
/// the smallest generator of F_q^*: the domains H_n = <GEN^((q - 1) / n)> and the commitment coset GEN H_n
pub(crate) const GEN: u64 = 3;
/// F_q^4 = F_q[X]/(X^4 - NR): NR the smallest non-square (q = 1 mod 4, so X^4 - NR is irreducible)
pub(crate) const NR: u64 = 3;
/// FFT radices (each divides q - 1; their product times 4 bounds the domain sizes, fft.rs)
pub(crate) const RADICES: [usize; 4] = [2, 19, 43, 431];
/// THE preset (Params::proven, owner 2026-10-14 (a)): proven regime, n = 32,756 = 4 19 431, k = 817 = 19 43,
/// t = 121 (soundness depends on n, k only; ligero_params.py), l = k - t - 1 = 695
pub(crate) const PRESET_N: usize = 32_756;
pub(crate) const PRESET_K: usize = 817;
pub(crate) const PRESET_T: usize = 121;
