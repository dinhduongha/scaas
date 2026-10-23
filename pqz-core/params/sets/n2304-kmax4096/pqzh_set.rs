//! PQZH (Ligero, pqz-core/pqzh/ligero) constants of parameter set `n2304-kmax4096`, set (a) (q = 61,275,424,977,257);
//! plan 5h Task 8c. Preset B (owner 2026-10-22): the radices 7 and 17 of this q - 1 and the preset n 45,752, k 952,
//! t 120, so that every debit proof bound is below MAX_PROOF_PQZH 262,144 (THE preset's were 263,784-265,236).
//! Hand-written for now (the set generator pqz-core/params/sets/gen_set.py takes it over later): a plain list.
//! Derivation: `python3 -I pqz-core/pqzh/ligero/ligero_params.py --set n2304-kmax4096` (factorisation of q - 1, the
//! generator and non-square checks, the preset search with the set's radices; t = 120 is one above the search's minimum
//! 119, so the soundness total stays above THE preset's 127.23 bits); docs/research/pqzh-set-a-proof-limit.md. The
//! crate's unit tests `fq::tests` / `fft::tests` / `ligero::tests` assert every value. The fallbacks (THE preset) are in
//! ./pqzh_set_fallback.rs. The lattice constants (q, n, k, Delta, bit widths, bounds) are PQZL's, in ./rust/set.rs.
#![allow(dead_code)]
/// the prime factors of q - 1, with multiplicity
pub(crate) const QM1: &[u64] = &[2, 2, 2, 7, 17, 19, 43, 431, 182_789];
/// the smallest generator of F_q^*: the domains H_n = <GEN^((q - 1) / n)> and the commitment coset GEN H_n
pub(crate) const GEN: u64 = 3;
/// F_q^4 = F_q[X]/(X^4 - NR): NR the smallest non-square (q = 1 mod 4, so X^4 - NR is irreducible)
pub(crate) const NR: u64 = 3;
/// FFT radices, ascending (the largest is the deepest stage); each divides q - 1, 4 times their product bounds the
/// domain sizes (fft.rs). 7 and 17 run through the generic r-point stage.
pub(crate) const RADICES: [usize; 6] = [2, 7, 17, 19, 43, 431];
/// the preset (Params::proven): proven regime, n = 45,752 = 2^3 7 19 43 (the code on the coset 3 H_n), k = 952 =
/// 2^3 7 17, t = 120, l = k - t - 1 = 831; products on H_2261 (7 17 19)
pub(crate) const PRESET_N: usize = 45_752;
pub(crate) const PRESET_K: usize = 952;
pub(crate) const PRESET_T: usize = 120;
