//! SUPERSEDED, not compiled (owner 2026-10-22: preset B at t = 120 is ./pqzh_set.rs). RESEARCH SPIKE B (plan 5h Task 8c
//! spike, 2026-10-22; kept as the record of the measured t = 119 run, runs/spike-b-*): set (a)'s PQZH constants with
//! the radices 7 and 17 of its q - 1 and the preset `ligero_params.py --set n2304-kmax4096` finds with them. It was selected by
//! the spike's feature `spike-b` (removed).
#![allow(dead_code)]
/// the prime factors of q - 1, with multiplicity
pub(crate) const QM1: &[u64] = &[2, 2, 2, 7, 17, 19, 43, 431, 182_789];
/// the smallest generator of F_q^*
pub(crate) const GEN: u64 = 3;
/// F_q^4 = F_q[X]/(X^4 - NR)
pub(crate) const NR: u64 = 3;
/// FFT radices, ascending (the largest is the deepest stage); 7 and 17 added
pub(crate) const RADICES: [usize; 6] = [2, 7, 17, 19, 43, 431];
/// the spike preset: proven, n = 45,752 = 2^3 7 19 43, k = 952 = 2^3 7 17, t = 119, l = 832
pub(crate) const PRESET_N: usize = 45_752;
pub(crate) const PRESET_K: usize = 952;
pub(crate) const PRESET_T: usize = 119;
