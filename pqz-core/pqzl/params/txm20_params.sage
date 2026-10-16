# R_TXM, M = 2 legs, G = 1 randomness group(s) of <= 4 legs, auditor off (CTR-PQZ-24): no pk_a / v_{a,j}, row 5 skipped (P6-ANON plan §3, D4, D5; Track L1).
# s1 = s_f, e_f, (r_g, e1_g) for g < 1 (32 polys each), e2_j of the 2 legs (one exact-l2 block per leg, 1 poly, bound 64: owner 2026-10-15, X-1), e2_f
# (1 poly), 16 binary polys (981 used bits: d_j per leg, d', M, c, e_T).
# M = 1 is R_TX / R_TX0 (tx_params.sage / tx0_params.sage); this spec is the sketch params/anon/txm2_params.sage without the auditor.
pqz_verbose = 1
name = "pqz_txm20"
q_fixed = 2^42 - 215
pqz_L = 4
log2q = 42
pqz_delta = 1.00366       # root-Hermite factor at beta ~ 450 (CTR-PQZ-03 target), checked by e_s1_proof.sage
d = 64

m1 = 32 * 4 + 2 + 1 + 16
alpha = sqrt(2 * (36^2 + 164^2) + (2 + 1) * 64^2 + 16 * 64)
l = 0

nbin = 16
n = [32, 32, 32, 32, 1, 1, 1]
B = [36, 164, 36, 164, 64, 64, 64]

# LaZer's tbox needs nprime > 0 (see codegen): a one-poly approximate l_inf proof as filler
# (e2_0, the first leg's noise, |coefficients| <= 20 < 64).
nprime = 1
Bprime = 64
