# R_TXM, M = 8 legs, G = 2 randomness group(s) of <= 4 legs, auditor on: one auditor copy per leg (row 5), e2_{a,j} one block each (P6-ANON plan §3, D4, D5; Track L1).
# s1 = s_f, e_f, (r_g, e1_g) for g < 2 (32 polys each), e2_j of the 8 legs (one exact-l2 block per leg, 1 poly, bound 64: owner 2026-10-15, X-1), e2_f
# (1 poly), e2_{a,j} of the legs (one block per copy, 1 poly, bound 64), 22 binary polys (1365 used bits: d_j per leg, d', M, c, e_T).
# M = 1 is R_TX / R_TX0 (tx_params.sage / tx0_params.sage); this spec is the sketch params/anon/txm8g2_params.sage.
pqz_verbose = 1
name = "pqz_txm8"
q_fixed = 2^42 - 215
pqz_L = 4
log2q = 42
pqz_delta = 1.00366       # root-Hermite factor at beta ~ 450 (CTR-PQZ-03 target), checked by e_s1_proof.sage
d = 64

m1 = 32 * 6 + 8 + 1 + 8 + 22
alpha = sqrt(3 * (36^2 + 164^2) + (8 + 1 + 8) * 64^2 + 22 * 64)
l = 0

nbin = 22
n = [32, 32, 32, 32, 32, 32, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
B = [36, 164, 36, 164, 36, 164, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64]

# LaZer's tbox needs nprime > 0 (see codegen): a one-poly approximate l_inf proof as filler
# (e2_0, the first leg's noise, |coefficients| <= 20 < 64).
nprime = 1
Bprime = 64
