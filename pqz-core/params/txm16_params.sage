# R_TXM, M = 16 legs, G = 4 randomness group(s) of <= 4 legs, auditor on: one auditor copy per leg (row 5), e2_{a,j} one block (P6-ANON plan §3, D4, D5; Track L1).  OVERSIZE (P6-ANON D3 / D20: does not fit MAX_INPUT; built only with -DPQZ_TXM_OVERSIZE).
# s1 = s_f, e_f, (r_g, e1_g) for g < 4 (32 polys each), e2_j of the 16 legs (one exact-l2 block, bound 64*sqrt(M)), e2_f
# (1 poly), e2_{a,j} of the legs (one block), 30 binary polys (1877 used bits: d_j per leg, d', M, c, e_T).
# M = 1 is R_TX / R_TX0 (tx_params.sage / tx0_params.sage); this spec is the sketch params/anon/txm16g4_params.sage.
pqz_verbose = 1
name = "pqz_txm16"
q_fixed = 2^42 - 215
pqz_L = 4
log2q = 42
pqz_delta = 1.00366       # root-Hermite factor at beta ~ 450 (CTR-PQZ-03 target), checked by e_s1_proof.sage
d = 64

m1 = 32 * 10 + 16 + 1 + 16 + 30
alpha = sqrt(5 * (36^2 + 164^2) + (16 + 1 + 16) * 64^2 + 30 * 64)
l = 0

nbin = 30
n = [32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 16, 1, 16]
B = [36, 164, 36, 164, 36, 164, 36, 164, 36, 164, 64 * sqrt(16), 64, 64 * sqrt(16)]

# LaZer's tbox needs nprime > 0 (see codegen): a one-poly approximate l_inf proof as filler
# (e2_0, the first leg's noise, |coefficients| <= 20 < 64).
nprime = 1
Bprime = 64
