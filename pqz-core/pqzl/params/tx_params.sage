# R_TX (pq-zero-knowledge.md §7.4): witness s1 = s_f, e_f, r, e1 (32 polys each), e2_t, e2_f, e2_a
# (1 poly each, 16 used coefficients), 15 binary polys (917 used bits: d, d', M, c, e_T).
pqz_verbose = 1
name = "pqz_tx"
q_fixed = 2^42 - 215
pqz_L = 4
log2q = 42
pqz_delta = 1.00366       # root-Hermite factor at beta ~ 450 (CTR-PQZ-03 target), checked by e_s1_proof.sage
d = 64

m1 = 32 * 4 + 3 + 15
alpha = sqrt(2 * 36^2 + 2 * 164^2 + 3 * 64^2 + 15 * 64)
l = 0

nbin = 15
n = [32, 32, 32, 32, 1, 1, 1]
B = [36, 164, 36, 164, 64, 64, 64]

# LaZer's tbox needs nprime > 0 (see codegen): a one-poly approximate l_inf proof as filler
# (e2_t, |coefficients| <= 20 < 64).
nprime = 1
Bprime = 64
