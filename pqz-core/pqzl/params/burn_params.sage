# R_BURN (pq-zero-knowledge.md §7.5; also REFRESH): R_TX rows 1, 2, 4, 6, 7 with d = digits(amount) public.
# Witness s1 = s_f, e_f, r, e1 (32 polys each), e2_f (1 poly, 16 used coefficients),
# 14 binary polys (853 used bits: d', M, c, e_T).
pqz_verbose = 1
name = "pqz_burn"
q_fixed = 2^42 - 215
pqz_L = 4
log2q = 42
pqz_delta = 1.00366       # root-Hermite factor at beta ~ 450 (CTR-PQZ-03 target), checked by e_s1_proof.sage
d = 64

m1 = 32 * 4 + 1 + 14
alpha = sqrt(2 * 36^2 + 2 * 164^2 + 64^2 + 14 * 64)
l = 0

nbin = 14
n = [32, 32, 32, 32, 1]
B = [36, 164, 36, 164, 64]

# LaZer's tbox needs nprime > 0 (see codegen): a one-poly approximate l_inf proof as filler
# (e2_f, |coefficients| <= 20 < 64).
nprime = 1
Bprime = 64
