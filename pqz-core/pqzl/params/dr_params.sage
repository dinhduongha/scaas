# R_DR (pq-zether.md §7.9, RECEIVER_X and AUDITOR): pk = A s + e,
# v[i] - (u^T s)[i] = Delta digits(amount)_i + e'_i, e'_i + 2^24 in [0, 2^25).
# Witness s1 = s, e (32 polys each), 7 binary polys (400 used bits: e').
pqz_verbose = 1
name = "pqz_dr"
q_fixed = 2^42 - 215
pqz_L = 4
log2q = 42
pqz_delta = 1.00366       # root-Hermite factor at beta ~ 450 (CTR-PQZ-03 target), checked by e_s1_proof.sage
d = 64

m1 = 32 * 2 + 7
alpha = sqrt(36^2 + 164^2 + 7 * 64)
l = 0

nbin = 7
n = [32, 32]
B = [36, 164]

# LaZer's tbox needs nprime > 0 (see codegen): a one-poly approximate l_inf proof as filler
# (s[0], coefficients in [-1, 1]).
nprime = 1
Bprime = 1
