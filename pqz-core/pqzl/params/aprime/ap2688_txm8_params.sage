# Plan Task 5h A' sizing (not a frozen relation): R_TXM M = 8, G = 2, auditor on: s_f, e_f, (r_g, e1_g) x 2, 8 + 1 + 8 e2 blocks, 26 binary polys (1647 bits).
# n = 2688 (k = 42), q = 2^54 - 327 (q = 9 mod 16), beta_s = 41, beta_e = 186, K_MAX = 65,536 (aprime.sage budget).
pqz_verbose = 1
name = "pqz_ap2688_txm8"
q_fixed = 2^54 - 327
pqz_L = 4
log2q = 54
pqz_delta = 1.00366
d = 64

m1 = 42 * 6 + 8 + 1 + 8 + 26
alpha = sqrt(3 * (41^2 + 186^2) + (8 + 1 + 8) * 64^2 + 26 * 64)
l = 0

nbin = 26
n = [42, 42, 42, 42, 42, 42, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
B = [41, 186, 41, 186, 41, 186, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64]

nprime = 1
Bprime = 64
