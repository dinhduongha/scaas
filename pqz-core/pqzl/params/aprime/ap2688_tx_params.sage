# Plan Task 5h A' sizing (not a frozen relation): R_TX: s_f, e_f, r, e1 (k polys each), e2_t, e2_f, e2_a, 19 binary polys (1199 bits: d 64, d' 64, M 16x20, c 15x17, e_T 16x31).
# n = 2688 (k = 42), q = 2^54 - 327 (q = 9 mod 16), beta_s = 41, beta_e = 186, K_MAX = 65,536 (aprime.sage budget).
pqz_verbose = 1
name = "pqz_ap2688_tx"
q_fixed = 2^54 - 327
pqz_L = 4
log2q = 54
pqz_delta = 1.00366
d = 64

m1 = 42 * 4 + 3 + 19
alpha = sqrt(2 * 41^2 + 2 * 186^2 + 3 * 64^2 + 19 * 64)
l = 0

nbin = 19
n = [42, 42, 42, 42, 1, 1, 1]
B = [41, 186, 41, 186, 64, 64, 64]

nprime = 1
Bprime = 64
