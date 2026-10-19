# Plan Task 5h A' sizing (not a frozen relation): R_BURN: s_f, e_f, r, e1, e2_f, 18 binary polys (1135 bits: d' 64, M 16x20, c 15x17, e_T 16x31).
# n = 2688 (k = 42), q = 2^54 - 327 (q = 9 mod 16), beta_s = 41, beta_e = 186, K_MAX = 65,536 (aprime.sage budget).
pqz_verbose = 1
name = "pqz_ap2688_burn"
q_fixed = 2^54 - 327
pqz_L = 4
log2q = 54
pqz_delta = 1.00366
d = 64

m1 = 42 * 4 + 1 + 18
alpha = sqrt(2 * 41^2 + 2 * 186^2 + 64^2 + 18 * 64)
l = 0

nbin = 18
n = [42, 42, 42, 42, 1]
B = [41, 186, 41, 186, 64]

nprime = 1
Bprime = 64
