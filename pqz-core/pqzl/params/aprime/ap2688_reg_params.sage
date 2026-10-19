# Plan Task 5h A' sizing (not a frozen relation): R_REG: pk = A s + e.
# n = 2688 (k = 42), q = 2^54 - 327 (q = 9 mod 16), beta_s = 41, beta_e = 186, K_MAX = 65,536 (aprime.sage budget).
pqz_verbose = 1
name = "pqz_ap2688_reg"
q_fixed = 2^54 - 327
pqz_L = 4
log2q = 54
pqz_delta = 1.00366
d = 64

m1 = 84
alpha = sqrt(41^2 + 186^2)
l = 0

nbin = 0
n = [42, 42]
B = [41, 186]

nprime = 1
Bprime = 1
