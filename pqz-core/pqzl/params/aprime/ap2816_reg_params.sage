# Plan Task 5h A' sizing (not a frozen relation): R_REG: pk = A s + e.
# n = 2816 (k = 44), q = 2^54 - 327 (q = 9 mod 16), beta_s = 42, beta_e = 189, K_MAX = 65,536 (aprime.sage budget).
pqz_verbose = 1
name = "pqz_ap2816_reg"
q_fixed = 2^54 - 327
pqz_L = 4
log2q = 54
pqz_delta = 1.00366
d = 64

m1 = 88
alpha = sqrt(42^2 + 189^2)
l = 0

nbin = 0
n = [44, 44]
B = [42, 189]

nprime = 1
Bprime = 1
