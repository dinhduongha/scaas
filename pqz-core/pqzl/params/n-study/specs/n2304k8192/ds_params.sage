# Plan 5h Task 7c (n-study research spec, not a relation): R_DS
# n = 2304 (k = 36), q = 245122345819289 (2^47.800), beta_s = 38, beta_e = 173, K_MAX = 8,192: M_i 17 bits, carries 14, e_T / e' 28 bits.
pqz_verbose = 1
name = "pqz_ds"
q_fixed = 245122345819289
pqz_L = 4
log2q = 47
pqz_delta = 1.00366
d = 64

m1 = 73
alpha = sqrt(38^2 + 173^2 + 64^2)
l = 0

nbin = 0
n = [36, 36, 1]
B = [38, 173, 64]

nprime = 1
Bprime = 64
