# Plan 5h Task 7c (n-study research spec, not a relation): R_DS
# n = 2048 (k = 32), q = 3551048676137 (2^41.691), beta_s = 36, beta_e = 164, K_MAX = 1,024: M_i 14 bits, carries 11, e_T / e' 25 bits.
pqz_verbose = 1
name = "pqz_ds"
q_fixed = 3551048676137
pqz_L = 4
log2q = 41
pqz_delta = 1.00366
d = 64

m1 = 65
alpha = sqrt(36^2 + 164^2 + 64^2)
l = 0

nbin = 0
n = [32, 32, 1]
B = [36, 164, 64]

nprime = 1
Bprime = 64
