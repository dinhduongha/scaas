# Plan 5h Task 7c (n-study research spec, not a relation): R_TXM M = 2, G = 1, auditor on, 5 e2 blocks, 981 bits
# n = 2048 (k = 32), q = 3551048676137 (2^41.691), beta_s = 36, beta_e = 164, K_MAX = 1,024: M_i 14 bits, carries 11, e_T / e' 25 bits.
pqz_verbose = 1
name = "pqz_txm2"
q_fixed = 3551048676137
pqz_L = 4
log2q = 41
pqz_delta = 1.00366
d = 64

m1 = 149
alpha = sqrt(2 * (36^2 + 164^2) + 5 * 64^2 + 16 * 64)
l = 0

nbin = 16
n = [32, 32, 32, 32, 1, 1, 1, 1, 1]
B = [36, 164, 36, 164, 64, 64, 64, 64, 64]

nprime = 1
Bprime = 64
