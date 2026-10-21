# Plan 5h Task 7c (n-study research spec, not a relation): R_TXM M = 4, G = 1, auditor on, 9 e2 blocks, 1250 bits
# n = 2432 (k = 38), q = 253825663236121 (2^47.851), beta_s = 39, beta_e = 177, K_MAX = 8,192: M_i 17 bits, carries 14, e_T / e' 28 bits.
pqz_verbose = 1
name = "pqz_txm4"
q_fixed = 253825663236121
pqz_L = 4
log2q = 47
pqz_delta = 1.00366
d = 64

m1 = 181
alpha = sqrt(2 * (39^2 + 177^2) + 9 * 64^2 + 20 * 64)
l = 0

nbin = 20
n = [38, 38, 38, 38, 1, 1, 1, 1, 1, 1, 1, 1, 1]
B = [39, 177, 39, 177, 64, 64, 64, 64, 64, 64, 64, 64, 64]

nprime = 1
Bprime = 64
