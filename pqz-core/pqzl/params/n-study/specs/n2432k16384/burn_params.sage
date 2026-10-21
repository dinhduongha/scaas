# Plan 5h Task 7c (n-study research spec, not a relation): R_BURN / REFRESH, 1 e2 blocks, 1041 bits
# n = 2432 (k = 38), q = 1015347418145737 (2^49.851), beta_s = 39, beta_e = 177, K_MAX = 16,384: M_i 18 bits, carries 15, e_T / e' 29 bits.
pqz_verbose = 1
name = "pqz_burn"
q_fixed = 1015347418145737
pqz_L = 4
log2q = 49
pqz_delta = 1.00366
d = 64

m1 = 170
alpha = sqrt(2 * (39^2 + 177^2) + 1 * 64^2 + 17 * 64)
l = 0

nbin = 17
n = [38, 38, 38, 38, 1]
B = [39, 177, 39, 177, 64]

nprime = 1
Bprime = 64
