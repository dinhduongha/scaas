# Plan 5h Task 7c (n-study research spec, not a relation): R_REG pk = A s + e
# n = 2432 (k = 38), q = 1015347418145737 (2^49.851), beta_s = 39, beta_e = 177, K_MAX = 16,384: M_i 18 bits, carries 15, e_T / e' 29 bits.
pqz_verbose = 1
name = "pqz_reg"
q_fixed = 1015347418145737
pqz_L = 4
log2q = 49
pqz_delta = 1.00366
d = 64

m1 = 76
alpha = sqrt(39^2 + 177^2)
l = 0

nbin = 0
n = [38, 38]
B = [39, 177]

nprime = 1
Bprime = 1
