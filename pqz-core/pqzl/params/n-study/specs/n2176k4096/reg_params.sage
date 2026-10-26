# Plan 5h Task 7c (n-study research spec, not a relation): R_REG pk = A s + e
# n = 2176 (k = 34), q = 59152611864169 (2^45.750), beta_s = 37, beta_e = 169, K_MAX = 4,096: M_i 16 bits, carries 13, e_T / e' 27 bits.
pqz_verbose = 1
name = "pqz_reg"
q_fixed = 59152611864169
pqz_L = 4
log2q = 45
pqz_delta = 1.00366
d = 64

m1 = 68
alpha = sqrt(37^2 + 169^2)
l = 0

nbin = 0
n = [34, 34]
B = [37, 169]

nprime = 1
Bprime = 1
