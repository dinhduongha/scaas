# Plan 5h Task 8b (set (a)): R_TXM M = 8, G = 2 randomness group(s) of <= 4 legs, auditor off: s_f, e_f, (r_g, e1_g) x 2, e2_j, e2_f; 9 e2 blocks, 1459 bits
# n = 2304 (k = 36), q = 61275424977257 (2^45.800, prime, q = 9 mod 16), Delta = 233747196, beta_s = 38, beta_e = 173,
# K_MAX = 4,096: M_i 16 bits, carries 13 bits (c_i + 64), e_T / e' + 2^26 in 27 bits (set (a), owner 2026-10-21).
# pqz_delta / kmlwe_min: pqz-core/params/sets/n2304-kmax4096/e-s1.txt (MSIS beta >= 450, hiding MLWE uSVP and dual_hybrid >= 450).
pqz_verbose = 1
name = "pqz_txm80"
q_fixed = 61275424977257
pqz_L = 4
log2q = 45
pqz_delta = 1.00366
kmlwe_min = 36
d = 64

m1 = 248
alpha = sqrt(3 * (38^2 + 173^2) + 9 * 64^2 + 23 * 64)
l = 0

nbin = 23
n = [36, 36, 36, 36, 36, 36, 1, 1, 1, 1, 1, 1, 1, 1, 1]
B = [38, 173, 38, 173, 38, 173, 64, 64, 64, 64, 64, 64, 64, 64, 64]

# LaZer's tbox needs nprime > 0: a one-poly approximate l_inf proof as filler (e2_0, the first leg's noise, |coefficients| <= 20 < 64).
nprime = 1
Bprime = 64
