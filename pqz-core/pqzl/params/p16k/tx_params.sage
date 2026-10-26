# Plan 5h Task 7 (16k candidate, not a frozen relation; Task 8 switches the code): R_TX: s_f, e_f, r, e1, e2_t, e2_f, e2_a; bits d 64, d' 64, M 16x18, c 15x15, e_T 16x29. 3 e2 blocks, 18 binary polys (1105 bits).
# n = 2560 (k = 40), q = 2^50 - 42,310,535 (prime, q = 9 mod 16, owner ruling Q1), beta_s = 40, beta_e = 182,
# K_MAX = 16,384: M_i 18 bits, carries 15 bits, e_T + 2^28 in 29 bits (plan D16). pqz_delta / kmlwe_min: p16k/estimator-e-s1-16k.txt.
pqz_verbose = 1
name = "pqz_tx"
q_fixed = 2^50 - 42310535
pqz_L = 4
log2q = 50
pqz_delta = 1.00366       # root-Hermite target: MSIS beta >= 450 on the first try (estimator-e-s1-16k.txt)
kmlwe_min = 39            # MLWE rank floor: the codegen default 38 gives dual_hybrid 446 / 447 < 450; 39 gives 462 / 463
d = 64

m1 = 40 * 4 + 3 + 18
alpha = sqrt(2 * (40^2 + 182^2) + 3 * 64^2 + 18 * 64)
l = 0

nbin = 18
n = [40, 40, 40, 40, 1, 1, 1]
B = [40, 182, 40, 182, 64, 64, 64]

# LaZer's tbox needs nprime > 0: a one-poly approximate l_inf proof as filler (e2 of the first leg).
nprime = 1
Bprime = 64
