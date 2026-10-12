# R_REG (pq-zether.md §7.2 step 6): pk = A s + e, ||s|| <= 36, ||e|| <= 164.
# Witness s1 = (s, e): 64 polys of R_q, q = 2^42 - 215, d = 64.
pqz_verbose = 1
name = "pqz_reg"
q_fixed = 2^42 - 215    # CTR-PQZ-03, proof modulus = q (CTR-PQZ-09)
pqz_L = 4               # X^64 + 1 splits into 4 factors mod q
log2q = 42
pqz_delta = 1.00366       # root-Hermite factor at beta ~ 450 (CTR-PQZ-03 target), checked by e_s1_proof.sage
d = 64

m1 = 64                 # s (32) || e (32)
alpha = sqrt(36^2 + 164^2)
l = 0

nbin = 0
n = [32, 32]
B = [36, 164]

nprime = 0
Bprime = 0
