# R_TXM sizing sketch (P6-ANON research, docs/research/pqz-anonymity.md §7): PQZ multi-recipient transfer,
# M = 2 legs (decoys = legs of amount 0), 1 randomness group(s), auditor on (one auditor copy per leg).
# s1 = s_f, e_f, (r_g, e1_g) per group (32 polys each), e2 of the M legs (one block, M polys, bound 64*sqrt(M)),
# e2_f (1 poly), auditor e2 of the M legs (one block), 16 binary polys (R_TX's 917 bits - 64 + 64 per leg).
pqz_verbose = 1
name = "pqz_txm2"
q_fixed = 2^42 - 215
pqz_L = 4
log2q = 42
pqz_delta = 1.00366
d = 64

m1 = 32 * 4 + 2 * 2 + 1 + 16
alpha = sqrt(2 * (36^2 + 164^2) + (2 * 2 + 1) * 64^2 + 16 * 64)
l = 0

nbin = 16
n = [32, 32, 32, 32, 2, 1, 2]
B = [36, 164, 36, 164, 64 * sqrt(2), 64, 64 * sqrt(2)]

nprime = 1
Bprime = 64
