# R_DS (pq-zero-knowledge.md §7.9, SENDER_S): u = A^T r + e1, v_t[i] = (pk_t^T r)[i] + e2_t[i] + Delta digits(amount)_i.
# Witness s1 = r, e1 (32 polys each), e2_t (1 poly, 16 used coefficients); no binary part.
pqz_verbose = 1
name = "pqz_ds"
q_fixed = 2^42 - 215
pqz_L = 4
log2q = 42
pqz_delta = 1.00366       # root-Hermite factor at beta ~ 450 (CTR-PQZ-03 target), checked by e_s1_proof.sage
d = 64

m1 = 32 * 2 + 1
alpha = sqrt(36^2 + 164^2 + 64^2)
l = 0

nbin = 0
n = [32, 32, 1]
B = [36, 164, 64]

# LaZer's tbox needs nprime > 0 (see codegen): a one-poly approximate l_inf proof as filler
# (e2_t, |coefficients| <= 20 < 64).
nprime = 1
Bprime = 64
