# -*- coding: utf-8 -*-
"""Plan 5h Task 7: ../e_s0.py's parameter checks, challenge space, exactness of the norm proofs (part 4) and per-round
Fiat-Shamir soundness (part 5) at the 16k candidate: n = 2560 (k = 40), q = 2^50 - 42,310,535, Delta = 2^30 - 41,
beta_s / beta_e = 40 / 182, K_MAX = 16,384, M_i < 2^18, carries 15 bits, e_T + 2^28 in 29 bits (plan D16, owner Q1).

The estimator parts of e_s0.py (1-3) are replaced at 16k by enc16k.sage (encryption), run_hints16k.sh (DDGR20) and
e_s1_16k.sage (the LaZer proof instances). Stdlib + numpy; run in the pinned Sage image:
  scripts/capped pqz-core/pqzl/params/p16k/run_e_s0_16k.sh > pqz-core/pqzl/params/p16k/e-s0-16k.txt
"""
import math
import sys
from math import comb, log2, sqrt

import numpy as np

d, k = 64, 40
q = 2**50 - 42_310_535
l = 4
DELTA = 2**30 - 41
BETA_S, BETA_E, BETA_2 = 40, 182, 64
K_MAX = 16_384
M_BITS, C_BITS, ET_BITS = 18, 15, 29          # M_i < 2^18, c_i + 64 < 2^15, e_T + 2^28 < 2^29
E = 2**28
ROLL_MAX_BOUND, INLINE_MAX = 2**14, 16        # Solidity: 64-bit lanes hold 2^64 / q terms


def hr(title):
    print("\n" + "=" * 100 + "\n" + title + "\n" + "=" * 100, flush=True)


def lg(x):
    return float(log2(float(x)))


def is_prime(n):
    if n % 2 == 0:
        return n == 2
    dd, s = n - 1, 0
    while dd % 2 == 0:
        dd, s = dd // 2, s + 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):   # deterministic below 3.3e24
        x = pow(a, dd, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


ok = True


def check(name, cond):
    global ok
    ok &= bool(cond)
    print(f"{name}: {'OK' if cond else 'MISS'}")


hr("0. Environment and the 16k parameter checks (pq-zero-knowledge.md §4.3 with K = 16,384)")
print(f"Python {sys.version.split()[0]}, numpy {np.__version__}")
check(f"q = 2^50 - 42,310,535 = {q} prime, q mod 16 = {q % 16} (l = {l})", is_prime(q) and q % 16 == 9)
check(f"Delta = floor(q / 2^20) = {q // 2**20} = 2^30 - 41", DELTA == q // 2**20 == 2**30 - 41)
ls18 = q ** (1 / l) / sqrt(l)
print(f"LS18 Cor. 1.2 invertibility bound q^(1/l)/sqrt(l) = {ls18:.1f} (l_inf; today 724)")
b_fresh = 2 * BETA_E * BETA_S + BETA_2
check(f"B_FRESH = {b_fresh}; K_MAX * B_FRESH = {K_MAX * b_fresh} <= E = 2^28", K_MAX * b_fresh <= E)
check(f"15 K_MAX = {15 * K_MAX} < 2^{M_BITS} (digit sums M_i)", 15 * K_MAX < 2**M_BITS)
check(f"uniqueness 2E = 2^29 <= Delta", 2 * E <= DELTA)
check(f"centring Delta (2^18 - 1) + E = 2^{lg(DELTA * (2**M_BITS - 1) + E):.3f} < q/2", DELTA * (2**M_BITS - 1) + E < q // 2)
print(f"mint margin (Delta - E) / ((K - 1) B_FRESH) = {(DELTA - E) / ((K_MAX - 1) * b_fresh):.2f}x (today 4.14x)")
check(f"Solidity lanes: 2^64 / q = 2^{64 - lg(q):.3f} terms >= ROLL_MAX + 1 + INLINE_MAX for ROLL_MAX < 2^14 - 17",
      2**64 // q >= ROLL_MAX_BOUND - 1)

hr("3a. Challenge space (LNP22 4.4; independent of q, re-checked against the 16k LS18 bound)")
theta = [math.pi * (2 * j + 1) / d for j in range(d // 2)]
EMB = np.array([[1.0] + [2 * math.cos(i * t) for i in range(1, d // 2)] for t in theta])
rng = np.random.default_rng(20261013)
chal = {}
for kappa in range(6, 10):
    c = rng.integers(-kappa, kappa + 1, size=(200_000, d // 2))
    op = np.abs(c @ EMB.T).max(axis=1)
    eta = int(math.ceil(np.quantile(op, 0.99)))
    acc = float((op <= eta).mean())
    logc = (d // 2) * log2(2 * kappa + 1) + log2(acc)
    chal[kappa] = (eta, acc, logc)
    print(f"kappa = {kappa}: eta = {eta}, |C| = 2^{logc:.2f}, 2/|C| = 2^-{logc - 1:.2f}, 2 kappa = {2 * kappa} < {ls18:.0f}: "
          f"{2 * kappa < ls18}")
KAPPA = min(kk for kk, v in chal.items() if v[2] - 1 >= 128)
ETA, _, LOGC = chal[KAPPA]
check(f"=> kappa = {KAPPA}, eta = {ETA}; 2 kappa < LS18 bound", 2 * KAPPA < ls18)

# R_TX witness at 16k: s_f, e_f, r, e1 (40 each), e2_t/f/a, the 1,105 binary digits (18 polys: d 64, d' 64, M 16x18,
# c 15x15, e_T 16x29) and the slack bits of 7 exact l2 proofs (7 x 16 bits, as e_s0.py)
BITS = 64 + 64 + 16 * M_BITS + 15 * C_BITS + 16 * ET_BITS
M1 = 4 * k + 3 + math.ceil(BITS / d) + math.ceil(7 * 16 / d)
ALPHA = sqrt(2 * BETA_S**2 + 2 * BETA_E**2 + 3 * BETA_2**2 + BITS + 7 * 16)
LAM = math.ceil(128 / log2(q))
GAMMA = 11
print(f"R_TX: {BITS} bits, m1 = {M1} ring elements ({M1 * d} coefficients), ||s1|| <= alpha = {ALPHA:.1f}; "
      f"lambda = {LAM} (q^-{LAM} = 2^-{LAM * log2(q):.2f})")

hr("4. Exactness of the norm proofs (no wrap-around mod q)")
s3 = GAMMA * sqrt(337) * ALPHA
b_jl = 2 * sqrt(2 * 256) * s3 / sqrt(30)
N_JL = M1 * d
print(f"JL extracted bound b' = 2 sqrt(512) s3 / sqrt(30) = {b_jl:.4g} = 2^{lg(b_jl):.2f}")
check(f"exact l2: b'^2 + beta_e^2 = 2^{lg(b_jl**2 + BETA_E**2):.2f} < q = 2^{lg(q):.2f}", b_jl**2 + BETA_E**2 < q)
check(f"modular JL: 41 * N * b' = 2^{lg(41 * N_JL * b_jl):.2f} < q", 41 * N_JL * b_jl < q)
check(f"binary rows: largest reconstructed integer 2^{ET_BITS} (e_T + 2^28) < q", 2**ET_BITS < q)
check(f"row 7 terms |M_i + c_(i-1) - d'_i - d_i - 16 c_i| < 2^{M_BITS + 1} < q", 2**(M_BITS + 1) < q)
check(f"R_DR: e' + 2^28 in 29 bits, Delta d + e' < q", DELTA * 15 + 2**ET_BITS < q)

hr("5. Per-round Fiat-Shamir soundness (LNP22 rounds, each on its own)")
jl_unit = log2(sum(comb(256, i) for i in range(30))) - 256
rounds = [
    ("R1 JL projection R <- Bin^{256 x N} (LNP22 JL lemma, < 2^-128)", 128.0, f"unit-vector case 2^{jl_unit:.2f}"),
    (f"R2 Z_q amortization, lambda = {LAM} repetitions (q^-lambda)", LAM * log2(q), ""),
    (f"R2 with lambda = {LAM - 1} (for reference)", (LAM - 1) * log2(q), "not used"),
    (f"R3 R_q aggregation of quadratic relations (q^-(d/l) = q^-{d // l})", (d // l) * log2(q), ""),
    (f"R4 final challenge c in C, kappa = {KAPPA}, eta = {ETA} (2/|C|)", LOGC - 1, ""),
]
for name, bits, note in rounds:
    print(f"{name:72s} {bits:8.2f} bits {'OK' if bits >= 128 else 'MISS'}  {note}")
ok &= all(bits >= 128 for name, bits, note in rounds if "reference" not in name)
print(f"\nGATE (16k checks, exactness, FS rounds): {'MET' if ok else 'MISSED'}")
