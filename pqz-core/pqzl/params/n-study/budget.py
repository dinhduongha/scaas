#!/usr/bin/env python3
"""Plan 5h Task 7c (n-study, research): the noise and digit budget of spec 2026-10-20 §6.1 over the grid
n in {2048, 2176, 2304, 2432, 2560} x K_MAX in {1,024, 4,096, 8,192, 16,384}, the smallest q per cell and a concrete
prime, plus the stdlib uSVP shortcut of ../anon/usvp.py (hints as removed dimensions) as the first cheap screen.

Budget (../aprime/aprime.sage `budget`, unchanged formulas): norm bounds at today's distance above the mean
(beta_s 12.02 s.d. CBD(1), beta_e 10.15 s.d. CBD(20)); B = 2 beta_e beta_s + 64; m = bitlen(15 K) (15 K < 2^m);
E = 2^ceil(log2(K B)); Delta = floor(q / 2^(m+2)); uniqueness 2E <= Delta; centring Delta (2^m - 1) + E < q/2;
K B <= E; mint margin (Delta - E) / ((K - 1) B).
Two q per cell:
  q3: the smallest admissible prime with mint margin >= 3.08 (the lowest margin the owner accepted, O3 2026-10-19;
      the approved 16k set has 3.36, today 4.14) -- the primary candidate;
  q1: the smallest admissible prime at all (2E <= Delta; margin then 1.0-2.0) -- the "bare budget" variant, shown
      to price the margin in beta.
Admissible prime (spec §6.5): q = 9 mod 16 (PQZL: l = 4) and 2^3 * 19 * 43 * 431 | q - 1 (PQZH: today's radices),
i.e. q = 1 + 2,817,016 t with t odd; Miller-Rabin with the 12 smallest prime bases (deterministic below 3.3e24).
Also: Z_q-amortisation repetitions lambda = ceil(128 / log2 q), 64-bit lanes 2^64 / q.

Stdlib only:  python3 -I pqz-core/pqzl/params/n-study/budget.py > pqz-core/pqzl/params/n-study/budget.txt
(writes cells.json next to this file for screen.sage).
"""
import json
import math
import os
from math import e, log, pi, sqrt

NS = (2048, 2176, 2304, 2432, 2560)
KS = (1024, 4096, 8192, 16384)
MARGIN = 3.08
RADIX = 2**3 * 19 * 43 * 431          # 2,817,016
Q16K = 2**50 - 42_310_535             # the approved 16k prime (calibration row)
HERE = os.path.dirname(os.path.abspath(__file__))


def is_prime(n):
    if n < 2 or n % 2 == 0:
        return n == 2
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


def norm_bounds(n):
    bs = math.ceil(math.sqrt(n / 2 + 12.02 * math.sqrt(n / 4)))
    be = math.ceil(math.sqrt(10 * n + 10.15 * math.sqrt(195 * n)))
    return bs, be


def budget(n, K, q):
    bs, be = norm_bounds(n)
    B = 2 * be * bs + 64
    m = int(15 * K).bit_length()
    E = 2**math.ceil(math.log2(K * B))
    D = q // 2**(m + 2)
    ok = 2 * E <= D and D * (2**m - 1) + E < q // 2 and K * B <= E
    return dict(n=n, k=n // 64, K=K, bs=bs, be=be, B=B, m=m, E=E, e_bits=int(math.log2(E)), q=q, D=D, ok=ok,
                margin=(D - E) / ((K - 1) * B), lam=math.ceil(128 / math.log2(q)), lanes=2**64 // q,
                bits_tx=64 + 64 + 16 * m + 15 * (m - 3) + 16 * (int(math.log2(E)) + 1))


def smallest_q(n, K, margin):
    """the smallest admissible prime whose budget holds with mint margin >= margin"""
    bs, be = norm_bounds(n)
    B = 2 * be * bs + 64
    m = int(15 * K).bit_length()
    E = 2**math.ceil(math.log2(K * B))
    dmin = max(2 * E, E + math.ceil(margin * (K - 1) * B))
    t = max(1, (dmin * 2**(m + 2) - 1) // RADIX)
    t += 1 - t % 2                     # t odd: q - 1 = 8 mod 16
    while True:
        q = 1 + RADIX * t
        b = budget(n, K, q)
        if b["ok"] and b["margin"] >= margin and is_prime(q):
            assert q % 16 == 9 and (q - 1) % RADIX == 0
            return q
        t += 2


# ../anon/usvp.py (ADPS16 primal uSVP, GSA), unchanged
def delta(b):
    return ((pi * b)**(1 / b) * b / (2 * pi * e))**(1 / (2 * (b - 1)))


def usvp_beta(n, q, ss, se, mmax):
    best = None
    for m in range(max(1, n // 4), mmax + 1, 16):
        d = m + n + 1
        lv = (m * log(q) + n * log(se / ss)) / d
        for b in range(50, 2000):
            if log(se * sqrt(b)) <= (2 * b - d - 1) * log(delta(b)) + lv:
                if best is None or b < best:
                    best = b
                break
    return best


def shortcut(n, q):
    return {h: usvp_beta(n - h, q, sqrt(.5), sqrt(10), n + 48) for h in (0, 32, 80)}


def main():
    cells = []
    print("Task 7c n-study: budget per (n, K_MAX), q3 = smallest admissible prime with mint margin >= 3.08, q1 = smallest")
    print("admissible prime (2E <= Delta); uSVP shortcut = ../anon/usvp.py, h hints as h removed dimensions, m <= n + 48")
    print("| n | k | K_MAX | b_s / b_e | B | m | log2 E | variant | q | log2 q | Delta | margin | lambda | R_TX bits"
          " | uSVP shortcut h0 / h32 / h80 |")
    print("|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|")
    rows = [(n, K, v) for n in NS for K in KS for v in ("q3", "q1")] + [(2560, 16384, "16k")]
    for n, K, v in rows:
        q = Q16K if v == "16k" else smallest_q(n, K, MARGIN if v == "q3" else 1.0)
        b = budget(n, K, q)
        assert b["ok"] and is_prime(q) and q % 16 == 9 and (q - 1) % RADIX == 0
        b["variant"] = v
        b["shortcut"] = shortcut(n, q)
        cells.append(b)
        s = b["shortcut"]
        print(f"| {n} | {b['k']} | {K:,} | {b['bs']} / {b['be']} | {b['B']:,} | {b['m']} | {b['e_bits']} | {v} | {q} | "
              f"{math.log2(q):.3f} | 2^{math.log2(b['D']):.3f} | {b['margin']:.2f}x | {b['lam']} | {b['bits_tx']} | "
              f"{s[0]} / {s[32]} / {s[80]} |", flush=True)
    with open(os.path.join(HERE, "cells.json"), "w") as f:
        json.dump(cells, f, indent=1)
    print("\ncells.json written: %d rows" % len(cells))


if __name__ == "__main__":
    # self-check: the approved 16k prime and today's set pass the same budget
    assert budget(2560, 16384, Q16K)["ok"] and abs(budget(2560, 16384, Q16K)["margin"] - 3.36) < 0.01
    assert budget(2048, 1024, 2**42 - 215)["ok"] and abs(budget(2048, 1024, 2**42 - 215)["margin"] - 4.14) < 0.01
    assert norm_bounds(2048) == (36, 164) and norm_bounds(2304) == (38, 173) and norm_bounds(2560) == (40, 182)
    assert usvp_beta(512, 3329, sqrt(1.5), sqrt(1.5), 1024) == 406     # usvp.py's Kyber-512 calibration
    main()
