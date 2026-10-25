# -*- coding: utf-8 -*-
"""Plan 5h Task 8b: e_s0 of one parameter set, per relation (owner 2026-10-21: e_s0 exactness for every relation incl.
txm4 / txm8). pqz-core/pqzl/params/n-study/e_s0_n.py (itself ../p16k/e_s0_16k.py, ../e_s0.py parts 0, 3a, 4, 5) with
the set's constants read from sets/<set>/pqz_set.h (gen_set.py) and, per relation, the spec (m1, alpha, nbin) and the
codegen header (stdev3, challenge omega / eta, knowledge error) of sets/<set>/; checks unchanged:
  part 0  the set's budget checks (§4.3);
  part 3a challenge space of each header's (omega, eta) (sampled, LNP22 4.4), 2 omega below the LS18 bound: |C| counts
          the set the cores sample since the R0 review fix (R0-C3), c autostable with sqrt(||o(c) c||_1) <= eta (the
          resampled challenge: lazer poly.c poly_urandom_challenge, Rust Poly::urandom_challenge); the operator norm
          max_j |c(zeta_j)| <= eta (the bound the extractor's argument uses, implied by the l1 one) is printed beside it;
  part 4  exactness of the norm proofs per relation: the JL-extracted bound b' = 2 sqrt(512) s3 / sqrt(30) with
          s3 = the larger of e_s0.py's 11 sqrt(337) alpha and the header's stdev3; b'^2 + beta_e^2 < q,
          41 (m1 d) b' < q, binary rows < q;
  part 5  per-round Fiat-Shamir soundness (R1 JL, R2 q^-lambda with lambda read from each header's quad_eval
          parameters, even and lambda log2 q >= 128 (review R0-2 / R0-C7), R3 q^-16, R4 the relation's 2/|C|) and the
          header's knowledge error.
Stdlib + numpy; in the pinned Sage image (numpy pinned with it):
  SET=<set> scripts/capped pqz-core/params/sets/run_e_s0_set.sh > pqz-core/params/sets/<set>/e-s0.txt
"""
import glob
import math
import os
import re
import sys
from math import comb, log2, sqrt

import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
SET = os.environ["SET"]
SD = os.path.join(HERE, SET)
H = {m[0]: int(m[1]) for m in re.findall(r"#define PQZ_(\w+) \(?(?:\(int64_t\))?(\d+)", open(os.path.join(SD, "pqz_set.h")).read())}
d, k, q, l = 64, H["K"], H["Q"], 4
DELTA, K_MAX, M_BITS, C_BITS, ET_BITS = H["DELTA"], H["K_MAX"], H["MBITS"], H["CBITS"], H["EBITS"]
BETA_S, BETA_E, BETA_2 = H["BETA_S"], H["BETA_E"], H["BETA_2"]
E = 2**(ET_BITS - 1)
GAMMA = 11
ok = True


def hr(title):
    print("\n" + "=" * 100 + "\n" + title + "\n" + "=" * 100, flush=True)


def lg(x):
    return float(log2(float(x)))


def is_prime(n):
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


def check(name, cond):
    global ok
    ok &= bool(cond)
    print(f"{name}: {'OK' if cond else 'MISS'}")


def rel(spec):
    s = open(spec).read()
    name = re.search(r'name = "pqz_(\w+)"', s)[1]
    m1 = int(re.search(r"^m1 = (\d+)", s, re.M)[1])
    alpha = eval(re.search(r"^alpha = (.*)$", s, re.M)[1].replace("^", "**"), {"sqrt": sqrt})
    nbin = int(re.search(r"^nbin = (\d+)", s, re.M)[1])
    h = open(os.path.join(SD, f"pqz_{name}_params.h")).read()
    st3 = float(re.search(r"stdev3 = ([\d.]+)", h)[1])
    om, eta = map(int, re.search(r"\[-omega,omega\] = \[-(\d+),\d+\].*eta = (\d+)", h).groups())
    ke = float(re.search(r"knowledge error <= 2\^\(([-\d.]+)\)", h)[1])
    assert int(re.search(r"s1: m1 = (\d+)", h)[1]) == m1
    # lambda: the last field of the relation's lnp_quad_eval_params_t (the cores read it there)
    lam = int(re.search(r"lnp_quad_eval_params_t pqz_%s_quad_eval = \{\{[^}]*, (\d+)\}\};" % name, h)[1])
    return name, m1, alpha, nbin, st3, om, eta, ke, lam


RELS = [rel(p) for p in sorted(glob.glob(os.path.join(SD, "*_params.sage")))]
if len(RELS) != 14:
    print(f"the set has {len(RELS)} relation specs, not 14: MISS")
    ok = False

hr(f"0. Set {SET}: n = {k * d}, K_MAX = {K_MAX:,}, q = {q} (pqz_set.h; pq-zero-knowledge.md §4.3)")
print(f"Python {sys.version.split()[0]}, numpy {np.__version__}")
check(f"q = 2^{lg(q):.3f} prime, q mod 16 = {q % 16} (l = {l})", is_prime(q) and q % 16 == 9)
check(f"Delta = floor(q / 2^{M_BITS + 2}) = {DELTA} = 2^{lg(DELTA):.3f}", DELTA == q // 2**(M_BITS + 2))
ls18 = q ** (1 / l) / sqrt(l)
print(f"LS18 Cor. 1.2 invertibility bound q^(1/l)/sqrt(l) = {ls18:.1f} (l_inf)")
b_fresh = 2 * BETA_E * BETA_S + BETA_2
check(f"B_FRESH = {b_fresh}; K_MAX * B_FRESH = {K_MAX * b_fresh} <= E = 2^{ET_BITS - 1}", K_MAX * b_fresh <= E)
check(f"15 K_MAX = {15 * K_MAX} < 2^{M_BITS} (digit sums M_i)", 15 * K_MAX < 2**M_BITS)
check(f"uniqueness 2E = 2^{ET_BITS} <= Delta", 2 * E <= DELTA)
check(f"centring Delta (2^{M_BITS} - 1) + E = 2^{lg(DELTA * (2**M_BITS - 1) + E):.3f} < q/2", DELTA * (2**M_BITS - 1) + E < q // 2)
print(f"mint margin (Delta - E) / ((K - 1) B_FRESH) = {(DELTA - E) / ((K_MAX - 1) * b_fresh):.2f}x")
print(f"Delta parity: {'even' if DELTA % 2 == 0 else 'odd'} (an even Delta allows a rounding tie at |noise| = Delta / 2 "
      f"= 2^{lg(DELTA / 2):.2f}; honest noise < E = 2^{ET_BITS - 1})")

hr("3a. Challenge space of each relation's header (LNP22 4.4), 2 omega below the LS18 bound")
theta = [math.pi * (2 * j + 1) / d for j in range(d // 2)]
EMB = np.array([[1.0] + [2 * math.cos(i * t) for i in range(1, d // 2)] for t in theta])


def l1_ocsq(c):
    """||o(c) c||_1 of autostable challenges c (rows: c_0 .. c_31 as sampled; c_32 = 0, c_(64-i) = -c_i): o(c) = c, so
    the negacyclic square, by an exact float FFT (|coefficients| <= 64 * 8^2)"""
    out = []
    for c in np.array_split(c, max(1, c.shape[0] // 20_000)):  # chunks: the run's --memory 1g
        full = np.zeros((c.shape[0], d))
        full[:, :d // 2] = c
        full[:, d // 2 + 1:] = -c[:, :0:-1]
        lin = np.rint(np.fft.irfft(np.fft.rfft(full, 2 * d) ** 2, 2 * d))
        out.append(np.abs(lin[:, :d] - lin[:, d:]).sum(axis=1))
    return np.concatenate(out)


chal = {}
for om, eta in sorted({(r[5], r[6]) for r in RELS}):
    rng = np.random.default_rng(20261013)
    c = rng.integers(-om, om + 1, size=(200_000, d // 2))
    acc_op = float((np.abs(c @ EMB.T).max(axis=1) <= eta).mean())
    l1 = l1_ocsq(c)
    acc = float((l1 <= eta * eta).mean())
    logc = (d // 2) * log2(2 * om + 1) + log2(acc)
    chal[om, eta] = logc
    check(f"omega = {om}, eta = {eta}: P(sqrt ||o(c) c||_1 <= eta) = {acc:.4f} (the sampled set; operator norm "
          f"<= eta: {acc_op:.4f}), |C| = 2^{logc:.2f}, 2/|C| = 2^-{logc - 1:.2f}, 2 omega = {2 * om} < {ls18:.0f}",
          2 * om < ls18 and logc - 1 >= 128)
    # every filtered challenge meets the operator-norm bound (sqrt of the l1 norm of c^2 bounds |c(zeta)|)
    sel = l1 <= eta * eta
    check("  every challenge of the sampled set has max |c(zeta_j)| <= eta", bool((np.abs(c[sel] @ EMB.T).max(axis=1) <= eta).all()))

hr("4. Exactness of the norm proofs per relation (no wrap-around mod q)")
print(f"{'rel':7s} {'m1':>4s} {'alpha':>8s} {'nbin':>4s} {'s3 e_s0':>10s} {'stdev3':>10s} {'log2 b_':>7s} "
      f"{'l2: b^2+be^2':>12s} {'JL: 41 N b':>11s}  (log2; q = 2^{lg(q):.2f})")
for name, m1, alpha, nbin, st3, om, eta, ke, lam in RELS:
    s3 = max(GAMMA * sqrt(337) * alpha, st3)
    b = 2 * sqrt(2 * 256) * s3 / sqrt(30)
    l2, jl = b**2 + BETA_E**2, 41 * m1 * d * b
    good = l2 < q and jl < q
    ok &= good
    print(f"{name:7s} {m1:4d} {alpha:8.1f} {nbin:4d} {GAMMA * sqrt(337) * alpha:10.4g} {st3:10.4g} {lg(b):7.2f} "
          f"{lg(l2):12.2f} {lg(jl):11.2f}  {'OK' if good else 'MISS'}")
check(f"binary rows: largest reconstructed integer 2^{ET_BITS} (e_T + E) < q", 2**ET_BITS < q)
check(f"row 7 terms |M_i + c_(i-1) - d'_i - d_i - 16 c_i| < 2^{M_BITS + 1} < q", 2**(M_BITS + 1) < q)
check(f"R_DR: e' + E in {ET_BITS} bits, Delta d + e' < q", DELTA * 15 + 2**ET_BITS < q)

hr("5. Per-round Fiat-Shamir soundness (LNP22 rounds, each on its own) and the headers' knowledge error")
jl_unit = log2(sum(comb(256, i) for i in range(30))) - 256
lams = sorted({r[8] for r in RELS})
LAM = min(lams)  # every header's lambda (review R0-2 / R0-C7: read, not computed)
check(f"lambda of every header {lams}: even, lambda log2 q = {LAM * log2(q):.2f} >= 128",
      all(x % 2 == 0 for x in lams) and LAM * log2(q) >= 128)
rounds = [("R1 JL projection R <- Bin^{256 x N} (LNP22 JL lemma, < 2^-128)", 128.0, f"unit-vector case 2^{jl_unit:.2f}"),
          (f"R2 Z_q amortization, lambda = {LAM} repetitions (q^-lambda, the headers')", LAM * log2(q), ""),
          (f"R3 R_q aggregation of quadratic relations (q^-(d/l) = q^-{d // l})", (d // l) * log2(q), "")]
for name, bits, note in rounds:
    print(f"{name:72s} {bits:8.2f} bits {'OK' if bits >= 128 else 'MISS'}  {note}")
    ok &= bits >= 128
for name, m1, alpha, nbin, st3, om, eta, ke, lam in RELS:
    r4 = chal[om, eta] - 1
    good = r4 >= 128 and ke <= -127
    ok &= good
    print(f"R4 {name:7s} c in [-{om},{om}], eta {eta}: 2/|C| = 2^-{r4:.2f}; header knowledge error 2^{ke}: "
          f"{'OK' if good else 'MISS'}")
print(f"\nGATE ({SET}: set checks, exactness and FS rounds of {len(RELS)} relations): {'MET' if ok else 'MISSED'}")
