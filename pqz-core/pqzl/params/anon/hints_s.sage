# -*- coding: utf-8 -*-
# R0-1 step 1 (pqz-core/research/code-review-2026-10-25/R0-1-auditor-shared-randomness.md, direction 2): the hint
# budget of one randomness group of s legs when the auditor's copies use DISTINCT coefficients of one pk_a^T r_g
# (leg j of the group: coefficients [16 (j mod s), 16 (j mod s) + 16)), per parameter set.
#
# Model (hints.sage's, per set): u = A^T r + e1, r CBD(1) (var 1/2), e1 CBD(20) (var 10), m = n + 16 samples; the
# set's n, q (set.toml) and BETA_S, BETA_E (pqz_set.h). Each recipient key gives 16 hints per leg; the auditor now gives
# 16 distinct forms per leg as well, so a group of s legs has 16 s + 16 s = 32 s worst-case hints with the auditor on
# (hints.sage: 16 s + 16, the auditor's copies repeating one key's 16 forms) and 16 s without (unchanged). The same three
# hint kinds as hints.sage section 2 (unit on r, unit on e1, orthogonal maximal-norm mixed forms with
# V_max = var_s BETA_E^2 + var_e BETA_S^2: the worst case), DDGR20 = leaky-LWE-Estimator 0a9caf8 DBDD_predict_diag +
# integrate_q_vectors; the mixed-hint closed form is hints.sage section 1 / hints_q.sage (hints-anon.txt), not re-run.
# dual_hybrid: lattice-estimator 53da598 has no hints, so (as n-study/enc_n.sage and p16k/dual_hints16k.sage) h hints
# are h removed secret dimensions, LWE(n - h, m = n + 16) [measured on that instance], and the worst case subtracts the
# offset (primal uSVP of n - h minus the DDGR20 mixed beta at h) [estimate].
#
# Run: SET=<set> SCRIPT=hints_s.sage run_hints.sh <lk 0a9caf8> <le 53da598> >> hints-s.txt (one set per container).
import os
import re
import sys
import math
import tomllib
from functools import lru_cache
from copy import deepcopy

LK_COMMIT = os.environ.get("LK_COMMIT", "unknown")
LE_COMMIT = os.environ.get("LE_COMMIT", "unknown")
assert LK_COMMIT.startswith("0a9caf8") and LE_COMMIT.startswith("53da598"), (LK_COMMIT, LE_COMMIT)
SET = os.environ["SET"]

os.chdir("/lk/framework")
load("/lk/framework/DBDD_predict_diag.sage")
_compute_delta = compute_delta  # memoized as in hints.sage (pure; makes d ~ 5600 tractable)
compute_delta = lru_cache(maxsize=None)(lambda k: RR(_compute_delta(k)))

from estimator import LWE, ND, RC
from estimator.lwe_parameters import LWEParameters
from estimator.reduction import ADPS16
from sage.version import version as SAGE_VERSION

toml = tomllib.load(open(f"/sets/{SET}/set.toml", "rb"))
hdr = open(f"/sets/{SET}/pqz_set.h").read()
N, Q = int(toml["n"]), Integer(toml["q"])
BETA_S = int(re.search(r"#define PQZ_BETA_S (\d+)", hdr).group(1))
BETA_E = int(re.search(r"#define PQZ_BETA_E (\d+)", hdr).group(1))
assert int(re.search(r"#define PQZ_N (\d+)", hdr).group(1)) == N and f"#define PQZ_Q {Q}ULL" in hdr
if os.environ.get("SMOKE"):  # code-path check only
    N = 512
M_SAMPLES = N + 16
VAR_S, VAR_E = 0.5, 10.0
V_MAX = VAR_S * BETA_E**2 + VAR_E * BETA_S**2
TARGET = 450
# today's 80-hint DDGR20 worst case per set (SET.md), to reproduce within 0.5 before anything else counts
H80 = {"n2048-kmax1024": 445.97, "n2304-kmax4096": 468.47, "n2560-kmax16384": 482.43, "n2816-kmax65536": 496.79}
# today's dual_hybrid at 80 hints - offset, cl. / qu. (SET.md; n2048 / n2816 were not measured)
D80 = {"n2304-kmax4096": (458.47, 461.47), "n2560-kmax16384": (474.43, 476.43)}
HINTS = [0, 16, 32, 48, 64, 80, 96, 128]
DUAL_HINTS = [0, 32, 64, 80, 96, 128]
MODELS = {"classical": RC.ADPS16, "quantum": ADPS16(mode="quantum")}
OK = "ok"  # a label: inside an f-string the Sage preparser rewrites a literal 450 (dual_hints16k.sage)


def hr(t):
    print("\n" + "=" * 100 + "\n" + t + "\n" + "=" * 100, flush=True)


def diag_instance(n, m, q, var_s, var_e):
    S = diagonal_matrix(RR, [var_e] * m + [var_s] * n + [0])
    inst = DBDD_predict_diag(None, S, None, verbosity=0, Bvol=float(m * math.log(q)))
    inst._q = q
    return inst


def unit(dim, i):
    v = [0] * dim
    v[i] = 1
    return v


def finish(inst):
    inst = deepcopy(inst)
    inst.integrate_q_vectors(inst._q)
    return float(inst.beta), inst.dim()


def lwe(n):
    return LWEParameters(n=n, q=Q, Xs=ND.CenteredBinomial(1), Xe=ND.CenteredBinomial(20), m=M_SAMPLES)


def usvp(p):
    return int(LWE.primal_usvp(p, red_cost_model=RC.ADPS16, red_shape_model="gsa")["beta"])


hr(f"{SET}: 0. Environment and calibration")
print(f"leaky-LWE-Estimator (DDGR20) commit: {LK_COMMIT}\nlattice-estimator commit: {LE_COMMIT}")
print(f"SageMath {SAGE_VERSION}, Python {sys.version.split()[0]}")
print(f"set {SET}: n = {N}, q = {Q} (log2 {float(math.log2(Q)):.3f}), m = n + 16 = {M_SAMPLES}, BETA_S = {BETA_S}, "
      f"BETA_E = {BETA_E}, V_max = {V_MAX:g}")
from estimator import schemes
ky = schemes.Kyber512
kb, kd = finish(diag_instance(512, 512, 3329, 1.5, 1.5))
print(f"Kyber-512: DDGR20 beta = {kb:.2f} (dim {kd}); lattice-estimator primal_usvp beta = "
      f"{int(LWE.primal_usvp(ky, red_cost_model=RC.ADPS16, red_shape_model='gsa')['beta'])}", flush=True)

hr(f"{SET}: 1. DDGR20 beta per number of perfect hints on one (r_g, e1_g)")
rows = {}
for kind in ("r", "e1", "mixed"):
    inst = diag_instance(N, M_SAMPLES, Q, VAR_S, VAR_E)
    dim = M_SAMPLES + N
    done = 0
    for h in HINTS:
        while done < h:
            if kind == "e1":
                inst.integrate_perfect_hint(unit(dim, done), 0)
            else:
                inst.integrate_perfect_hint(unit(dim, M_SAMPLES + done), 0)
                if kind == "mixed":  # w^T Sigma w = V_max instead of var_s (hints.sage section 1)
                    inst.Bvol += 0.5 * math.log(V_MAX / VAR_S)
            done += 1
        rows.setdefault(h, {})[kind] = finish(inst)[0]
        print(f"  [{kind} {h}: {rows[h][kind]:.2f}]", flush=True)
print(f"{'hints':>5s} {'unit on r':>10s} {'unit on e1':>11s} {'mixed (worst)':>14s}")
for h in HINTS:
    print(f"{h:5d} {rows[h]['r']:10.2f} {rows[h]['e1']:11.2f} {rows[h]['mixed']:14.2f}")
rep = abs(rows[80]["mixed"] - H80[SET]) <= 0.5
print(f"reproduction: mixed at 80 hints {rows[80]['mixed']:.2f} vs SET.md {H80[SET]:.2f} -> "
      f"{'reproduces (within 0.5)' if rep else 'DOES NOT REPRODUCE'}", flush=True)

hr(f"{SET}: 2. dual_hybrid on the hinted instance: LWE(n - h, m = n + 16) [measured], minus the DDGR20 offset [estimate]")
print(f"{'hints':>5s} {'primal n-h':>10s} {'dual cl.':>9s} {'dual qu.':>9s} {'DDGR20 mixed':>13s} {'offset':>7s} "
      f"{'dual cl. - off':>15s} {'dual qu. - off':>15s}", flush=True)
dual = {}
for h in DUAL_HINTS:
    p = lwe(N - h)
    pu = usvp(p)
    d = [int(LWE.dual_hybrid(p, red_cost_model=m)["beta"]) for m in MODELS.values()]
    off = pu - rows[h]["mixed"]
    dual[h] = (d[0] - off, d[1] - off)
    print(f"{h:5d} {pu:10d} {d[0]:9d} {d[1]:9d} {rows[h]['mixed']:13.2f} {off:7.2f} {dual[h][0]:15.2f} "
          f"{dual[h][1]:15.2f}", flush=True)
if SET in D80:
    rd = max(abs(a - b) for a, b in zip(dual[80], D80[SET]))
    print(f"reproduction: dual_hybrid - offset at 80 hints {dual[80][0]:.2f} / {dual[80][1]:.2f} vs SET.md "
          f"{D80[SET][0]:.2f} / {D80[SET][1]:.2f} -> {'reproduces (within 0.5)' if rd <= 0.5 else 'DOES NOT REPRODUCE'}")
else:
    print("reproduction: no earlier dual_hybrid value at 80 hints for this set (SET.md: not measured)")

hr(f"{SET}: 3. Group of s legs: hints with the auditor's forms distinct (32 s) vs today's model (16 s + 16)")
print(f"{'s':>2s} {'auditor':>8s} {'hints':>6s} {'DDGR20 mixed':>13s} {'dual cl./qu. - off':>19s} {OK:>4s}   "
      f"{'today: hints':>12s} {'DDGR20 mixed':>13s}")
best = {}
for A in (1, 0):
    for s in (1, 2, 3, 4):
        h = 32 * s if A else 16 * s
        old = 16 * s + 16 if A else 16 * s
        b = rows[h]["mixed"]
        dd = dual.get(h)
        ok = b >= TARGET and (dd is None or min(dd) >= TARGET)
        if ok:
            best[A] = s
        ds = f"{dd[0]:.2f} / {dd[1]:.2f}" if dd else "-"
        print(f"{s:2d} {('on' if A else 'off'):>8s} {h:6d} {b:13.2f} {ds:>19s} {('yes' if ok else 'NO'):>4s}   "
              f"{old:12d} {rows[old]['mixed']:13.2f}")
print(f"largest s in (1..4) with DDGR20 and dual_hybrid - offset >= 450: auditor on {best.get(1, 0)}, "
      f"auditor off {best.get(0, 0)} (no dual value at 16 / 48 hints: DDGR20 only there)")
print("done", flush=True)
