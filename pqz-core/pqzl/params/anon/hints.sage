# -*- coding: utf-8 -*-
# P6-ANON Task S1 (plan docs/superpowers/plans/2026-10-14-p6-anon.md, D4): DDGR20 perfect hints on one shared
# encryption randomness (r, e1) of the multi-recipient transfer R_TXM, per hint count, per M and leg grouping.
#
# Run by run_hints.sh in the pinned Sage image with the pinned leaky-LWE-Estimator (DDGR20, lducas/leaky-LWE-Estimator
# 0a9caf8) mounted at /lk and lattice-estimator 53da598 at /le; stdout is hints-anon.txt.
#
# Instance (pq-zero-knowledge.md CTR-PQZ-03 / -04): u = A^T r + e1, r in R_q^32 CBD(1) (n = 2048, var 1/2), e1 CBD(20)
# (var 10), q = 2^42 - 215, m = 2048 + 16 samples (u and the sender's own v_f in group 0; conservative for the other
# groups). A recipient key pk = A s + e yields 16 hints <(e, -s), (r, e1)> per leg (one per coefficient of v); the M
# auditor copies of a group repeat one key's 16 forms. Hints per group of L legs: 16 L (+ 16 with the auditor).
# Three hint kinds: 16 h unit hints on r, unit hints on e1, and the worst case of pqz-core/params/e_s0.py part 2:
# h orthogonal maximal-norm mixed forms (V_max = var_s 164^2 + var_e 36^2 = 26408).
import os
import sys
from functools import lru_cache
from copy import deepcopy

LK_COMMIT = os.environ.get("LK_COMMIT", "unknown")
LE_COMMIT = os.environ.get("LE_COMMIT", "unknown")
assert LK_COMMIT.startswith("0a9caf8") and LE_COMMIT.startswith("53da598"), (LK_COMMIT, LE_COMMIT)

os.chdir("/lk/framework")  # the framework loads its siblings as ../framework/*.sage
load("/lk/framework/DBDD_predict_diag.sage")
load("/lk/framework/DBDD_predict.sage")

# compute_delta (utils.sage) evaluates pi and e symbolically on every call and compute_beta_delta calls it for every
# beta in [2, d); memoizing the pure function keeps its values and makes d ~ 4100 tractable.
_compute_delta = compute_delta
compute_delta = lru_cache(maxsize=None)(lambda k: RR(_compute_delta(k)))

import math
from estimator import LWE, ND, RC, schemes
from estimator.lwe_parameters import LWEParameters
from sage.version import version as SAGE_VERSION

N, M_SAMPLES = (512, 512 + 16) if os.environ.get("SMOKE") else (2048, 2048 + 16)   # SMOKE=1: code-path check only
Q = 2**42 - 215
VAR_S, VAR_E = 0.5, 10.0
BETA_S, BETA_E = 36, 164
V_MAX = VAR_S * BETA_E**2 + VAR_E * BETA_S**2
TARGET = 450
HINTS = [0, 16, 32, 48, 64, 80, 96, 112, 128, 144, 256, 272]


def hr(t):
    print("\n" + "=" * 100 + "\n" + t + "\n" + "=" * 100, flush=True)


def diag_instance(n, m, q, var_s, var_e):
    """DBDD_predict_diag as initialize_from_LWE_instance builds it (coordinates e || s || 1, Bvol = m ln q), without
    drawing A: the prediction uses only Sigma, the dimension and the volume."""
    S = diagonal_matrix(RR, [var_e] * m + [var_s] * n + [0])
    inst = DBDD_predict_diag(None, S, None, verbosity=0, Bvol=float(m * math.log(q)))
    inst._q = q
    return inst


def unit(dim, i, scale=1):
    v = [0] * dim
    v[i] = scale
    return v


def finish(inst):
    """The tool's attack estimate after integrating every worthy q-vector (its sample-count optimization)."""
    inst = deepcopy(inst)
    inst.integrate_q_vectors(inst._q)
    return float(inst.beta), inst.dim()


def usvp(n, m, q, xs, xe):
    p = LWEParameters(n=n, q=q, Xs=xs, Xe=xe, m=m)
    return int(LWE.primal_usvp(p, red_cost_model=RC.ADPS16, red_shape_model="gsa")["beta"])


hr("0. Environment and calibration")
print(f"leaky-LWE-Estimator (DDGR20) commit: {LK_COMMIT}\nlattice-estimator commit: {LE_COMMIT}")
print(f"SageMath {SAGE_VERSION}, Python {sys.version.split()[0]}; DBDD_predict_diag, integrate_q_vectors, "
      f"compute_beta_delta (non-probabilistic, interpolated)")
ky = schemes.Kyber512
inst = diag_instance(512, 512, 3329, 1.5, 1.5)
kb, kd = finish(inst)
print(f"Kyber-512: DDGR20 beta = {kb:.2f} (dim {kd}); lattice-estimator primal_usvp beta = "
      f"{usvp(ky.n, ky.m, ky.q, ky.Xs, ky.Xe)}")
base = diag_instance(N, M_SAMPLES, Q, VAR_S, VAR_E)
b0, d0 = finish(base)
print(f"PQZ (u, v_f), no hints: DDGR20 beta = {b0:.2f} (dim {d0}); lattice-estimator primal_usvp beta = "
      f"{usvp(N, M_SAMPLES, Q, ND.CenteredBinomial(1), ND.CenteredBinomial(20))}")

hr("1. A general (mixed) perfect hint w: the tool's DBDD_predict update equals dvol += (1/2) ln det(W Sigma W^T)")
print("""DBDD_predict_diag accepts hints on canonical directions only. For the mixed worst case the run applies the
closed form of DBDD_predict's general update (Bvol += ln ||w||, Sigma projected: net dvol += (1/2) ln(w^T Sigma w) per
orthogonal w), checked here against the tool's full-covariance DBDD_predict on a small instance (n = m = 32, q = 3329).""")
set_random_seed(20261014)
n_s, m_s = 32, 32
Ssm = diagonal_matrix(QQ, [10] * m_s + [QQ(1) / 2] * n_s + [0])
full = DBDD_predict(None, Ssm, None, verbosity=0, Bvol=float(m_s * math.log(3329)))
W = []
dv0 = full.volumes()[2]
for t in range(6):
    w = [ZZ.random_element(-5, 6) for _ in range(m_s + n_s)]
    full.integrate_perfect_hint(vec(w), 0)
    W.append(w)
Wm = matrix(QQ, W)
closed = dv0 + 0.5 * math.log(float((Wm * Ssm[:-1, :-1] * Wm.T).det()))
print(f"6 random integer hints: tool dvol {full.volumes()[2]:.9f}, closed form {closed:.9f}, "
      f"difference {abs(full.volumes()[2] - closed):.2e}; dim {full.dim()} = {m_s + n_s + 1} - 6")
assert abs(full.volumes()[2] - closed) < 1e-6

hr("2. DDGR20 beta per number of perfect hints on one (r, e1)")
print("V_max = %d; target beta >= %d (pq-zero-knowledge.md CTR-PQZ-03). Last column: lattice-estimator primal_usvp with the "
      "hints as removed secret dimensions (n - h), the approximation of pq-zero-knowledge.md §4.5 / params/anon/usvp.py."
      % (int(V_MAX), int(TARGET)))
print(f"{'hints':>5s} {'unit on r':>10s} {'unit on e1':>11s} {'mixed (worst)':>14s} {'estimator n-h':>14s}")
rows = {}
kinds = {}
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
                if kind == "mixed":  # a hint with w^T Sigma w = V_max instead of var_s (section 1)
                    inst.Bvol += 0.5 * math.log(V_MAX / VAR_S)
            done += 1
        rows.setdefault(h, {})[kind] = finish(inst)[0]
        print(f"  [{kind} {h}: {rows[h][kind]:.2f}]", flush=True)
for h in HINTS:
    rows[h]["est"] = usvp(N - h, M_SAMPLES, Q, ND.CenteredBinomial(1), ND.CenteredBinomial(20))
    r = rows[h]
    print(f"{h:5d} {r['r']:10.2f} {r['e1']:11.2f} {r['mixed']:14.2f} {r['est']:14d}", flush=True)


def beta_of(h):
    return rows[h]["mixed"]


hr("3. Per M and leg grouping: the weakest group's hints (16 per leg + 16 with the auditor), worst-case beta")
print(f"{'M':>3s} {'legs/group':>10s} {'G':>3s} {'auditor':>8s} {'hints':>6s} {'beta (mixed)':>13s} {'beta (unit r)':>14s}"
      f" {'>= 450':>7s}")
for M in (1, 2, 4, 8, 16):
    for L in sorted({l for l in (1, 2, 3, 4, M) if l <= M}):
        G = -(-M // L)
        for A in (1, 0):
            h = 16 * L + 16 * A
            b = beta_of(h)
            print(f"{M:3d} {L:10d} {G:3d} {('on' if A else 'off'):>8s} {h:6d} {b:13.2f} {rows[h]['r']:14.2f} "
                  f"{('yes' if b >= TARGET else 'NO'):>7s}")

hr("4. Largest group size with beta >= 450 (worst-case mixed hints)")
for A in (1, 0):
    ok = [L for L in (1, 2, 3, 4, 5, 6, 7, 8) if 16 * L + 16 * A in rows and beta_of(16 * L + 16 * A) >= TARGET]
    print(f"auditor {'on ' if A else 'off'}: legs per (r, e1) <= {max(ok) if ok else 0}")
