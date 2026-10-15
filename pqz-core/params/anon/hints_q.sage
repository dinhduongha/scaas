# -*- coding: utf-8 -*-
# P6-ANON S1 review (finding 8): is hints.sage's mixed-hint shortcut conservative AFTER the q-vector step?
#
# hints.sage puts a mixed hint w = (e1 part, r part) on a canonical r coordinate and adds the volume of w^T Sigma w
# (exact for the hint itself, section 1 there), then lets DBDD_predict_diag integrate q-vectors on every coordinate.
# A real mixed hint also touches e1 coordinates, which the full-covariance DBDD_predict then cannot project away. This
# script compares, on a small instance where the full model is affordable (n = m = 256, q = 4096, the PQZ variances,
# hint norms ||r part|| = 164, ||e1 part|| = 36 as a registered key allows), the tool's DBDD_predict with real mixed
# hints + integrate_q_vectors against the shortcut, at 10 hints (80 / 2048 of the dimension) and at 80 hints.
# Run by run_hints.sh with SCRIPT=hints_q.sage; output appended to hints-anon.txt.
import os
import math
import random as pyrandom
import time
T0 = time.time()

assert os.environ.get("LK_COMMIT", "").startswith("0a9caf8"), "leaky-LWE-Estimator must be at 0a9caf8"
os.chdir("/lk/framework")
load("/lk/framework/DBDD_predict_diag.sage")
load("/lk/framework/DBDD_predict.sage")
from functools import lru_cache
_compute_delta = compute_delta
compute_delta = lru_cache(maxsize=None)(lambda k: RR(_compute_delta(k)))  # pure; memoized as in hints.sage
import numpy.linalg as nla  # after the loads: `from fpylll import *` rebinds the name `numpy`
_logdet = logdet


def logdet(M, exact=False):
    """geometry.sage's logdet (numpy slogdet of the float matrix), without its element-wise conversion of RDF matrices"""
    if not exact and M.base_ring() is RDF:
        return float(nla.slogdet(M.numpy())[1])
    return _logdet(M, exact)

N = M = 256
Q = 4096
VAR_S, VAR_E = 0.5, 10.0
NR, NE = 164, 36
RNG = pyrandom.Random(int(20261015))


def rounded(vals, norm):
    """integer vector close to `norm` in direction vals"""
    s = math.sqrt(sum(x * x for x in vals))
    return [int(round(x * norm / s)) for x in vals]


def hints(kind, h):
    W = []
    for t in range(h):
        r = rounded([RNG.gauss(0, 1) for _ in range(N)], NR)
        if kind == "dense e1 part":
            e = rounded([RNG.gauss(0, 1) for _ in range(M)], NE)
        elif kind == "one e1 coordinate":
            e = [0] * M
            e[t] = NE
        else:  # key with s = 0: r part only
            e = [0] * M
        W.append(e + r)  # coordinates e1 || r (|| 1), as the tool's LWE instances
    return W


def full_beta(W):
    S = diagonal_matrix(RDF, [VAR_E] * M + [VAR_S] * N + [0])
    inst = DBDD_predict(None, S, None, verbosity=0, Bvol=float(M * math.log(Q)))
    used = 0
    for w in W:
        try:
            inst.integrate_perfect_hint(vec(w), 0)
            used += 1
        except InvalidHint:
            pass
    inst.integrate_q_vectors(Q)
    return float(inst.beta), inst.dim(), used


def short_beta(W, worst=False):
    S = diagonal_matrix(RR, [VAR_E] * M + [VAR_S] * N + [0])
    inst = DBDD_predict_diag(None, S, None, verbosity=0, Bvol=float(M * math.log(Q)))
    h = len(W)
    for i in range(h):
        v = [0] * (M + N)
        v[M + i] = 1
        inst.integrate_perfect_hint(v, 0)
    Wm = matrix(RDF, W)
    Sg = diagonal_matrix(RDF, [VAR_E] * M + [VAR_S] * N)
    gain = (h / 2) * math.log(VAR_E * NE**2 + VAR_S * NR**2) if worst else 0.5 * float(nla.slogdet((Wm * Sg * Wm.T).numpy())[1])
    inst.Bvol += gain - (h / 2) * math.log(VAR_S)
    inst.integrate_q_vectors(Q)
    return float(inst.beta)


print("\n" + "=" * 100)
print("5. Finding 8: the mixed-hint shortcut against the full-covariance DBDD_predict after integrate_q_vectors")
print("=" * 100)
print("n = m = %d, q = %d, var_s %s, var_e %s, hint norms r part %d, e1 part %d; Python random seed 20261015"
      % (N, Q, VAR_S, VAR_E, NR, NE))
base = DBDD_predict_diag(None, diagonal_matrix(RR, [VAR_E] * M + [VAR_S] * N + [0]), None, verbosity=0,
                         Bvol=float(M * math.log(Q)))
base.integrate_q_vectors(Q)
print(f"no hints: beta {float(base.beta):.2f}")
print(f"{'hints':>5s} {'kind':>20s} {'full model':>11s} {'(dim, used)':>12s} {'shortcut, same W':>17s} "
      f"{'shortcut, V_max':>16s} {'conservative':>13s}")
ok = True
for h in (10, 80):
    for kind in ("dense e1 part", "one e1 coordinate", "r part only"):
        W = hints(kind, h)
        bf, dim, used = full_beta(W)
        bs, bw = short_beta(W), short_beta(W, worst=True)
        good = bs <= bf + 1e-6 and bw <= bf + 1e-6
        print(f"  [{kind}, {h} hints: {time.time() - T0:.0f} s since start]", flush=True)
        ok &= good
        print(f"{h:5d} {kind:>20s} {bf:11.2f} {str((dim, used)):>12s} {bs:17.2f} {bw:16.2f} {'yes' if good else 'NO':>13s}",
              flush=True)
print(f"shortcut conservative (shortcut beta <= full-model beta in every case): {'YES' if ok else 'NO'}")
