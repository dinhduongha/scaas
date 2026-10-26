# -*- coding: utf-8 -*-
# Plan 5h Task 7c (n-study, research): the cheap security screen of every grid cell in cells.json (budget.py):
# lattice-estimator 53da598 primal uSVP (ADPS16, GSA) on the encryption instance (m = n + 48) and DDGR20
# (leaky-LWE-Estimator 0a9caf8) worst-case maximal-norm mixed hints on the shared (r, e1) at 0 / 32 / 80 hints
# (32 = R_TX with the auditor, 80 = an op 7 group of 4 legs + auditor, the on-chain maximum M <= 4).
# The DDGR20 part is ../aprime/aprime.sage's `ddgr` unchanged (diagonal instance, m = n + 16, V_max = var_s beta_e^2 +
# var_e beta_s^2 with the cell's bounds). Run by run_screen.sh in the pinned Sage image; stdout is screen.txt.
# ROWS = comma-separated row indexes of cells.json (default: the 16k calibration row first, then all q3, then all q1).
import os
import sys
import json
import math
from functools import lru_cache
from copy import deepcopy

LK_COMMIT = os.environ.get("LK_COMMIT", "unknown")
LE_COMMIT = os.environ.get("LE_COMMIT", "unknown")
assert LK_COMMIT.startswith("0a9caf8") and LE_COMMIT.startswith("53da598"), (LK_COMMIT, LE_COMMIT)
CELLS = json.load(open("/p/cells.json"))
os.chdir("/lk/framework")
load("/lk/framework/DBDD_predict_diag.sage")
_compute_delta = compute_delta
compute_delta = lru_cache(maxsize=None)(lambda k: RR(_compute_delta(k)))

from estimator import LWE, ND, RC
from estimator.lwe_parameters import LWEParameters
from sage.version import version as SAGE_VERSION

VAR_S, VAR_E = 0.5, 10.0


def diag_instance(n, m, q):
    S = diagonal_matrix(RR, [VAR_E] * m + [VAR_S] * n + [0])
    inst = DBDD_predict_diag(None, S, None, verbosity=0, Bvol=float(m * math.log(q)))
    inst._q = q
    return inst


def finish(inst):
    inst = deepcopy(inst)
    inst.integrate_q_vectors(inst._q)
    return float(inst.beta)


def ddgr(n, q, vmax, counts):
    m = n + 16
    inst = diag_instance(n, m, q)
    out, done = {}, 0
    for h in counts:
        while done < h:
            inst.integrate_perfect_hint([0] * (m + done) + [1] + [0] * (n - done - 1), 0)
            inst.Bvol += 0.5 * math.log(vmax / VAR_S)
            done += 1
        out[h] = finish(inst)
    return out


def usvp(n, m, q):
    p = LWEParameters(n=n, q=q, Xs=ND.CenteredBinomial(1), Xe=ND.CenteredBinomial(20), m=m)
    return int(LWE.primal_usvp(p, red_cost_model=RC.ADPS16, red_shape_model="gsa")["beta"])


print(f"lattice-estimator {LE_COMMIT}, leaky-LWE-Estimator {LK_COMMIT}, SageMath {SAGE_VERSION}, "
      f"Python {sys.version.split()[0]}")
idx = [int(x) for x in os.environ.get("ROWS", "").split(",") if x]
if not idx:
    idx = [i for i, c in enumerate(CELLS) if c["variant"] == "16k"] + \
          [i for i, c in enumerate(CELLS) if c["variant"] == "q3"] + [i for i, c in enumerate(CELLS) if c["variant"] == "q1"]
print("| row | n | K_MAX | variant | log2 q | enc uSVP | DDGR20 h0 | h32 | h80 | core-SVP@h80 cl. / qu. | >= 450 @80 |")
print("|---|---|---|---|---|---|---|---|---|---|---|", flush=True)
for i in idx:
    c = CELLS[i]
    n, q = c["n"], Integer(c["q"])
    assert is_prime(q) and q % 16 == 9
    vmax = VAR_S * c["be"]**2 + VAR_E * c["bs"]**2
    h = ddgr(n, q, vmax, (0, 32, 80))
    u = usvp(n, n + 48, q)
    print(f"| {i} | {n} | {c['K']:,} | {c['variant']} | {float(math.log2(q)):.3f} | {u} | {h[0]:.2f} | {h[32]:.2f} | "
          f"{h[80]:.2f} | {0.292 * h[80]:.1f} / {0.265 * h[80]:.1f} | {'yes' if h[80] >= 450 else 'no'} |", flush=True)
print("done")
