# -*- coding: utf-8 -*-
# Plan 5h Task 7c (n-study): the expensive encryption estimates for the promising cells (ROWS of cells.json):
# (1) the full LWE.estimate (lattice-estimator 53da598, deny arora-gb / bkw / bdd_mitm_hybrid) under ADPS16 classical and
#     quantum on the encryption instance (m = n + 48; the key instance m = n gave identical numbers in every earlier run:
#     ../p16k/enc-16k.txt, ../aprime/aprime.txt), as ../p16k/enc16k.sage;
# (2) dual_hybrid on the 80-hint instance as ../p16k/dual_hints16k.sage: 80 hints on r as 80 removed secret dimensions
#     (LWE n - 80, m = n + 16), both models, and the same value minus the DDGR20 worst-case offset
#     (primal uSVP of n - 80 minus the DDGR20 mixed beta at 80 hints from screen.txt) [estimate].
# Run: ROWS=<i,j,...> run_sage.sh <tools> enc_n.sage > enc-n.txt
import os
import sys
import json
import math
import re

LE_COMMIT = os.environ.get("LE_COMMIT", "unknown")
assert LE_COMMIT.startswith("53da598"), LE_COMMIT
sys.path.insert(0, "/le")
from estimator import LWE, ND, RC
from estimator.lwe_parameters import LWEParameters
from estimator.reduction import ADPS16

CELLS = json.load(open("/p/cells.json"))
H80 = {int(r): float(b) for r, b in re.findall(r"^\| (\d+) \|(?:[^|]*\|){7}\s*([\d.]+) \|", open("/p/screen.txt").read(), re.M)}
DENY = ("arora-gb", "bkw", "bdd_mitm_hybrid")
MODELS = {"classical": RC.ADPS16, "quantum": ADPS16(mode="quantum")}
print(f"lattice-estimator {LE_COMMIT}")
print("| row | n | K_MAX | variant | log2 q | best classical / quantum | uSVP | dual_hybrid cl. / qu. | n-80: primal, dual_hybrid cl. / qu."
      " | DDGR20 h80 | offset | dual_hybrid h80 - offset cl. / qu. |")
print("|---|---|---|---|---|---|---|---|---|---|---|---|", flush=True)
for i in [int(x) for x in os.environ["ROWS"].split(",")]:
    c = CELLS[i]
    n, q = c["n"], Integer(c["q"])
    p = LWEParameters(n=n, q=q, Xs=ND.CenteredBinomial(1), Xe=ND.CenteredBinomial(20), m=n + 48)
    best, usvp, dual = [], None, []
    for name, model in MODELS.items():
        r = LWE.estimate(p, red_cost_model=model, deny_list=DENY, jobs=2)
        b = min(r, key=lambda a: r[a]["rop"])
        best.append(f"2^{float(math.log2(r[b]['rop'])):.1f} ({b})")
        usvp = int(r["usvp"]["beta"])
        dual.append(int(r["dual_hybrid"]["beta"]))
    ph = LWEParameters(n=n - 80, q=q, Xs=ND.CenteredBinomial(1), Xe=ND.CenteredBinomial(20), m=n + 16)
    pu = int(LWE.primal_usvp(ph, red_cost_model=RC.ADPS16, red_shape_model="gsa")["beta"])
    dh = [int(LWE.dual_hybrid(ph, red_cost_model=m)["beta"]) for m in MODELS.values()]
    off = pu - H80[i]
    print(f"| {i} | {n} | {c['K']:,} | {c['variant']} | {float(math.log2(q)):.3f} | {best[0]} / {best[1]} | {usvp} | "
          f"{dual[0]} / {dual[1]} | {pu}, {dh[0]} / {dh[1]} | {H80[i]:.2f} | {off:.2f} | {dh[0] - off:.2f} / {dh[1] - off:.2f} |",
          flush=True)
print("done")
