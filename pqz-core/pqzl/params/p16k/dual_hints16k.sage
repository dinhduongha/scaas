# -*- coding: utf-8 -*-
# Plan 5h Task 7, fix round 1 (review I2): the dual_hybrid side of the hinted encryption instance. As the "estimator
# n - h" column of hints-16k-n2560.txt (anon/hints.sage section 2), h perfect hints on r are modelled as h removed
# secret dimensions: LWE(n = 2560 - h, m = 2560 + 16, q, CBD(1), CBD(20)). For each h: primal uSVP beta (the column's
# value, as a cross-check) and lattice-estimator's LWE.dual_hybrid (MATZOV) beta under ADPS16 classical and quantum.
# The worst-case mixed hints of DDGR20 sit below the n - h model by (n - h primal - DDGR20 mixed) (7.32 at 144); the
# last columns subtract that same offset from dual_hybrid as a conservative worst-case figure [estimate].
# Run: SCRIPT=dual_hints16k.sage run_enc16k.sh <le> >> hints-16k-n2560.txt
import os
import sys

LE_COMMIT = os.environ.get("LE_COMMIT", "unknown")
assert LE_COMMIT.startswith("53da598"), LE_COMMIT
sys.path.insert(0, "/le")
from estimator import LWE, ND, RC
from estimator.lwe_parameters import LWEParameters
from estimator.reduction import ADPS16

N, Q = 2560, 2**50 - 42310535
M = N + 16
# DDGR20 worst-case mixed beta per h, from section 2 of hints-16k-n2560.txt (same run, same instance)
MIXED = {0: 507.31, 16: 502.32, 32: 497.34, 80: 482.43, 128: 467.60, 144: 462.68}
OK_HEAD = "ok"  # a label: inside an f-string the Sage preparser rewrote a literal 450 (first run printed _sage_const_450)
MODELS = {"classical": RC.ADPS16, "quantum": ADPS16(mode="quantum")}
print("\n" + "=" * 100 + "\n6. Fix round 1 (I2): dual_hybrid on the hinted instance, n - h model (dual_hints16k.sage)\n" + "=" * 100)
print(f"lattice-estimator {LE_COMMIT}; n = {N}, m = {M}, q = {Q}, CBD(1) secret, CBD(20) error")
print(f"{'hints':>5s} {'primal n-h':>10s} {'dual cl.':>9s} {'dual qu.':>9s} {'DDGR20 mixed':>13s} {'offset':>7s} "
      f"{'dual cl. - off':>15s} {'dual qu. - off':>15s} {OK_HEAD:>7s}", flush=True)
for h in sorted(MIXED):
    p = LWEParameters(n=N - h, q=Q, Xs=ND.CenteredBinomial(1), Xe=ND.CenteredBinomial(20), m=M)
    pu = int(LWE.primal_usvp(p, red_cost_model=RC.ADPS16, red_shape_model="gsa")["beta"])
    d = [int(LWE.dual_hybrid(p, red_cost_model=m)["beta"]) for m in MODELS.values()]
    off = pu - MIXED[h]
    adj = [x - off for x in d]
    print(f"{h:5d} {pu:10d} {d[0]:9d} {d[1]:9d} {MIXED[h]:13.2f} {off:7.2f} {adj[0]:15.2f} {adj[1]:15.2f} "
          f"{'yes' if min(d) >= 450 and min(adj) >= 450 else 'NO':>7s}", flush=True)
print("done")
