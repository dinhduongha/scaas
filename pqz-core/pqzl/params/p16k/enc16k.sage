# -*- coding: utf-8 -*-
# Plan 5h Task 7: encryption security of the 16k candidate (n = 2560, k = 40) and of the n = 2304 (k = 36) option at
# q = 2^50 - 42,310,535 (owner ruling Q1): lattice-estimator 53da598 primal uSVP (ADPS16, GSA) and the full LWE.estimate
# under ADPS16 classical and quantum for the key (m = n) and the encryption (u, v_t, v_f, v_a: m = n + 48) instances, as
# ../aprime/aprime.sage parts 2-3. The DDGR20 hint tables come from run_hints16k.sh. Run by run_enc16k.sh; stdout is
# p16k/enc-16k.txt.
import os
import sys
import math

LE_COMMIT = os.environ.get("LE_COMMIT", "unknown")
assert LE_COMMIT.startswith("53da598"), LE_COMMIT
sys.path.insert(0, "/le")
from estimator import LWE, ND, RC, schemes
from estimator.lwe_parameters import LWEParameters
from estimator.reduction import ADPS16
from sage.version import version as SAGE_VERSION

Q = 2**50 - 42310535
assert is_prime(Q) and Q % 16 == 9
DENY = ("arora-gb", "bkw", "bdd_mitm_hybrid")
MODELS = {"classical": RC.ADPS16, "quantum": ADPS16(mode="quantum")}
print(f"lattice-estimator {LE_COMMIT}, SageMath {SAGE_VERSION}, Python {sys.version.split()[0]}; q = {Q}")
ky = schemes.Kyber512
print(f"reference: Kyber-512 usvp beta {int(LWE.primal_usvp(ky, red_cost_model=RC.ADPS16, red_shape_model='gsa')['beta'])}",
      flush=True)
for n in (2560, 2304):
    for tag, m in (("key (m = n)", n), ("enc (m = n + 48)", n + 48)):
        p = LWEParameters(n=n, q=Q, Xs=ND.CenteredBinomial(1), Xe=ND.CenteredBinomial(20), m=m, tag=f"n={n} {tag}")
        u = int(LWE.primal_usvp(p, red_cost_model=RC.ADPS16, red_shape_model="gsa")["beta"])
        print(f"\n== n = {n} {tag}: primal uSVP beta {u}", flush=True)
        for name, model in MODELS.items():
            r = LWE.estimate(p, red_cost_model=model, deny_list=DENY, jobs=2)
            b = min(r, key=lambda a: r[a]["rop"])
            print(f"  {name}: best 2^{float(math.log2(r[b]['rop'])):.1f} ({b}, beta {int(r[b]['beta'])}); "
                  f"usvp beta {int(r['usvp']['beta'])}, dual_hybrid beta {int(r['dual_hybrid']['beta'])}", flush=True)
print("\ndone")
