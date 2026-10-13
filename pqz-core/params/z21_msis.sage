# PQZ P6-Z21 (lazer#26): the MSIS instance behind the tbox proofs when z21 is not norm-checked (v2 verifiers before
# the fix) against the instance the parameters were sized for. docs/research/pqz-z21-norm.md §5.
#
# LNP22 (eprint 2022/284) Fig. 18 / Thm A.2: the verifier checks ||(z21, A1 z1 + A2' z21 - c 2^D tA1 - gamma w1)||
# <= B = Bound_(); the extractor gets ||c_bar s_bar2|| <= 2B, so the codegen's B2 = 2 Bound_() and
# Bound() = 4 eta sqrt(B1^2 + B2^2). Without the z21 check the only bound on z21 is the proof length: z21 is coded by
# coder_enc_grandom (log2stdev2 + 1 binary bits, a final zero, a unary high part), so every spare bit of the
# PQZ_MAX_PROOF budget adds 2^log2stdev2 to one coefficient (one coefficient maximises ||z21|| for a fixed number of
# bits). The z22 part stays bounded by Bound_() (that check exists). So
#   Z21max = (E / 2 + 1/2) 2^(log2stdev2 + 1),   E = 8 (MAX_PROOF - smallest measured honest proof) + allowance,
#   B2' = 2 sqrt(Z21max^2 + Bound_()^2),        Bound' = 4 eta sqrt(B1^2 + B2'^2),
# allowance = 3 bits per Gaussian-coded coefficient (z1, z21, z3, z4; the unary bits of an honest proof a cheater
# could also spend; an over-estimate). Run: SCRIPT=z21_msis.sage ./run_e_s1.sh <LaZer> <estimator> reg tx burn ds dr
import os, sys
sys.path.insert(0, "/le")
import estimator as le
from estimator.sis_parameters import SISParameters

assert os.environ.get("LE_COMMIT", "").startswith("53da598")
MAX_PROOF = 98304  # PQZ_MAX_PROOF, src/pqz.h
# smallest honest proof per relation [measured], pqz-core/STATUS.md (rel3/runs/f2-*, v2 sizes unchanged)
HONEST_MIN = {"reg": 28097, "tx": 42741, "burn": 41916, "ds": 28937, "dr": 28987}


def codegen(params_file):
    g = globals()
    for k in ("kmsis_min", "kmlwe_min"):
        g.pop(k, None)
    load(params_file)
    g["kmlwe_min"] = 33  # estimator-e-s1*.txt: every relation settled at pqz_delta 1.00366, kmlwe_min 33
    g.update(verbose=0, code=0, loaded=1, pqz_verbose=0)
    load("lnp-tbox-codegen.sage")


def sis(Bv):
    p = SISParameters(n=int(kmsis) * 64, q=int(q), length_bound=float(Bv), m=int(m1 + m2) * 64, norm=2)
    lat = le.SIS.lattice(p, red_cost_model=le.RC.ADPS16)
    return int(lat["beta"]), float(log(lat["rop"], 2)), float(get_delta_msis(Bv, kmsis, d, q))


print("relation | kmsis | m1+m2 | log2stdev2 | Bsq | B1 | Bound_ | E bits | Z21max | Z21max^2/Bsq | "
      "Bound: designed -> no z21 check | delta (codegen) | beta / log2 rop (SIS.lattice, ADPS16 classical)")
for rel in sys.argv[1:]:
    codegen(f"/tmp/w/{rel}_params.sage")
    l2s2 = int(mp.log(stdev2 / mpf(1.55), 2))
    ncoef = int((m1 + Z) + (m2 - kmsis)) * 64 + 256 + approx_proof * 256
    E = 8 * (MAX_PROOF - HONEST_MIN[rel]) + 3 * ncoef
    Zmax = (mpf(E) / 2 + mpf(1) / 2) * 2 ** (l2s2 + 1)
    Zmax = min(Zmax, mpf(q - 1) / 2)  # z21 is centred mod q
    Bd = Bound()
    Bn = 4 * mpf(eta) * mp.sqrt(Bound1() ** 2 + (2 * mp.sqrt(Zmax ** 2 + Bound_() ** 2)) ** 2)
    (b0, r0, d0), (b1, r1, d1) = sis(Bd), sis(Bn)
    print(f"{rel} | {kmsis} | {int(m1 + m2)} | {l2s2} | {floor(Bound_() ** 2)} (2^{float(log(Bound_() ** 2, 2)):.2f}) | "
          f"2^{float(log(Bound1(), 2)):.2f} | 2^{float(log(Bound_(), 2)):.2f} | {E} | 2^{float(log(Zmax, 2)):.2f} | "
          f"{float(Zmax ** 2 / Bound_() ** 2):.3g} | 2^{float(log(Bd, 2)):.2f} -> 2^{float(log(Bn, 2)):.2f} | "
          f"{float(d0):.5f} -> {float(d1):.5f} | {b0} / {r0:.1f} -> {b1} / {r1:.1f}")
    sys.stdout.flush()
