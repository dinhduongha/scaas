# Plan 5h Task 7c (n-study): ../p16k/e_s1_16k.sage unchanged except (1) the final full SIS / LWE.estimate per spec
# runs only with FULL=1 (the loop already gives MSIS lattice beta, MLWE uSVP and dual_hybrid beta under both models),
# (2) one summary line per spec at the end. Run: run_sage.sh <tools> e_s1_n.sage /p/specs/<cell>/<rel>_params.sage ...
# Plan 5h Task 7 (16k): ../e_s1_proof.sage with the dual_hybrid check added (spec 2026-10-20 §6.2: at q ~ 2^54 the
# codegen's MLWE rank reached uSVP 465 but dual_hybrid only 447 / 448). The loop lowers pqz_delta until MSIS beta >= 450
# and raises kmlwe_min until the hiding MLWE has primal uSVP beta >= 450 AND dual_hybrid (lattice-estimator's
# LWE.dual_hybrid = MATZOV) beta >= 450 under ADPS16 classical and quantum. Also prints LaZer's lambda (Z_q
# amortisation repetitions) for e_s0_16k.py. Run: p16k/run_e_s1_16k.sh (pinned Sage image, no network); stdout is
# p16k/estimator-e-s1-16k.txt. Everything else is ../e_s1_proof.sage unchanged.
import os, sys
sys.path.insert(0, "/le")
import estimator as le
from estimator.reduction import ADPS16
from estimator.lwe_parameters import LWEParameters
from estimator.sis_parameters import SISParameters
from functools import lru_cache

assert os.environ.get("LE_COMMIT", "").startswith("53da598")
TARGET_BETA = 450
MODELS = {"classical": le.RC.ADPS16, "quantum": ADPS16(mode="quantum")}
DENY = ("arora-gb", "bkw", "bdd_mitm_hybrid")


def codegen(params_file, delta=None, kmlwe_min=None):
    g = globals()
    for k in ("kmsis_min", "kmlwe_min"):
        g.pop(k, None)
    load(params_file)
    if delta is not None:
        g["pqz_delta"] = delta
    if kmlwe_min is not None:
        g["kmlwe_min"] = kmlwe_min
    g.update(verbose=0, code=0, loaded=1, pqz_verbose=0)
    load("lnp-tbox-codegen.sage")
    rows = int(kmsis + l + lmbda / 2 + 256 / d + approx_proof * 256 / d + 2)
    return dict(kmsis=int(kmsis), kmlwe=int(kmlwe), m1=int(m1), Z=int(Z), m2=int(m2), rows=rows, q=int(q), lmbda=int(lmbda),
                B=float(Bound()), D=int(D), gamma=int(gamma), proof_bytes=int(ceil(proof_bits / 8)))


def sis_params(c):
    return SISParameters(n=c["kmsis"] * 64, q=c["q"], length_bound=c["B"], m=(c["m1"] + c["m2"]) * 64, norm=2,
                         tag=f"MSIS({c['kmsis']},{c['m1'] + c['m2']},2^{float(log(c['B'], 2)):.2f})")


def mlwe_params(c):
    u = le.ND.Uniform(-1, 1)
    return LWEParameters(n=c["kmlwe"] * 64, q=c["q"], Xs=u, Xe=u, m=c["rows"] * 64,
                         tag=f"MLWE({c['kmlwe']},{c['rows']},[-1,1])")


def sis_beta(c):
    return int(le.SIS.lattice(sis_params(c), red_cost_model=le.RC.ADPS16)["beta"])


def mlwe_beta(c):
    return int(le.LWE.primal_usvp(mlwe_params(c), red_cost_model=le.RC.ADPS16, red_shape_model="gsa")["beta"])


@lru_cache(maxsize=None)  # a unique name: the codegen load()s third_party/estimator.py (its own _dual) into globals
def _p16k_dual(kmlwe, rows, q):
    c = dict(kmlwe=kmlwe, rows=rows, q=q)
    return tuple(int(le.LWE.dual_hybrid(mlwe_params(c), red_cost_model=m)["beta"]) for m in MODELS.values())


def dual_beta(c):
    """(classical, quantum) dual_hybrid beta of the hiding MLWE (depends on kmlwe, rows, q only)"""
    return _p16k_dual(c["kmlwe"], c["rows"], c["q"])


def full(c):
    for name, model in MODELS.items():
        r = le.SIS.estimate(sis_params(c), red_cost_model=model)
        b = min(r, key=lambda a: r[a]["rop"])
        print(f"  {sis_params(c).tag} {name}: {float(log(r[b]['rop'], 2)):.1f} ({b}, beta {int(r[b]['beta'])})")
        r = le.LWE.estimate(mlwe_params(c), red_cost_model=model, deny_list=DENY, jobs=2)
        b = min(r, key=lambda a: r[a]["rop"])
        print(f"  {mlwe_params(c).tag} {name}: {float(log(r[b]['rop'], 2)):.1f} ({b}); uSVP beta {int(r['usvp']['beta'])}")
        sys.stdout.flush()


SUMMARY = []
for rel in sys.argv[1:]:
    print(f"\n== {rel}")
    c = codegen(rel)
    print(f"LaZer codegen as is: kmsis {c['kmsis']}, kmlwe {c['kmlwe']}, m2 {c['m2']}, B 2^{float(log(c['B'], 2)):.2f}, "
          f"D {c['D']}, gamma {c['gamma']}: MSIS beta {sis_beta(c)}, MLWE uSVP beta {mlwe_beta(c)}, "
          f"proof ~{c['proof_bytes']} B")
    # The codegen spends any MSIS slack on compression (D, gamma), so MSIS is steered by the root-Hermite
    # target pqz_delta; MLWE by a rank floor.
    dl, kl = float(pqz_delta), c["kmlwe"]
    while True:
        c = codegen(rel, dl, kl)
        sb, mb = sis_beta(c), mlwe_beta(c)
        db = dual_beta(c) if mb >= TARGET_BETA else (0, 0)
        print(f"  pqz_delta {dl:.5f}, kmlwe_min {kl}: kmsis {c['kmsis']}, kmlwe {c['kmlwe']}, m2 {c['m2']}, "
              f"B 2^{float(log(c['B'], 2)):.2f}, D {c['D']}, gamma {c['gamma']}, lambda {c['lmbda']}: MSIS beta {sb}, "
              f"MLWE uSVP beta {mb}, dual_hybrid beta {db[0]} / {db[1]}, proof ~{c['proof_bytes']} B")
        sys.stdout.flush()
        if sb >= TARGET_BETA and mb >= TARGET_BETA and min(db) >= TARGET_BETA:
            break
        if sb < TARGET_BETA:
            dl -= 0.00002
        if mb < TARGET_BETA or min(db) < TARGET_BETA:
            kl = c["kmlwe"] + 1
    print(f"=> {rel}: pqz_delta = {dl:.5f}, kmlwe_min = {kl} (kmsis = {c['kmsis']}, m2 = {c['m2']}, D = {c['D']}, "
          f"gamma = {c['gamma']}, lambda = {c['lmbda']}, MSIS beta {sb}, MLWE uSVP beta {mb}, dual_hybrid {db[0]} / {db[1]}, codegen proof size ~{c['proof_bytes']} B)")
    SUMMARY.append(f"{rel}: kmlwe_min {kl}, kmsis {c['kmsis']}, MSIS {sb}, MLWE uSVP {mb}, dual_hybrid {db[0]} / {db[1]}, proof {c['proof_bytes']} B")
    if os.environ.get("FULL"):
        full(c)
print("\nSUMMARY")
for x in SUMMARY:
    print(x)
