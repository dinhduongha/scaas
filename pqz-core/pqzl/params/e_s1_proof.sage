# PQZ E-S1 (P6d): size the ABDLOP ranks of LaZer's tbox codegen with the pinned lattice-estimator.
#
# LaZer's codegen picks the MSIS rank (kmsis) and the MLWE hiding rank (kmlwe) from a root-Hermite target
# (delta <= 1.0044) and the old lwe-estimator. CTR-PQZ-03 asks every proof instance to reach the Kyber-512
# margin in block-size terms (beta >= 450) under lattice-estimator 53da598, RC.ADPS16. This script runs the
# real codegen (pqz-core/pqzl/params/codegen, LaZer's formulas: B = 4 eta sqrt(B1^2 + B2^2), bimodal s2, the t_A /
# w compression terms) with floors kmsis_min / kmlwe_min, reads back its instances, and raises the floors until
# both pass. Output: the floors per relation and the full estimates of the chosen instances.
# Run: run_e_s1.sh (pinned Sage image, no network). Writes to stdout (recorded as estimator-e-s1.txt).
import os, sys
sys.path.insert(0, "/le")
import estimator as le
from estimator.reduction import ADPS16
from estimator.lwe_parameters import LWEParameters
from estimator.sis_parameters import SISParameters

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
    return dict(kmsis=int(kmsis), kmlwe=int(kmlwe), m1=int(m1), Z=int(Z), m2=int(m2), rows=rows, q=int(q),
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


def full(c):
    for name, model in MODELS.items():
        r = le.SIS.estimate(sis_params(c), red_cost_model=model)
        b = min(r, key=lambda a: r[a]["rop"])
        print(f"  {sis_params(c).tag} {name}: {float(log(r[b]['rop'], 2)):.1f} ({b}, beta {int(r[b]['beta'])})")
        r = le.LWE.estimate(mlwe_params(c), red_cost_model=model, deny_list=DENY, jobs=4)
        b = min(r, key=lambda a: r[a]["rop"])
        print(f"  {mlwe_params(c).tag} {name}: {float(log(r[b]['rop'], 2)):.1f} ({b}); uSVP beta {int(r['usvp']['beta'])}")
        sys.stdout.flush()


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
        print(f"  pqz_delta {dl:.5f}, kmlwe_min {kl}: kmsis {c['kmsis']}, kmlwe {c['kmlwe']}, m2 {c['m2']}, "
              f"B 2^{float(log(c['B'], 2)):.2f}, D {c['D']}, gamma {c['gamma']}: MSIS beta {sb}, MLWE beta {mb}, "
              f"proof ~{c['proof_bytes']} B")
        sys.stdout.flush()
        if sb >= TARGET_BETA and mb >= TARGET_BETA:
            break
        if sb < TARGET_BETA:
            dl -= 0.00002
        if mb < TARGET_BETA:
            kl = c["kmlwe"] + 1
    print(f"=> {rel}: pqz_delta = {dl:.5f}, kmlwe_min = {kl} (kmsis = {c['kmsis']}, m2 = {c['m2']}, D = {c['D']}, "
          f"gamma = {c['gamma']}, codegen proof size ~{c['proof_bytes']} B)")
    full(c)
