# -*- coding: utf-8 -*-
"""PQZ E-S0 parameter spike (P6b): security estimates and per-round Fiat-Shamir soundness.

Run inside SageMath with lattice-estimator (commit 53da598) on PYTHONPATH; run.sh does that in a pinned container
and its stdout is estimator.txt. Every parameter comes from docs/contracts/pq-zether.md (CTR-PQZ-03, -04, section 5)
or from a derivation printed next to it; docs/research/pqz-parameters-e-s0.md explains each step.
"""
import math
import os
import sys
from math import comb, log, log2, sqrt

import numpy as np
from estimator import LWE, ND, RC, SIS, schemes
from estimator.lwe_parameters import LWEParameters
from estimator.reduction import ADPS16
from estimator.sis_parameters import SISParameters
from sage.version import version as SAGE_VERSION

COMMIT = os.environ.get("LE_COMMIT", "unknown")
assert COMMIT.startswith("53da598"), "lattice-estimator must be checked out at 53da598"

MODELS = {"classical": RC.ADPS16, "quantum": ADPS16(mode="quantum")}
# arora-gb and bkw are far off on these instances; bdd_mitm_hybrid targets sparse secrets (CBD(1) has weight ~n/2) and
# takes ~30 min per n = 2048 run, so it runs once (PQZ key, classical) as the record and is skipped elsewhere.
DENY_ALL = ("arora-gb", "bkw")
DENY = DENY_ALL + ("bdd_mitm_hybrid",)
TARGET_BETA = 450  # CTR-PQZ-03 "in block-size terms beta >= 450"

# ---- CTR-PQZ-03 -------------------------------------------------------------------------------------------------
d, k = 64, 32
q = 2**42 - 215
l = 4
DELTA = 2**26 - 1
BETA_S, BETA_E, BETA_2 = 36, 164, 64
K_MAX = 1024
CBD1, CBD20 = ND.CenteredBinomial(1), ND.CenteredBinomial(20)
VAR_S, VAR_E = 0.5, 10.0  # CBD(1), CBD(20)


def hr(title):
    print("\n" + "=" * 100 + "\n" + title + "\n" + "=" * 100, flush=True)


def lg(x):
    return float(log2(float(x)))


def full_estimate(params, deny=(DENY, DENY)):
    """LWE.estimate under both ADPS16 modes; returns {model: (min log2 rop, attack, usvp beta)}."""
    out = {}
    for (name, model), dl in zip(MODELS.items(), deny):
        print(f"\n# LWE.estimate({params.tag}, red_cost_model=ADPS16('{name}'), deny_list={dl})", flush=True)
        res = LWE.estimate(params, red_cost_model=model, deny_list=dl, jobs=4)
        best = min(res, key=lambda a: res[a]["rop"])
        out[name] = (lg(res[best]["rop"]), best, int(res["usvp"]["beta"]))
    return out


def sis_estimate(params):
    out = {}
    for name, model in MODELS.items():
        print(f"\n# SIS.estimate({params.tag}, red_cost_model=ADPS16('{name}'))", flush=True)
        res = SIS.estimate(params, red_cost_model=model)
        best = min(res, key=lambda a: res[a]["rop"])
        out[name] = (lg(res[best]["rop"]), best, int(res[best]["beta"]))
    return out


# ---- 0. header and parameter checks ------------------------------------------------------------------------------
hr("0. Environment and CTR-PQZ-03 parameter checks")
print(f"lattice-estimator commit: {COMMIT}")
print(f"SageMath: {SAGE_VERSION}   Python: {sys.version.split()[0]}   numpy: {np.__version__}")
print(f"cost models: ADPS16 classical 0.292*beta, ADPS16 quantum 0.265*beta; shape model GSA (estimator default)")
from sage.all import is_prime  # noqa: E402

assert is_prime(q) and q % 16 == 9 and DELTA == q // 2**16
print(f"q = 2^42 - 215 = {q}: prime, q mod 16 = {q % 16} (l = {l} factors), Delta = floor(q/2^16) = {DELTA}")
ls18 = q ** (1 / l) / sqrt(l)
print(f"LS18 Cor. 1.2 invertibility bound q^(1/l)/sqrt(l) = {ls18:.1f} (l_inf)")
b_fresh = BETA_E * BETA_S + BETA_S * BETA_E + BETA_2
print(f"B_FRESH = {b_fresh}; K_MAX*B_FRESH = {K_MAX * b_fresh} < 2^24 = {2**24}: {K_MAX * b_fresh < 2**24}; "
      f"2^24 < Delta/2: {2**24 < DELTA / 2}")

# ---- 1. LWE instances --------------------------------------------------------------------------------------------
hr("1. LWE instances under LWE.estimate")
kyber = schemes.Kyber512
key = LWEParameters(n=d * k, q=q, Xs=CBD1, Xe=CBD20, m=d * k, tag="PQZ key  pk = A s + e")
# u = A^T r + e1 together with the three v rows (16 coefficients each for v_t, v_f, v_a) once pk is replaced by
# uniform under the key instance: n = 2048, m = 2048 + 48, errors CBD(20).
enc_u = LWEParameters(n=d * k, q=q, Xs=CBD1, Xe=CBD20, m=d * k + 3 * 16, tag="PQZ enc  (u, v_t, v_f, v_a)")
# CTR-PQZ-04 approximation: 32 perfect hints on r = 32 secret dimensions removed (checked against DBDD in part 2).
enc_h = LWEParameters(n=d * k - 32, q=q, Xs=CBD1, Xe=CBD20, m=d * k + 3 * 16, tag="PQZ enc  32 hints (n - 32)")
lwe_rows = {}
deny_of = {kyber.tag: (DENY_ALL, DENY_ALL), key.tag: (DENY_ALL, DENY)}
for p in (kyber, key, enc_u, enc_h):
    lwe_rows[p.tag] = full_estimate(p, deny_of.get(p.tag, (DENY, DENY)))

# ---- 2. DDGR20 leaky-LWE: 32 perfect hints on (r, e1) --------------------------------------------------------------
hr("2. DDGR20 perfect hints on the joint secret (r, e1): predictive DBDD (own implementation, see README)")
print("""Model (Dachman-Soled, Ducas, Gong, Rossi 2020, 'lightweight' DBDD prediction, perfect hints, primitive case):
  embedding dimension dim = m' + n + 1, normalized log-volume lv = m' ln q - (m'/2) ln var_e - (n/2) ln var_s;
  a perfect hint <v, (r, e1)> = l does dim -= 1 and lv += (1/2) ln(v^T Sigma v)  (Sigma = diag(var_s, var_e));
  beta = min over m' of the least beta with sqrt(beta) <= delta(beta)^(2 beta - dim - 1) * exp(lv / dim)
  (the ADPS16 uSVP condition on the isotropic lattice; the same GSA condition the estimator's primal_usvp uses).
A larger lv makes the attack easier, so the most informative hint is the one with the largest v^T Sigma v. For k hints
with integer matrix W, lv += (1/2) ln det(W Sigma W^T) <= (1/2) sum_i ln(w_i^T Sigma w_i) (Hadamard) <= (k/2) ln V_max,
V_max = var_s*beta_e^2 + var_e*beta_s^2 for the forms e^T r - s^T e1 a registered key allows (||e|| <= 164,
||s|| <= 36): k orthogonal maximal-norm mixed forms are the worst directions for any k perfect hints.""")


def delta_of(beta):
    return (beta / (2 * math.pi * math.e) * (math.pi * beta) ** (1 / beta)) ** (1 / (2 * (beta - 1)))


def beta_for(dim, lv):
    for beta in range(40, dim):
        if sqrt(beta) <= delta_of(beta) ** (2 * beta - dim - 1) * math.exp(lv / dim):
            return beta
    return dim


def dbdd_beta(n, m, qq, var_s, var_e, hints_s=(), hints_e=(), hints_mixed=()):
    """hints_*: lists of v^T Sigma v; e1 hints need their samples kept (m' >= len(hints_e))."""
    best = None
    for mm in range(max(len(hints_e), 64), m + 1, 8):
        dim = mm + n + 1 - len(hints_s) - len(hints_e) - len(hints_mixed)
        lv = mm * log(qq) - mm / 2 * log(var_e) - n / 2 * log(var_s)
        lv += sum(0.5 * log(v) for v in (*hints_s, *hints_e, *hints_mixed))
        b = beta_for(dim, lv)
        best = b if best is None else min(best, b)
    return best


kb = dbdd_beta(512, 512, 3329, 1.5, 1.5)
print(f"\ncalibration: Kyber-512 DBDD beta = {kb} (estimator usvp: {lwe_rows[kyber.tag]['classical'][2]})")
base = dbdd_beta(2048, 2096, q, VAR_S, VAR_E)
print(f"calibration: PQZ enc DBDD beta = {base} (estimator usvp: {lwe_rows[enc_u.tag]['classical'][2]})")
mixed_v = VAR_S * BETA_E**2 + VAR_E * BETA_S**2  # h = e^T r - s^T e1 with ||e|| = 164, ||s|| = 36
cases = [
    ("32 unit hints on r", dict(hints_s=[VAR_S] * 32)),
    ("32 unit hints on e1", dict(hints_e=[VAR_E] * 32)),
    ("16 on r + 16 on e1", dict(hints_s=[VAR_S] * 16, hints_e=[VAR_E] * 16)),
    (f"32 maximal-norm mixed forms (V_max = {mixed_v:.0f}, worst case)", dict(hints_mixed=[mixed_v] * 32)),
]
hint_rows = []
for name, kw in cases:
    b = dbdd_beta(2048, 2096, q, VAR_S, VAR_E, **kw)
    hint_rows.append((name, b))
    print(f"{name:55s} beta = {b:4d}  (DBDD drop {base - b:+d})  core-SVP {0.292 * b:.1f} / {0.265 * b:.1f}")

# ---- 3. Proof engine instances (LNP22 / LaZer ABDLOP) -------------------------------------------------------------
hr("3. Proof instances: challenge space, ABDLOP MSIS (binding) and MLWE (hiding), sized for R_TX")
# Challenge space: sigma_{-1}-invariant c in R_q with coefficients in [-kappa, kappa] (LNP22 4.4): 32 free coefficients
# (c_0, c_1..c_31; c_{64-i} = -c_i, c_32 = 0). Operator norm s(c) = max_j |c(zeta_j)| <= eta, measured below.
theta = [math.pi * (2 * j + 1) / d for j in range(d // 2)]
EMB = np.array([[1.0] + [2 * math.cos(i * t) for i in range(1, d // 2)] for t in theta])
rng = np.random.default_rng(20261013)
chal = {}
for kappa in range(6, 10):
    c = rng.integers(-kappa, kappa + 1, size=(200_000, d // 2))
    op = np.abs(c @ EMB.T).max(axis=1)
    eta = int(math.ceil(np.quantile(op, 0.99)))
    acc = float((op <= eta).mean())
    logc = (d // 2) * log2(2 * kappa + 1) + log2(acc)
    chal[kappa] = (eta, acc, logc)
    print(f"kappa = {kappa}: eta (99% quantile of s(c), 2e5 samples) = {eta}, |C| = 2^{logc:.2f}, "
          f"final-round error 2/|C| = 2^-{logc - 1:.2f}, 2*kappa = {2 * kappa} < {ls18:.0f}: {2 * kappa < ls18}")
KAPPA = min(kk for kk, v in chal.items() if v[2] - 1 >= 128)
ETA, _, LOGC = chal[KAPPA]
print(f"=> kappa = {KAPPA}, eta = {ETA} (smallest kappa with 2/|C| <= 2^-128)")

# R_TX witness s1 (ring elements of R_q, CTR-PQZ-03 norms): s_f, e_f, r, e1 (32 each), e2_t/f/a (1 each), the 917
# binary digits of the integer rows (15 polys) and the slack bits of 7 exact l2 proofs (7 x 16 bits = 2 polys).
M1 = 4 * k + 3 + math.ceil(917 / d) + math.ceil(7 * 16 / d)
ALPHA = sqrt(2 * BETA_S**2 + 2 * BETA_E**2 + 3 * BETA_2**2 + 917 + 7 * 16)
LAM = math.ceil(128 / log2(q))  # Z_q amortization repetitions (q^-LAM <= 2^-128)
L_B = 256 // d + LAM + 1  # t_B rows: JL mask y3 (256/d), LAM garbage polys, 1 quadratic-garbage poly
GAMMA = 11  # Rej0 slack s = gamma*||cv||, expected repetitions M = exp(13.37/gamma + 1/(2 gamma^2))
M_REJ = math.exp(sqrt(2 * 129 * log(2)) / GAMMA + 1 / (2 * GAMMA**2))
print(f"R_TX: m1 = {M1} ring elements ({M1 * d} coefficients), ||s1|| <= alpha = {ALPHA:.1f}; lambda = {LAM} "
      f"(q^-{LAM} = 2^-{LAM * log2(q):.2f}; lambda = {LAM - 1} gives 2^-{(LAM - 1) * log2(q):.2f}); "
      f"t_B rows = {L_B}; gamma = {GAMMA} (M = {M_REJ:.2f} per masked vector)")


def msis_bound(m1, m2):
    s1 = GAMMA * ETA * ALPHA
    s2 = GAMMA * ETA * sqrt(m2 * d)  # s2 ternary, nu = 1
    b1 = 2 * s1 * sqrt(2 * m1 * d)
    b2 = 2 * s2 * sqrt(2 * m2 * d)
    return 8 * ETA * sqrt(b1**2 + b2**2)  # LNP22 ABDLOP binding: MSIS_{n, m1+m2, 8 eta sqrt(B1^2 + B2^2)}


def mlwe(rank, rows):
    return LWEParameters(n=rank * d, q=q, Xs=CBD1, Xe=CBD1, m=rows * d, tag=f"proof MLWE rank {rank}, {rows} rows")


def usvp_beta(p):
    return int(LWE.primal_usvp(p, red_cost_model=RC.ADPS16, red_shape_model="gsa")["beta"])


def min_rank(rows):
    lo, hi = 8, 96
    while lo < hi:
        mid = (lo + hi) // 2
        if usvp_beta(mlwe(mid, rows)) >= TARGET_BETA:
            hi = mid
        else:
            lo = mid + 1
    return lo


print("\nsizing search (fast: primal_usvp for MLWE, SIS lattice attack for MSIS; target beta >= "
      f"{TARGET_BETA}):")
for n_sis in range(8, 64):
    rows = n_sis + L_B
    rank = min_rank(rows)
    m2 = rank + rows
    B = msis_bound(M1, m2)
    sp = SISParameters(n=n_sis * d, q=q, length_bound=B, m=(M1 + m2) * d, norm=2, tag=f"proof MSIS n={n_sis}")
    sb = int(SIS.lattice(sp, red_cost_model=RC.ADPS16)["beta"])
    print(f"  n = {n_sis:2d}: MLWE rank {rank} -> m2 = {m2}; B = 2^{lg(B):.2f}; MSIS beta = {sb}", flush=True)
    if sb >= TARGET_BETA:
        break
N_SIS, M2, B_SIS = n_sis, m2, B
print(f"=> MSIS rank n = {N_SIS}, m2 = {M2} (MLWE rank {M2 - N_SIS - L_B}, {N_SIS + L_B} rows), "
      f"B = {B_SIS:.4g} = 2^{lg(B_SIS):.2f} (q = 2^{lg(q):.2f}); t_A = {N_SIS * d * 42 // 8} B")
proof_mlwe = mlwe(M2 - N_SIS - L_B, N_SIS + L_B)
proof_mlwe = proof_mlwe.updated(tag=f"proof MLWE (ABDLOP hiding, rank {M2 - N_SIS - L_B})")
lwe_rows[proof_mlwe.tag] = full_estimate(proof_mlwe)
proof_msis = SISParameters(n=N_SIS * d, q=q, length_bound=B_SIS, m=(M1 + M2) * d, norm=2,
                           tag=f"proof MSIS (ABDLOP binding, n = {N_SIS})")
sis_row = sis_estimate(proof_msis)

# ---- 4. Exactness of the norm proofs ------------------------------------------------------------------------------
hr("4. Exactness of the norm proofs (no wrap-around mod q)")
s3 = GAMMA * sqrt(337) * ALPHA  # JL mask width: ||R s|| <= sqrt(337) ||s|| except with prob 2^-128
b_jl = 2 * sqrt(2 * 256) * s3 / sqrt(30)  # extracted ||s1|| bound from the approximate (JL) proof
N_JL = M1 * d
print(f"JL extracted bound b' = 2 sqrt(512) s3 / sqrt(30) = {b_jl:.4g} = 2^{lg(b_jl):.2f}")
print(f"exact l2: b'^2 + beta_e^2 = 2^{lg(b_jl**2 + BETA_E**2):.2f} < q = 2^{lg(q):.2f}: {b_jl**2 + BETA_E**2 < q}")
print(f"modular JL: 41 * N * b' = 2^{lg(41 * N_JL * b_jl):.2f} < q: {41 * N_JL * b_jl < q}")
print(f"binary rows: largest reconstructed integer 2^25 (e_T + 2^24) < q: {2**25 < q}; "
      f"row 7 terms < 2^15 < q: {2**15 < q}")

# ---- 5. Per-round Fiat-Shamir soundness ---------------------------------------------------------------------------
hr("5. Per-round Fiat-Shamir soundness (LNP22 rounds, each on its own; section 5 of pq-zether.md)")
jl_unit = log2(sum(comb(256, i) for i in range(30))) - 256
rounds = [
    ("R1 JL projection R <- Bin^{256 x N} (LNP22 JL lemma, < 2^-128)", 128.0,
     f"unit-vector case exactly 2^{jl_unit:.2f}"),
    (f"R2 Z_q amortization, lambda = {LAM} repetitions (q^-lambda)", LAM * log2(q), ""),
    (f"R3 R_q aggregation of quadratic relations (q^-(d/l) = q^-{d // l})", (d // l) * log2(q), ""),
    (f"R4 final challenge c in C, kappa = {KAPPA}, eta = {ETA} (2/|C|)", LOGC - 1, ""),
]
for name, bits, note in rounds:
    print(f"{name:72s} {bits:8.2f} bits {'OK' if bits >= 128 else 'MISS'}  {note}")

# ---- 6. Gate ------------------------------------------------------------------------------------------------------
hr("6. Gate: every instance >= Kyber-512 under both models, every round >= 128 bits")
ky = lwe_rows[kyber.tag]
ok = True
print(f"{'instance':48s} {'classical':>22s} {'quantum':>22s}  usvp beta")
for tag, r in lwe_rows.items():
    c, qu = r["classical"], r["quantum"]
    good = c[0] >= ky["classical"][0] and qu[0] >= ky["quantum"][0]
    ok &= good
    print(f"{tag:48s} {c[0]:7.1f} ({c[1]:>13s}) {qu[0]:7.1f} ({qu[1]:>13s})  {c[2]:4d}  {'OK' if good else 'MISS'}")
c, qu = sis_row["classical"], sis_row["quantum"]
good = c[0] >= ky["classical"][0] and qu[0] >= ky["quantum"][0]
ok &= good
print(f"{proof_msis.tag:48s} {c[0]:7.1f} ({c[1]:>13s}) {qu[0]:7.1f} ({qu[1]:>13s})  {c[2]:4d}  {'OK' if good else 'MISS'}")
for name, b in hint_rows:
    good = b >= ky["classical"][2]  # same uSVP model as Kyber-512's usvp beta
    ok &= good
    print(f"{'DBDD ' + name:48s} {0.292 * b:7.1f} ({'usvp':>13s}) {0.265 * b:7.1f} ({'usvp':>13s})  {b:4d}  "
          f"{'OK' if good else 'MISS'}")
ok &= all(bits >= 128 for _, bits, _ in rounds)
print(f"\nGATE: {'MET' if ok else 'MISSED'}")
