# -*- coding: utf-8 -*-
# Plan Task 5h (design), owner choice A' (decisions CTR-PQZ-06, 2026-10-19): larger lattice parameters so that
# K_MAX ~ 65,536. For each candidate (n = 64 k, q, K): the noise and digit budget of pq-zero-knowledge.md §4.3
# generalised, the sizes, and the encryption security with the pinned tools:
#   - lattice-estimator 53da598: primal uSVP beta (ADPS16, GSA) of the key and encryption instances for every
#     candidate, and the full LWE.estimate (ADPS16 classical and quantum) for the instances named in FULL;
#   - leaky-LWE-Estimator 0a9caf8 (DDGR20): perfect hints on the shared (r, e1), worst-case maximal-norm mixed forms,
#     as params/anon/hints.sage (16 per key; 32 = R_TX with the auditor, 80 = R_TXM group of 4 legs + auditor).
# Run by aprime/run.sh in the pinned Sage image; stdout is aprime/aprime.txt.
import os
import sys
import math
from functools import lru_cache
from copy import deepcopy

LK_COMMIT = os.environ.get("LK_COMMIT", "unknown")
LE_COMMIT = os.environ.get("LE_COMMIT", "unknown")
assert LK_COMMIT.startswith("0a9caf8") and LE_COMMIT.startswith("53da598"), (LK_COMMIT, LE_COMMIT)
os.chdir("/lk/framework")
load("/lk/framework/DBDD_predict_diag.sage")
_compute_delta = compute_delta
compute_delta = lru_cache(maxsize=None)(lambda k: RR(_compute_delta(k)))  # pure; memoized as in anon/hints.sage

from estimator import LWE, ND, RC, schemes
from estimator.lwe_parameters import LWEParameters
from estimator.reduction import ADPS16
from sage.version import version as SAGE_VERSION

VAR_S, VAR_E = 0.5, 10.0          # CBD(1), CBD(20), unchanged
BETA_2 = 64                       # e2: 16 coefficients, independent of n
DENY = ("arora-gb", "bkw", "bdd_mitm_hybrid")
MODELS = {"classical": RC.ADPS16, "quantum": ADPS16(mode="quantum")}
TARGET = 450
SMOKE = bool(os.environ.get("SMOKE"))


def hr(t):
    print("\n" + "=" * 110 + "\n" + t + "\n" + "=" * 110, flush=True)


def prime_9_16(bits):
    """the largest prime q < 2^bits with q = 9 mod 16 (X^64 + 1 splits into l = 4 factors, as CTR-PQZ-03)"""
    q = 2**bits - 7  # = 9 mod 16
    while not is_prime(q):
        q -= 16
    return q


def norm_bounds(n):
    """beta_s, beta_e at today's distance above the mean squared norm: 12.02 s.d. for CBD(1) (36 at n = 2048), 10.15 s.d.
    for CBD(20) (164 at n = 2048); var(x^2) = 1/4 (CBD(1)), 195 (CBD(20): mu4 = 3 sigma^4 - eta/4 = 295)"""
    bs = math.ceil(math.sqrt(n / 2 + 12.02 * math.sqrt(n / 4)))
    be = math.ceil(math.sqrt(10 * n + 10.15 * math.sqrt(195 * n)))
    return bs, be


def budget(n, q, K):
    """pq-zero-knowledge.md §4.3 with K units: digits M_i in [0, 2^m), m = bitlen(15 K); Delta = floor(q / 2^(m+2)) (so
    Delta 2^m <= q/4, today q / 2^16); e_T in [-E, E), E = 2^ceil(log2(K B)); uniqueness 2E <= Delta; mint threshold
    Delta - E against the reachable (K - 1) B (the plain term has noise 0)."""
    bs, be = norm_bounds(n)
    B = be * bs + bs * be + BETA_2
    m = int(15 * K).bit_length()
    D = q // 2**(m + 2)
    E = 2**int(math.ceil(math.log2(K * B)))
    ok = 2 * E <= D and D * (2**m - 1) + E < q // 2 and K * B <= E
    kfit = min(int(D // 4 // B), (2**m - 1) // 15)   # largest K with K B <= Delta/4 and 15 K < 2^m (same m)
    return dict(bs=bs, be=be, B=B, m=m, D=D, E=E, ok=ok, margin=float(D - E) / ((K - 1) * B), KB=K * B, kfit=kfit,
                bits=2 * 16 * 4 + 16 * m + 15 * (m - 3) + 16 * (int(math.log2(E)) + 1))


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
    """worst-case mixed hints (anon/hints.sage section 2): a unit hint on r plus the volume of w^T Sigma w = V_max"""
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


def full(tag, n, m, q):
    p = LWEParameters(n=n, q=q, Xs=ND.CenteredBinomial(1), Xe=ND.CenteredBinomial(20), m=m, tag=tag)
    row = {}
    for name, model in MODELS.items():
        r = LWE.estimate(p, red_cost_model=model, deny_list=DENY, jobs=2)
        b = min(r, key=lambda a: r[a]["rop"])
        row[name] = (float(math.log2(r[b]["rop"])), b, int(r[b]["beta"]))
        print(f"  {tag} {name}: 2^{row[name][0]:.1f} ({b}, beta {row[name][2]}); usvp beta {int(r['usvp']['beta'])}",
              flush=True)
    return row


hr("0. Environment")
print(f"lattice-estimator {LE_COMMIT}, leaky-LWE-Estimator (DDGR20) {LK_COMMIT}, SageMath {SAGE_VERSION}, "
      f"Python {sys.version.split()[0]}; SMOKE={SMOKE}")

Q42 = 2**42 - 215
assert is_prime(Q42) and Q42 % 16 == 9
CANDS = [  # (label, n, q, K)
    ("today", 2048, Q42, 1024),
    ("spec option A", 2560, prime_9_16(50), 4096),
    ("A' n=2560", 2560, prime_9_16(54), 65536),
    ("A' n=2688", 2688, prime_9_16(54), 65536),
    ("A' n=2816", 2816, prime_9_16(54), 65536),
    ("A' n=3072", 3072, prime_9_16(54), 65536),
    ("A' n=3072 q55", 3072, prime_9_16(55), 65536),
]
FULL = ("today", "spec option A", "A' n=2688", "A' n=2816")
if SMOKE:
    CANDS = [("smoke", 512, prime_9_16(42), 1024)]
    FULL = ()
# ONLY = comma-separated candidate indexes for sections 2-3 (memory: one n ~ 3000 DDGR instance needs ~4 GB);
# PARTS = "2", "3" or "23" (default); section 1 always runs.
ONLY = [int(x) for x in os.environ.get("ONLY", "").split(",") if x]
PARTS = os.environ.get("PARTS", "23")
SEL = [c for i, c in enumerate(CANDS) if not ONLY or i in ONLY]
print(f"ONLY={ONLY or 'all'} PARTS={PARTS}")

hr("1. Noise and digit budget (pq-zero-knowledge.md §4.3 generalised) and sizes")
print("B = 2 beta_e beta_s + 64; m = bitlen(15 K) digit-sum bits; Delta = floor(q / 2^(m+2)); E = 2^ceil(log2(K B));\n"
      "ok: 2E <= Delta (uniqueness), Delta (2^m - 1) + E < q/2, K B <= E; margin = (Delta - E) / ((K - 1) B) (today 4.14);\n"
      "K fit = largest K with K B <= Delta/4 at the same m; bits = the binary decomposition of R_TX (today 917)")
print("%-16s %3s %7s %8s %6s %4s %4s %6s %3s %10s %7s %8s %3s %7s %7s %5s %9s %7s" % ("candidate", "k", "log2 q", "q mod16",
      "K", "b_s", "b_e", "B", "m", "log2 Delta", "log2 E", "log2 KB", "ok", "margin", "K fit", "bits", "pk / u B", "ct B"))
BUD = {}
for lab, n, q, K in CANDS:
    b = budget(n, q, K)
    BUD[lab] = b
    print(f"{lab:16s} {n // 64:3d} {float(math.log2(q)):7.3f} {q % 16:8d} {K:6d} {b['bs']:4d} {b['be']:4d} {b['B']:6d} "
          f"{b['m']:3d} {float(math.log2(b['D'])):10.3f} {int(math.log2(b['E'])):7d} {float(math.log2(b['KB'])):8.3f} "
          f"{'yes' if b['ok'] else 'NO':>3s} {b['margin']:7.2f} {b['kfit']:7d} {b['bits']:5d} {8 * n:9d} {8 * n + 128:7d}")
for lab, n, q, K in CANDS:
    print(f"  {lab}: q = {q} (0x{q:x}), Delta = {BUD[lab]['D']}, LS18 bound q^(1/4)/2 = {float(q**0.25 / 2):.0f}")

hr("2. Encryption security: lattice-estimator primal uSVP (ADPS16, GSA) and DDGR20 worst-case mixed hints on (r, e1)")
print("key: pk = A s + e (m = n); enc: (u, v_t, v_f, v_a) (m = n + 48); DDGR20: m = n + 16 as anon/hints.sage, V_max =\n"
      "var_s beta_e^2 + var_e beta_s^2 with the candidate's bounds; 32 hints = R_TX with the auditor, 80 = R_TXM group\n"
      "(4 legs + auditor). Core-SVP 0.292 beta / 0.265 beta.")
print("%-16s %9s %9s %8s %8s %8s %14s %10s" % ("candidate", "key usvp", "enc usvp", "DDGR h0", "DDGR h32", "DDGR h80",
      "core-SVP@h80", "ok@h80"))
counts = (0, 32, 80)
for lab, n, q, K in (SEL if "2" in PARTS else []):
    b = BUD[lab]
    vmax = VAR_S * b["be"]**2 + VAR_E * b["bs"]**2
    h = ddgr(n, q, vmax, counts)
    ku, eu = usvp(n, n, q), usvp(n, n + 48, q)
    print(f"{lab:16s} {ku:9d} {eu:9d} {h[0]:8.2f} {h[32]:8.2f} {h[80]:8.2f} "
          f"{0.292 * h[80]:6.1f} / {0.265 * h[80]:5.1f} {'yes' if h[80] >= TARGET else 'NO':>10s}", flush=True)

hr("3. Full LWE.estimate (deny arora-gb, bkw, bdd_mitm_hybrid), ADPS16 classical and quantum")
ky = schemes.Kyber512
print(f"reference: Kyber-512 usvp beta {int(LWE.primal_usvp(ky, red_cost_model=RC.ADPS16, red_shape_model='gsa')['beta'])}")
for lab, n, q, K in (SEL if "3" in PARTS else []):
    if lab in FULL:
        full(f"{lab} key (m = n)", n, n, q)
        full(f"{lab} enc (m = n + 48)", n, n + 48, q)
print("\ndone")
