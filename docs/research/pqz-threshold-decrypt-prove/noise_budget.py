# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Paper arithmetic for docs/research/pqz-threshold-decrypt-prove.md (no timing, no calibration).
# Inputs: pqz-core/params/sets/<set>/set.json (read at run time) and the rules of pq-zero-knowledge.md §4.3.
import json, math, sys, os

ROOT = sys.argv[1]
SETS = ["n2048-kmax1024", "n2304-kmax4096", "n2560-kmax16384", "n2816-kmax65536"]
L2 = lambda x: math.log2(x)

def load(s):
    j = json.load(open(os.path.join(ROOT, "pqz-core/params/sets", s, "set.json")))
    q, d, kmax, bf, e, n = j["q"], j["delta"], j["k_max"], j["b_fresh"], j["e"], j["n"]
    # self-checks against the set files and the spec
    assert bf == j["beta_e"] * j["beta_s"] * 2 + j["beta_2"], s       # B_FRESH = 2 beta_e beta_s + beta_2
    assert (kmax - 1) * bf < e < d // 2, s                              # proof range and honest rounding
    return dict(q=q, d=d, kmax=kmax, bf=bf, e=e, n=n, mbits=j["mbits"],
                qd=round(L2(q / d)))

P = {s: load(s) for s in SETS}
assert P["n2304-kmax4096"]["d"] == 61275424977257 // 2**18
assert (4096 - 1) * 13212 == 54103140

print("== per set")
for s, p in P.items():
    acc = (p["kmax"] - 1) * p["bf"]
    print(f"{s}: log2q {L2(p['q']):.2f} q/D 2^{p['qd']} D {p['d']} (2^{L2(p['d']):.2f}) D/2 2^{L2(p['d']/2):.2f} "
          f"BF {p['bf']} (2^{L2(p['bf']):.2f}) acc {acc} (2^{L2(acc):.2f}) E 2^{L2(p['e']):.0f} "
          f"head fresh 2^{L2(p['d']/2-p['bf']):.2f} acc 2^{L2(p['d']/2-acc):.2f} ratio fresh {p['d']/2/p['bf']:.0f} acc {p['d']/2/acc:.3f}")

# Uniform smudging, statistical distance by a hybrid over N = 16 Q coefficients:
#   SD <= N * B / (2 B_sm + 1) <= 2^-kappa  =>  B_sm = N B 2^kappa / 2
# Correctness (deterministic, t partial shares each smudged): B + t B_sm < D/2
print("== uniform smudging: log2 B_sm, log2(B + t B_sm) over D/2, log2 q needed (q/D kept)")
for s, p in P.items():
    for kind, B in (("fresh", p["bf"]), ("acc", (p["kmax"] - 1) * p["bf"])):
        for kappa in (40, 80):
            for Q in (1, 2**20):
                row = []
                for t in (2, 3, 4):
                    bsm = 16 * Q * B * 2**kappa / 2
                    need = B + t * bsm
                    row.append(f"t{t}: Bsm 2^{L2(bsm):.1f} over 2^{L2(need/(p['d']/2)):.1f} q>=2^{L2(2*need)+p['qd']:.1f}")
                print(s, kind, f"k{kappa}", f"Q2^{int(L2(Q))}", " | ".join(row))

# Best statistical distance reachable inside today's D (one decryption, Q = 1): B_sm = (D/2 - B)/t
print("== best SD inside today's parameters, Q = 1")
for s, p in P.items():
    for kind, B in (("fresh", p["bf"]), ("acc", (p["kmax"] - 1) * p["bf"])):
        r = []
        for t in (2, 3, 4):
            bsm = (p["d"] / 2 - B) / t
            sd = 16 * B / (2 * bsm)
            r.append(f"t{t}: SD 2^{L2(sd):.1f}")
        print(s, kind, " ".join(r))

# Gaussian flooding by Renyi divergence of order 2 (search-type or public-sampleable arguments only):
#   per coefficient R_2 = exp(2 pi x^2 / s^2), N = 16 Q coefficients, R_2 <= e  =>  s = B sqrt(2 pi N), sigma = s / sqrt(2 pi) = B sqrt(16 Q)
#   correctness with a 13-sigma tail per coefficient (P ~ 2^-125): B + 13 sigma sqrt(t) < D/2  =>  Q_max
print("== Renyi (order 2 <= e) Gaussian flooding: largest Q per key, tail 13 sigma")
for s, p in P.items():
    for kind, B in (("fresh", p["bf"]), ("acc", (p["kmax"] - 1) * p["bf"])):
        r = []
        for t in (2, 3, 4):
            x = (p["d"] / 2 - B) / (13 * 4 * B * math.sqrt(t))
            r.append(f"t{t}: Qmax " + (f"2^{L2(x*x):.1f}" if x >= 1 else f"<1 (2^{L2(x*x):.1f})"))
        print(s, kind, " ".join(r))
p = P["n2304-kmax4096"]
print("check Renyi n2304 fresh t3 Q=2^12:", f"2^{L2(p['bf'] + 13*4*p['bf']*math.sqrt(3*2**12)):.2f}", "< D/2", f"2^{L2(p['d']/2):.2f}")

# Exact noise leak: unknowns (s, e) = 2n integers; a decryption that reveals the noise of a ciphertext whose
# (r, e1, e2) the observer chose gives 16 exact integer equations (h_i = (e^T r - s^T e1)[i] + e2[i]).
print("== chosen-credit key recovery if noise is ever opened: ceil(2n/16) credits")
for s, p in P.items():
    print(s, math.ceil(2 * p["n"] / 16))

# Honest (non-adversarial) noise of one fresh credit, CBD variances sigma_s^2 = 1/2, sigma_e^2 = 10 (context only)
print("== honest fresh noise sigma (context)")
for s, p in P.items():
    print(s, f"{math.sqrt(10 * p['n'] + 10):.1f}")
