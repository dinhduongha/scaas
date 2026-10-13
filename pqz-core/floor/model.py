#!/usr/bin/env python3
"""PQZL verifier floor: operation counts of a specialised LNP22 / tbox verifier for R_REG and R_TX times the unit
costs measured by kern.c (floor/runs/kern_{portable,native}.json). Prints the per-term table (markdown) for
docs/research/pqz-verifier-floor.md. Run: python3 -I floor/model.py [runs dir]   (self-check: python3 -I floor/model.py --check)

Counts follow the protocol, not LaZer's implementation (derivation in the note, section 3). Units:
P = ring products in the NTT domain, F / I = forward / inverse NTTs, G = PRG bytes, H = hashed bytes,
J = ternary multiply-accumulates of the JL fold, S = scalar mod-q multiplies, C = proof coefficients decoded and checked.
"""
import json
import os
import sys

D = 64
LAMBDA = 4
JL = 256

REL = {
    # tbox / quad_many dimensions from params/pqz_{tx,reg}_params.h
    "R_TX": dict(kmsis=23, m1=153, m2r=68 - 23, lB=12, K=32, lin_rows=2, nex=153, nprime=1, nbin=15, Z=7,
                 sum_n=131, Nq=64, Me=80, eval_vecs=4, stmt_bytes=82504, log2qD=31, log2m=23),
    "R_REG": dict(kmsis=22, m1=66, m2r=67 - 22, lB=12, K=32, lin_rows=1, nex=66, nprime=1, nbin=0, Z=2,
                  sum_n=64, Nq=32, Me=0, eval_vecs=0, stmt_bytes=16480, log2qD=33, log2m=25),
}


def terms(r):
    """[(name, per_proof_or_cacheable, counts dict)]"""
    k, m1, m2r, lB = r["kmsis"], r["m1"], r["m2r"], r["lB"]
    Ntot = LAMBDA // 2 + 2 + r["Nq"]
    halves = LAMBDA  # lambda/2 accumulators x 2 Z_q halves (coefficient 0 and d/2)
    t = []
    t.append(("ABDLOP: w = A1 z1 + A2' z21 - c 2^D tA1 (+ INTT w, dcompress)", "proof",
              dict(P=k * (m1 + m2r + 1), F=m1 + m2r + k + 1, I=k)))
    t.append(("B rows: c tB - B' z21 (garbage / y3 / y4 / beta / g commitments)", "proof",
              dict(P=lB * (m2r + 1), F=lB)))
    t.append(("Statement R_q-linear rows: A s + e = pk (R_TX also A^T r + e1 = u)", "proof",
              dict(P=r["lin_rows"] * r["K"] ** 2)))
    t.append(("Statement Z_q rows (R_TX: 80 evaluation eqs: pk^T r, u_T^T s, digits)", "proof",
              dict(P=r["eval_vecs"] * r["K"] + (halves * (r["eval_vecs"] + 15 + 3) if r["eval_vecs"] else 0),
                   S=(r["Me"] * halves * 64 if r["Me"] else 0))))
    t.append(("Norm-proof quadratic terms: o(z_i) z_i (l2, binary), upsilon, beta", "proof",
              dict(P=r["sum_n"] + r["nbin"] + r["Z"] + 3, S=(2 * (D - 1) + 1 + 1 + r["Z"]) * halves * 2)))
    nexd, npd = r["nex"] * D, r["nprime"] * D
    t.append(("JL (l2 approx, 256 rows): expand R, fold V^T R, <vR, o(z)> beta", "proof",
              dict(P=LAMBDA * (r["nex"] + r["nprime"]) + 2 * LAMBDA, F=LAMBDA * (r["nex"] + r["nprime"]),
                   G=JL * (2 * nexd // 8 + 2 * npd // 8), J=LAMBDA * JL * (nexd + npd), S=2 * LAMBDA * JL)))
    t.append(("Quad-many fold: sum_k mu_k F_k(z), c r1 z, c^2 r0; mu expansion", "proof",
              dict(P=Ntot + r["Nq"] + 4, F=Ntot + 2, I=1, G=Ntot * D * 6)))
    nV = 2 * r["Me"] + 2 * 2 * (D - 1) + 2 + (2 if r["nbin"] else 0) + 2 * r["Z"] + 2 * LAMBDA * JL
    tr = (k * D * r["log2qD"] + lB * D * 42 + 9 * D * 42 + 2 * D * 42 + 2 * D * 42 + k * D * r["log2m"]) // 8
    # LaZer opens one PRG stream per challenge domain (JL rows, each evaluation equation's Z_q vector): ndom
    # streams under 4 distinct seeds. AES-256-CTR keys on the seed (nonce = domain), so a specialised verifier
    # expands 4 keys and pays one batch start (~128 B of keystream) per domain.
    ndom = 1 + 2 * (D - 1) + 1 + (1 if r["nbin"] else 0) + r["Z"] + 2 + 1 + 2 * JL
    t.append(("Fiat-Shamir: statement + transcript hashing, Z_q challenge expansion", "proof",
              dict(H=r["stmt_bytes"] + tr, G=nV * 6 + ndom * 128, R=4)))
    ncoef = (m1 + m2r + 8 + lB + 2 * k + 2 + 1) * D
    t.append(("Decode proof, norm checks (z1, z21, z3, z4, w1 - gamma hint, h)", "proof", dict(C=ncoef)))
    stmt_ntt = (r["lin_rows"] * r["K"] + r["eval_vecs"] * r["K"])
    t.append(("Statement polys to NTT (pk, u, u_T): per account / per tx, cacheable per account", "cache",
              dict(F=stmt_ntt)))
    t.append(("A, A^T, A1, A2', B' in NTT form", "param", dict()))
    return t


def load(path):
    u = {}
    if os.path.exists(path):
        for line in open(path):
            o = json.loads(line)
            if "op" in o:
                u[o["op"]] = o["ns"]
    return u


def unit_costs(runs):
    """ns per unit for each build column"""
    p, n = load(os.path.join(runs, "kern_portable.json")), load(os.path.join(runs, "kern_native.json"))
    w = {k[len("wasm "):]: v for k, v in load(os.path.join(runs, "kern_wasm.json")).items()}

    def g(u, prefix):
        for key, v in u.items():
            if key.startswith(prefix):
                return v
        raise KeyError(prefix)

    cols = {}
    # (a) the fork's primitives as they are (portable C, -O2): incomplete NTT mod q, bitsliced AES, its SHAKE128
    cols["fork prims"] = dict(P=g(p, "fork pqz_ntt_basemul"), F=g(p, "fork pqz_ntt_fwd"), I=g(p, "fork pqz_ntt_inv"),
                              G=g(p, "fork AES-256-CTR") / 2 ** 20, H=g(p, "fork SHAKE128 absorb") / 65536,
                              J=g(p, "R_TX JL fold vR = V^T R") / (LAMBDA * JL * 153 * D),
                              R=g(p, "fork rng_init"), S=g(p, "scalar mod-q multiply") / 4096, C=10.0,
                              W={"R_TX": g(p, "R_TX w = A1"), "R_REG": g(p, "R_REG w = A1")})
    # (b) portable C, best representation: CRT 3 x 30-bit (3 products, 3 NTTs + CRT per poly); PRG still AES
    crt_ntt = 3 * g(p, "crt30 ntt_fwd")
    cols["portable CRT"] = dict(cols["fork prims"], P=3 * g(p, "crt30 pointwise"), F=crt_ntt,
                                I=3 * g(p, "crt30 ntt_inv") + 64 * 30.0,
                                W={"R_TX": g(p, "R_TX w mat-vec, CRT 3 x 30-bit scalar"),
                                   "R_REG": g(p, "R_REG w mat-vec, CRT 3 x 30-bit scalar")})
    # (b') same with SHAKE128 as the PRG (protocol change on both sides)
    cols["portable CRT, SHAKE PRG"] = dict(cols["portable CRT"], G=g(p, "fork SHAKE128 squeeze") / 2 ** 20,
                                           R=g(p, "fork SHAKE128 absorb") / 65536 * 168 * 2)
    # (b'') the portable columns in wasm32 (node, no SIMD): measured kernels; scalar mod-q and decode scaled by the
    # measured wasm / native ratio of the CRT pointwise kernel
    if w:
        r = g(w, "crt30 pointwise") / g(p, "crt30 pointwise")
        cols["wasm fork prims"] = dict(P=g(w, "fork pqz_ntt_basemul"), F=g(w, "fork pqz_ntt_fwd"),
                                       I=g(w, "fork pqz_ntt_inv"), G=g(w, "fork AES-256-CTR") / 2 ** 20,
                                       H=g(w, "fork SHAKE128 absorb") / 65536,
                                       J=g(w, "R_TX JL fold") / (LAMBDA * JL * 153 * D), R=g(w, "fork rng_init"),
                                       S=cols["fork prims"]["S"] * r, C=10.0 * r)
        cols["wasm CRT, SHAKE PRG"] = dict(cols["wasm fork prims"], P=3 * g(w, "crt30 pointwise"),
                                           F=3 * g(w, "crt30 ntt_fwd"), I=3 * g(w, "crt30 ntt_inv") + 64 * 30.0 * r,
                                           G=g(w, "fork SHAKE128 squeeze") / 2 ** 20,
                                           R=g(w, "fork SHAKE128 absorb") / 65536 * 168 * 2)
    # (c) AVX2: CRT 3 x 30-bit, 4 lanes; AES-NI and OpenSSL SHAKE; JL AVX2
    if n:
        cols["AVX2"] = dict(P=3 * g(n, "crt30 pointwise multiply-accumulate x4") / 4,
                            F=3 * g(n, "crt30 ntt_fwd x4") / 4, I=3 * g(n, "crt30 ntt_inv x4") / 4 + 64 * 10.0,
                            G=g(n, "OpenSSL 3.0 AES-256-CTR") / 2 ** 20,
                            H=g(n, "OpenSSL 3.0 SHAKE128 absorb") / 65536,
                            J=g(n, "R_TX JL fold, AVX2") / (LAMBDA * JL * 153 * D),
                            R=200.0, S=g(n, "scalar mod-q multiply") / 4096, C=3.0,
                            W={"R_TX": g(n, "R_TX w mat-vec, CRT 3 x 30-bit AVX2"),
                               "R_REG": g(n, "R_REG w mat-vec, CRT 3 x 30-bit AVX2")})
    return cols


def floor(rel, cols):
    out = {}
    for c, u in cols.items():
        rows = []
        for name, kind, cnt in terms(REL[rel]):
            ns = sum(cnt.get(x, 0) * u.get(x, 0) for x in "PFIGHJRSC")
            if name.startswith("ABDLOP") and rel in u.get("W", {}):
                ns = u["W"][rel]  # measured prototype (kern.c section 2), NTTs and CRT included
            rows.append((name, kind, cnt, ns))
        out[c] = rows
    return out


def main():
    if sys.argv[1:] == ["--check"]:
        t = {n: c for n, _, c in terms(REL["R_TX"])}
        assert t["ABDLOP: w = A1 z1 + A2' z21 - c 2^D tA1 (+ INTT w, dcompress)"]["P"] == 23 * 199
        assert t["JL (l2 approx, 256 rows): expand R, fold V^T R, <vR, o(z)> beta"]["G"] == 256 * (2448 + 16)
        print("ok")
        return
    runs = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "runs")
    cols = unit_costs(runs)
    print("unit costs (ns):")
    for c, u in cols.items():
        print(f"  {c}: " + ", ".join(f"{k}={v:.2f}" for k, v in u.items() if k != "W"))
    for rel in REL:
        res = floor(rel, cols)
        print(f"\n### {rel}\n")
        hdr = "| Term | Kind | Counts | " + " | ".join(f"{c} (ms)" for c in cols) + " |"
        print(hdr)
        print("|" + "---|" * (3 + len(cols)))
        names = [r[0] for r in next(iter(res.values()))]
        for i, nm in enumerate(names):
            cnt = next(iter(res.values()))[i][2]
            kind = next(iter(res.values()))[i][1]
            cs = ", ".join(f"{k} {v:,}" for k, v in cnt.items())
            print(f"| {nm} | {kind} | {cs} | " + " | ".join(f"{res[c][i][3] / 1e6:.3f}" for c in cols) + " |")
        print("| **Total per proof** | | | " + " | ".join(
            f"**{sum(r[3] for r in res[c] if r[1] == 'proof') / 1e6:.2f}**" for c in cols) + " |")
        print("| Total incl. statement NTTs (no per-account cache) | | | " + " | ".join(
            f"{sum(r[3] for r in res[c]) / 1e6:.2f}" for c in cols) + " |")
        tot = {}
        for x in "PFIGHJRSC":
            tot[x] = sum(r[2].get(x, 0) for r in next(iter(res.values())) if r[1] != "param")
        print("\ncount totals: " + ", ".join(f"{k} {v:,}" for k, v in tot.items()))


if __name__ == "__main__":
    main()
