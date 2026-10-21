#!/usr/bin/env python3
"""Plan 5h Task 7c: LaZer codegen specs (<rel>_params.sage) for one n-study cell, the 16k specs of ../p16k/ with
n (k = n / 64), q, beta_s / beta_e and the bit widths of the cell (m = digit-sum bits, carries m - 3, e_T / e'
log2 E + 1 bits); the shapes are the 16k ones: reg, tx, tx0, burn, ds, dr, txm2 / txm20, txm4 / txm40 (op 7 on chain
M <= 4, one randomness group). pqz_delta / kmlwe_min start at the 16k values' defaults (no kmlwe_min: the codegen's
own rank); e_s1_n.sage raises them. log2q: see `specs`.
  python3 -I gen_specs.py <n> <K_MAX> <q> [kmlwe_min]   -> specs/n<n>k<K>/<rel>_params.sage
"""
import math
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from budget import budget  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def specs(n, K, q, kmin=None):
    b = budget(n, K, q)
    assert b["ok"]
    k, bs, be, m, eb = n // 64, b["bs"], b["be"], b["m"], b["e_bits"] + 1
    tx_bits = 64 + 64 + 16 * m + 15 * (m - 3) + 16 * eb
    blk = f"{bs}^2 + {be}^2"
    # LaZer sizes kmsis at 2^log2q and then needs the exact q to pass the same root-Hermite test (its D loop never ends
    # otherwise: q = 2^47.80 with log2q = 48 hung). Round down unless q sits just below a power of two (the 16k and
    # today's specs: 2^50 - 42,310,535 -> 50, 2^42 - 215 -> 42).
    log2q = q.bit_length() if math.log2(q) > q.bit_length() - 0.01 else q.bit_length() - 1
    out = {}

    def spec(name, what, m1, alpha, nbin, ns, Bs, bprime):
        head = (f"# Plan 5h Task 7c (n-study research spec, not a relation): {what}\n"
                f"# n = {n} (k = {k}), q = {q} (2^{math.log2(q):.3f}), beta_s = {bs}, beta_e = {be}, K_MAX = {K:,}: "
                f"M_i {m} bits, carries {m - 3}, e_T / e' {eb} bits.\n")
        body = (f"pqz_verbose = 1\nname = \"pqz_{name}\"\nq_fixed = {q}\npqz_L = 4\nlog2q = {log2q}\n"
                f"pqz_delta = 1.00366\n" + (f"kmlwe_min = {kmin}\n" if kmin else "") + "d = 64\n\n"
                f"m1 = {m1}\nalpha = sqrt({alpha})\nl = 0\n\nnbin = {nbin}\nn = {ns}\nB = {Bs}\n\n"
                f"nprime = 1\nBprime = {bprime}\n")
        out[name] = head + body

    def nb(bits):
        return math.ceil(bits / 64)

    spec("reg", "R_REG pk = A s + e", 2 * k, blk, 0, [k, k], [bs, be], 1)
    for name, e2, bits, what in (("tx", 3, tx_bits, "R_TX"), ("tx0", 2, tx_bits, "R_TX0 (auditor off)"),
                                 ("burn", 1, tx_bits - 64, "R_BURN / REFRESH")):
        spec(name, f"{what}, {e2} e2 blocks, {bits} bits", 4 * k + e2 + nb(bits),
             f"2 * ({blk}) + {e2} * 64^2 + {nb(bits)} * 64", nb(bits), [k] * 4 + [1] * e2, [bs, be] * 2 + [64] * e2, 64)
    spec("ds", "R_DS", 2 * k + 1, f"{blk} + 64^2", 0, [k, k, 1], [bs, be, 64], 64)
    dr = 16 * eb
    spec("dr", f"R_DR, e' {eb} bits ({dr} bits)", 2 * k + nb(dr), f"{blk} + {nb(dr)} * 64", nb(dr), [k, k], [bs, be], 1)
    for M in (2, 4):
        bits = tx_bits - 64 + 64 * M
        for aud, e2 in ((1, 2 * M + 1), (0, M + 1)):
            name = f"txm{M}" + ("" if aud else "0")
            spec(name, f"R_TXM M = {M}, G = 1, auditor {'on' if aud else 'off'}, {e2} e2 blocks, {bits} bits",
                 4 * k + e2 + nb(bits), f"2 * ({blk}) + {e2} * 64^2 + {nb(bits)} * 64", nb(bits),
                 [k] * 4 + [1] * e2, [bs, be] * 2 + [64] * e2, 64)
    return out


def main():
    n, K, q = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
    kmin = int(sys.argv[4]) if len(sys.argv) > 4 else None
    d = os.path.join(HERE, "specs", f"n{n}k{K}")
    os.makedirs(d, exist_ok=True)
    for name, text in specs(n, K, q, kmin).items():
        with open(os.path.join(d, f"{name}_params.sage"), "w") as f:
            f.write(text)
    print(d)


if __name__ == "__main__":
    # self-check: at the 16k cell the generator reproduces the bit layout and witness shapes of ../p16k/
    s = specs(2560, 16384, 2**50 - 42_310_535)
    assert "m1 = 181\n" in s["tx"] and "nbin = 18\n" in s["tx"] and "m1 = 178\n" in s["burn"] and "nbin = 17\n" in s["burn"]
    assert "m1 = 88\n" in s["dr"] and "m1 = 184\n" in s["txm2"] and "m1 = 190\n" in s["txm4"] and "m1 = 186\n" in s["txm40"]
    assert "m1 = 182\n" in s["txm20"] and "m1 = 81\n" in s["ds"] and "m1 = 80\n" in s["reg"] and "log2q = 50\n" in s["tx"]
    assert "log2q = 47\n" in specs(2304, 8192, 245122345819289)["tx"]
    main()
