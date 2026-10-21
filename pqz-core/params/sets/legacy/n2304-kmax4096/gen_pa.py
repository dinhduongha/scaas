#!/usr/bin/env python3
"""Plan 5h Task 8b: the LaZer codegen specs (<rel>_params.sage) of every PQZL relation at parameter set (a) (owner
2026-10-21; n-study candidate E): n = 2304 (k = 36), K_MAX = 4,096, q = 61,275,424,977,257, beta_s / beta_e and the bit
widths from pqz-core/pqzl/params/n-study/budget.py (m = 16 digit-sum bits, carries m - 3 = 13, e_T / e' + 2^26 in 27 bits). Shapes: the
production ones of the v3 set (pqz-core/pqzl/params/tx_params.sage, ...): reg, tx, tx0, burn, ds, dr, R_TXM M = 2 / 4 / 8 with and without the auditor
with G = ceil(M / 4) randomness groups (M = 8: G = 2, today's shape), and the bench-only M = 16 (G = 4, OVERSIZE).
pqz_delta 1.00366 and kmlwe_min 36 are n-study's e_s1 results at this cell; e_s1_n.sage re-checks every spec
(e-s1.txt). log2q rounded down as pqzl/params/n-study/gen_specs.py (LaZer's D loop hangs otherwise).
  python3 -I pqz-core/params/sets/n2304-kmax4096/gen_pa.py      -> <rel>_params.sage next to it
"""
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "pqzl", "params", "n-study"))
from budget import budget  # noqa: E402

N, K_MAX, Q = 2304, 4096, 61_275_424_977_257
KMLWE_MIN = 36


def specs():
    b = budget(N, K_MAX, Q)
    assert b["ok"] and b["D"] == Q // 2**18 == 233_747_196 and b["m"] == 16 and b["e_bits"] == 26
    k, bs, be, m, eb = N // 64, b["bs"], b["be"], b["m"], b["e_bits"] + 1
    assert (bs, be) == (38, 173)
    tx_bits = 64 + 64 + 16 * m + 15 * (m - 3) + 16 * eb  # d, d', M_i, c_i + 64, e_T + 2^26
    blk = f"{bs}^2 + {be}^2"
    log2q = Q.bit_length() if math.log2(Q) > Q.bit_length() - 0.01 else Q.bit_length() - 1
    head0 = (f"# n = {N} (k = {k}), q = {Q} (2^{math.log2(Q):.3f}, prime, q = 9 mod 16), Delta = {b['D']}, "
             f"beta_s = {bs}, beta_e = {be},\n# K_MAX = {K_MAX:,}: M_i {m} bits, carries {m - 3} bits (c_i + 64), "
             f"e_T / e' + 2^{eb - 1} in {eb} bits (set (a), owner 2026-10-21).\n"
             f"# pqz_delta / kmlwe_min: pqz-core/params/sets/n2304-kmax4096/e-s1.txt (MSIS beta >= 450, hiding MLWE uSVP and dual_hybrid >= 450).\n")
    out = {}

    def nb(bits):
        return math.ceil(bits / 64)

    def spec(name, what, ks, Bs, e2, bits, bprime, filler):
        nbin = nb(bits) if bits else 0
        m1 = len(ks) * k + e2 + nbin
        alpha = " + ".join(x for x in (f"{len(ks) // 2} * ({blk})" if len(ks) > 2 else blk,
                                       f"{e2} * 64^2" if e2 else "", f"{nbin} * 64" if nbin else "") if x)
        n = ", ".join([str(k)] * len(ks) + ["1"] * e2)
        B = ", ".join([str(x) for x in Bs] + ["64"] * e2)
        out[name] = (f"# Plan 5h Task 8b (set (a)): {what}\n" + head0 +
                     f"pqz_verbose = 1\nname = \"pqz_{name}\"\nq_fixed = {Q}\npqz_L = 4\nlog2q = {log2q}\n"
                     f"pqz_delta = 1.00366\nkmlwe_min = {KMLWE_MIN}\nd = 64\n\n"
                     f"m1 = {m1}\nalpha = sqrt({alpha})\nl = 0\n\nnbin = {nbin}\nn = [{n}]\nB = [{B}]\n\n"
                     f"# LaZer's tbox needs nprime > 0: a one-poly approximate l_inf proof as filler ({filler}).\n"
                     f"nprime = 1\nBprime = {bprime}\n")

    def debit(G):
        return [k] * (2 + 2 * G), [bs, be] * (1 + G)

    spec("reg", f"R_REG pk = A s + e; s1 = s, e ({k} polys each)", [k, k], [bs, be], 0, 0, 1, "s[0], in [-1, 1]")
    ks, Bs = debit(1)
    spec("tx", f"R_TX: s_f, e_f, r, e1 ({k} polys each), e2_t, e2_f, e2_a; {tx_bits} bits (d 64, d' 64, M 16x{m}, "
         f"c 15x{m - 3}, e_T 16x{eb})", ks, Bs, 3, tx_bits, 64, "e2_t, |coefficients| <= 20 < 64")
    spec("tx0", f"R_TX0 (auditor off): R_TX without e2_a; {tx_bits} bits", ks, Bs, 2, tx_bits, 64,
         "e2_t, |coefficients| <= 20 < 64")
    spec("burn", f"R_BURN / REFRESH: s_f, e_f, r, e1, e2_f; {tx_bits - 64} bits (d public)", ks, Bs, 1, tx_bits - 64,
         64, "e2_f, |coefficients| <= 20 < 64")
    spec("ds", f"R_DS: s1 = r, e1 ({k} polys each), e2_t", [k, k], [bs, be], 1, 0, 64, "e2_t, |coefficients| <= 20 < 64")
    spec("dr", f"R_DR: s1 = s, e ({k} polys each), e'_i + 2^{eb - 1} in {eb} bits ({16 * eb} bits)", [k, k], [bs, be], 0,
         16 * eb, 1, "s[0], in [-1, 1]")
    for M in (2, 4, 8, 16):
        G = (M + 3) // 4
        bits = tx_bits - 64 + 64 * M
        ks, Bs = debit(G)
        for aud in (1, 0):
            e2 = M + 1 + aud * M
            name = f"txm{M}" + ("" if aud else "0")
            what = (f"R_TXM M = {M}, G = {G} randomness group(s) of <= 4 legs, auditor {'on' if aud else 'off'}: s_f, "
                    f"e_f, (r_g, e1_g) x {G}, e2_j, e2_f" + (", e2_{a,j}" if aud else "") +
                    f"; {e2} e2 blocks, {bits} bits" + ("; OVERSIZE (bench builds only, -DPQZ_TXM_OVERSIZE)" if M == 16 else ""))
            spec(name, what, ks, Bs, e2, bits, 64, "e2_0, the first leg's noise, |coefficients| <= 20 < 64")
    return out


def main():
    for name, text in specs().items():
        with open(os.path.join(HERE, f"{name}_params.sage"), "w") as f:
            f.write(text)
    print(HERE)


if __name__ == "__main__":
    s = specs()
    # the shapes agree with n-study's specs at this cell (G = 1 up to M = 4) and with today's production layout
    assert "m1 = 163\n" in s["tx"] and "nbin = 16\n" in s["tx"] and "m1 = 160\n" in s["burn"] and "nbin = 15\n" in s["burn"]
    assert "m1 = 79\n" in s["dr"] and "m1 = 73\n" in s["ds"] and "m1 = 72\n" in s["reg"] and "log2q = 45\n" in s["tx"]
    assert "m1 = 172\n" in s["txm4"] and "m1 = 256\n" in s["txm8"] and "nbin = 23\n" in s["txm8"]
    main()
