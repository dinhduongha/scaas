#!/usr/bin/env python3
"""Plan 5h Task 7 (D25, spec 2026-10-20 §6.5): PQZH Ligero at the 16k parameters, q = 2^50 - 42,310,535, n = 2560.

Stdlib only. The row layout is the crate's `cs::Layout::new` and the proof bound its `Params::max_len_exact`
(pqz-core/pqzh/ligero/src/{cs,ligero}.rs) with the widths as parameters; soundness (t), the FFT smoothness rule and
the prover-work model come from ../../../pqzh/ligero/ligero_params.py (imported, unchanged). The self-check reproduces
the crate's pinned bounds at today's parameters (test `limits_exact`) before printing the 16k numbers.
Every 16k number is an [estimate] of the model, not a measured proof (the crate is switched in plan Task 8).

  python3 -I pqz-core/pqzl/params/p16k/ligero16k.py > pqz-core/pqzl/params/p16k/ligero-16k.txt
"""
import math
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "pqzh", "ligero"))
import ligero_params as lp  # noqa: E402

BLIND, DIG, POLYS = 12, 32, 3   # blinding base rows, Keccak digest, test polynomials (as ligero.rs)
MAX_PROOF_PQZH, MAX_INPUT_TODAY, MAX_INPUT_16K = 262_144, 393_216, 512 * 1024


def factor(n):
    return lp.factor(n)


def is_prime(n):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):   # deterministic below 3.3e24
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


class P:
    """the parameters a layout depends on: ring size N, value bits of the CBD(1) / CBD(20) groups and their l2 slacks,
    digit-sum M bits, carry bits / offset, e_T (and R_DR e') bits / offset, bytes per F_q element"""
    def __init__(self, N, eb, s_bits=7, e_bits=9, sl_s=11, sl_e=15, m_bits=14, c_bits=11, et_bits=25):
        self.N, self.eb, self.s_bits, self.e_bits = N, eb, s_bits, e_bits
        self.sl_s, self.sl_e, self.m_bits, self.c_bits, self.et_bits = sl_s, sl_e, m_bits, c_bits, et_bits


TODAY = P(2048, 6)
# 16k: N = 2560; |s| <= 40 < 64 (7 bits, off 64), |e| <= 182 < 256 (9 bits, off 256) unchanged; l2 slacks 40^2 = 1,600
# < 2^11, 182^2 = 33,124 < 2^16 (was 15); M_i < 2^18, carries 15 bits, e_T + 2^28 < 2^29; 50-bit q in 7 bytes.
K16 = P(2560, 7, sl_e=16, m_bits=18, c_bits=15, et_bits=29)


def groups(m):
    return (m + 3) // 4


def rows(p, rel, ell):
    """cs::Layout::new(rel, ell).m; rel = ('reg' | 'tx' | 'tx0' | 'burn' | 'ds' | 'dr') or ('txm', M, aud[, G])"""
    se = [(p.s_bits,), (p.e_bits,)]
    sl = [(1, p.sl_s), (1, p.sl_e)]

    def debit(legs, nd, pairs):
        v = [(16 * legs, 8)]
        if nd:
            v.append((16 * nd, 4))
        v += [(16, 4), (16, p.m_bits), (16, p.c_bits), (16, p.et_bits)]
        v += sl * pairs
        v += [(1, 13)] * legs
        return v

    name = rel[0]
    if name == "reg":
        bigs, smalls = se, sl
    elif name == "tx":
        bigs, smalls = se * 2, debit(3, 1, 2)
    elif name == "tx0":
        bigs, smalls = se * 2, debit(2, 1, 2)
    elif name == "burn":
        bigs, smalls = se * 2, debit(1, 0, 2)
    elif name == "ds":
        bigs, smalls = se, [(16, 8)] + sl + [(1, 13)]
    elif name == "dr":
        bigs, smalls = se, [(16, p.et_bits)] + sl
    else:
        _, m, aud = rel[:3]
        g = rel[3] if len(rel) > 3 else groups(m)
        pairs = 1 + g
        bigs, smalls = se * pairs, debit(m + 1 + aud * m, m, pairs)
    nr = -(-p.N // ell)
    cur = sum(nr * (2 + b[0]) for b in bigs)
    nsv = -(-sum(c for c, _ in smalls) // ell)
    nsb = -(-sum(c * b for c, b in smalls) // ell)
    return cur + 2 * nsv + nsb


def depth(n):
    return (n - 1).bit_length()


def max_len(p, rel, n, k, t):
    """Params::max_len_exact: root, w, q, h, nonce, t distinct columns, the largest pruned multiproof"""
    ell = k - t - 1
    m = rows(p, rel, ell)
    d = depth(n)
    mid = sum(min(t, -(-n // (1 << l))) for l in range(1, d))
    poly = (2 * (2 * k - 1) + (2 * k - 1 - ell)) * 4 * p.eb
    return 32 + poly + 8 + t * (32 + (m + BLIND) * p.eb) + (mid + 2 - t) * DIG


def stmt_len(p, rel):
    """pqz-stmt lengths (pq-zero-knowledge.md §8.1): header 640, pk / u = 8 N bytes, v = 128"""
    pk, v, H = 8 * p.N, 128, 640
    name = rel[0]
    if name == "reg":
        return 96 + pk
    if name in ("ds", "dr"):
        return 288 + 2 * pk + v
    if name == "tx":
        return H + 3 * pk + (pk + v) + pk + 3 * v
    if name == "tx0":
        return H + 2 * pk + (pk + v) + pk + 2 * v
    if name == "burn":
        return H + pk + (pk + v) + pk + v
    _, m, aud = rel[:3]
    g = rel[3] if len(rel) > 3 else groups(m)
    return H + (1 + m + aud) * pk + (pk + v) + g * pk + v * (m + 1) + aud * v * m


def prover(p, rel, n, k, t):
    """ligero_params.model1's prover work (base-field products: FFTs of the rows and the products), radices of q - 1"""
    ell = k - t - 1
    m = rows(p, rel, ell)
    n2 = min(s for s in SMOOTH if s >= 2 * k - 1)
    return (m + BLIND) * (lp.fft_cost(k) + lp.fft_cost(n)) + (m + 40) * lp.fft_cost(n2)


SMOOTH = lp.SMOOTH4
RELS = [("reg",), ("tx",), ("tx0",), ("burn",), ("ds",), ("dr",),
        ("txm", 1, 1), ("txm", 1, 0), ("txm", 2, 1), ("txm", 2, 0), ("txm", 4, 1), ("txm", 4, 0),
        ("txm", 8, 1), ("txm", 8, 0), ("txm", 8, 1, 1), ("txm", 8, 0, 1)]


def label(rel):
    if rel[0] != "txm":
        return {"reg": "R_REG", "tx": "R_TX", "tx0": "R_TX0", "burn": "R_BURN", "ds": "R_DS", "dr": "R_DR / R_DA"}[rel[0]]
    g = rel[3] if len(rel) > 3 else groups(rel[1])
    return f"R_TXM M={rel[1]} {'aud' if rel[2] else 'noaud'} G={g}"


def selfcheck():
    """today's crate pins (ligero.rs limits_exact) at THE preset n = 32,756, k = 817, t = 121"""
    n, k, t = 32756, 817, 121
    want = {("reg",): 190_458, ("tx",): 235_470, ("burn",): 234_744, ("ds",): 190_458, ("dr",): 190_458,
            ("tx0",): 234_744, ("txm", 1, 1): 235_470, ("txm", 1, 0): 234_744, ("txm", 2, 1): 235_470,
            ("txm", 2, 0): 235_470, ("txm", 4, 1): 236_196, ("txm", 4, 0): 235_470, ("txm", 8, 1): 281_208,
            ("txm", 8, 0): 279_756, ("txm", 16, 1): 372_684, ("txm", 16, 0): 369_054}
    inp = {("txm", 4, 1): 369_193, ("txm", 8, 1): 497_149, ("tx",): 318_547, ("tx0",): 301_309}
    assert lp.t_of(lp.factor_proven(n, k)) == t
    for rel, w in want.items():
        assert max_len(TODAY, rel, n, k, t) == w, (rel, max_len(TODAY, rel, n, k, t), w)
    for rel, w in inp.items():
        assert 5 + stmt_len(TODAY, rel) + want[rel] == w, (rel, 5 + stmt_len(TODAY, rel) + want[rel], w)
    return len(want) + len(inp)


def main():
    q = 2**50 - 42_310_535
    f = factor(q - 1)
    print("# PQZH Ligero at the 16k parameters (plan 5h Task 7; every 16k number an [estimate] of the crate's layout model)\n")
    print(f"self-check: {selfcheck()} pinned bounds of today's crate (ligero.rs limits_exact, statement lengths) reproduced")
    assert is_prime(q) and q % 16 == 9
    assert f == [2, 2, 2, 19, 43, 431, 5659, 70627], f
    assert pow(3, (q - 1) // 2, q) == q - 1, "X^4 - 3 irreducible needs 3 a non-square"
    gen3 = all(pow(3, (q - 1) // r, q) != 1 for r in set(f))
    print(f"q = 2^50 - 42,310,535 = {q}: prime, q mod 16 = {q % 16}; q - 1 = {' * '.join(map(str, f))}")
    print(f"3 is a non-square (X^4 - 3 irreducible, F_q^4 as today); 3 generates F_q^*: {gen3}")
    print(f"F_q element: 50 bits in {K16.eb} bytes (today 42 bits in 6); |F_q^4| = 2^{4 * math.log2(q):.1f}")
    print(f"domains: the crate's radices 2 / 19 / 43 / 431 divide q - 1 (2-adicity 3, as today): every smooth size "
          f"of today's fft.rs is a subgroup of F_q^*; the preset n = 32,756 = 4 * 19 * 431 exists. New radices 5,659 "
          f"and 70,627 not used (an FFT step of radix r costs ~ r products per point).")
    print(f"lane check: 2^64 / q = 2^{64 - math.log2(q):.2f} terms per 64-bit lane (Solidity accumulators)\n")

    n, k, t = 32756, 817, 121
    print(f"## THE preset kept: proven, n = {n}, k = {k}, t = {t}, l = {k - t - 1} "
          f"(factor {lp.factor_proven(n, k):.4f}, soundness depends on n, k only)\n")
    print("| relation | rows m today | rows m 16k | proof bound today B | proof bound 16k B | <= MAX_PROOF_PQZH 262,144 "
          "| statement 16k B | input 5 + stmt + proof B | <= 512 KiB | prover products 16k |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    for rel in RELS:
        ell = k - t - 1
        a, b = max_len(TODAY, rel, n, k, t), max_len(K16, rel, n, k, t)
        s = stmt_len(K16, rel)
        inp = 5 + s + b
        print(f"| {label(rel)} | {rows(TODAY, rel, ell)} | {rows(K16, rel, ell)} | {a:,} | {b:,} | "
              f"{'yes' if b <= MAX_PROOF_PQZH else 'NO'} | {s:,} | {inp:,} | {'yes' if inp <= MAX_INPUT_16K else 'NO'} | "
              f"{prover(K16, rel, n, k, t):.3g} |")

    print("\n## Preset search at 16k (proven, radices 2/19/43/431, n >= 4k, k >= 64, prover <= "
          f"{lp.PMAX:.0e} products): the three smallest R_TX / R_TXM M=4 aud bounds\n")
    print("| relation | n | k | t | l | rows m | proof bound B | prover products |")
    print("|---|---|---|---|---|---|---|---|")
    for rel in (("tx",), ("txm", 4, 1), ("txm", 8, 1)):
        res = []
        for nn in SMOOTH:
            if nn > lp.NMAX:
                continue
            for kk in SMOOTH:
                if 4 * kk > nn or kk < 64:
                    continue
                tt = lp.t_of(lp.factor_proven(nn, kk))
                if kk - tt - 1 < 16:
                    continue
                pr = prover(K16, rel, nn, kk, tt)
                if pr <= lp.PMAX:
                    res.append((max_len(K16, rel, nn, kk, tt), nn, kk, tt, pr))
        for size, nn, kk, tt, pr in sorted(res)[:3]:
            print(f"| {label(rel)} | {nn} | {kk} | {tt} | {kk - tt - 1} | {rows(K16, rel, kk - tt - 1)} | {size:,} | {pr:.3g} |")


if __name__ == "__main__":
    main()
