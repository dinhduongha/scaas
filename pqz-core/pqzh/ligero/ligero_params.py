#!/usr/bin/env python3
"""Ligero over F_q for PQZH (docs/research/pqzh-ligero.md §2-§5): field checks, soundness per regime, and the
parameter choice (n, k, l, t) with a proof-size and verifier-work model. Stdlib only; every number printed is an
[estimate] from the layout model below, nothing is measured here.

  python3 pqz-core/pqzh/ligero/ligero_params.py          > runs/p1-params.txt   (layout of the crate, radices 2/19/43
                                                                                  and 2/19/43/431 side by side)
  python3 pqz-core/pqzh/ligero/ligero_params.py --p0     > runs/p0-params.txt   (the first model, kept for reference)

p1 (2026-10-14, crate layout): blinding rows in F_q^4 (3 polynomials = 12 base rows, needed for ZK since w, q, h have
F_q^4 coefficients), small values packed as the crate does (cs.rs), k need not divide n (the encoding is an inverse
FFT on H_k and a coset FFT on 3 H_n; 3 H_n and H_k are always disjoint because 3 generates F_q^*), n >= 4k (degree
correction, §5.1), exact proven factor of RS[n, 2k-1] at its unique-decoding radius.
"""
import math
import sys

Q = 2**42 - 215
EXT = 4                      # F_{q^4} = F_q[X]/(X^4 - 3)
W = 3
LAMBDA, POW = 128, 16        # target bits, grinding bits before the column query (as the STARK config)
EB, DIG, SALT = 6, 32, 32    # bytes per F_q element (42 bits in 6), Keccak-256 digest, per-column salt
SMOOTH3 = sorted({2**a * 19**b * 43**c for a in range(4) for b in range(2) for c in range(2)})
SMOOTH4 = sorted({s * 431**d for s in SMOOTH3 for d in range(2)})
NMAX = 2**21                 # prover memory: (m + 12) rows x n x 8 B stays under ~0.3 GB
PMAX = 4e9                   # prover budget, base-field products (FFT + products), ~ seconds native


def factor(n):
    f, p = [], 2
    while p * p <= n:
        while n % p == 0:
            f.append(p)
            n //= p
        p += 1
    return f + ([n] if n > 1 else [])


def checks():
    f = factor(Q - 1)
    assert f == [2, 2, 2, 19, 43, 431, 1561243], f
    assert pow(W, (Q - 1) // 2, Q) == Q - 1, 'X^4 - 3 irreducible needs 3 a non-square (q = 1 mod 4)'
    assert all(pow(3, (Q - 1) // p, Q) != 1 for p in set(f)), '3 generates F_q^*'
    return f


# ---- p1: the crate's layout (cs.rs) ----
# big groups: 2048 values, bits per value; rows per group = ceil(2048 / l) * (value + square + bits)
BIG = {'R_REG': [7, 9], 'R_TX': [7, 9, 7, 9]}
# small values (one value row, an aligned square row, packed bit rows): count and total bits
SMALL = {'R_REG': (2, 11 + 15),
         'R_TX': (135, 48 * 8 + 32 * 4 + 16 * 14 + 16 * 11 + 16 * 25 + 11 + 15 + 11 + 15 + 3 * 13)}
BLIND_ROWS = 12              # u_0, u_lin, u_quad in F_q^4, 4 base rows each


def rows1(rel, ell):
    r = sum(math.ceil(2048 / ell) * (2 + b) for b in BIG[rel])
    nv, nb = SMALL[rel]
    return r + 2 * math.ceil(nv / ell) + math.ceil(nb / ell)


def own_rows(rel, ell):
    """rows whose linear-test vector the verifier interpolates itself (big value rows, small rows) + 2 shared"""
    nv, nb = SMALL[rel]
    return len(BIG[rel]) * math.ceil(2048 / ell) + 2 * math.ceil(nv / ell) + math.ceil(nb / ell) + 2


def factor_proven(n, k):
    """per-query acceptance of a cheating prover, proven: one proximity test over RS[n, 2k-1] at its unique-decoding
    radius e, consistency terms (e + 2k - 2)/n (Ligero Thm 4.7 / App. C form)"""
    e = (n - 2 * k + 1) // 2
    return max(1 - e / n, (e + 2 * k - 2) / n)


def factor_conj(n, k):
    return (2 * k - 1) / n                   # rate of RS[n, 2k-1], the ethSTARK-style analogue


def t_of(f):
    return math.ceil((LAMBDA - POW) / -math.log2(f))


def n2_of(k, smooth):
    return min(s for s in smooth if s >= 2 * k - 1) if 2 * k - 1 <= smooth[-1] else None


def fft_cost(n):
    return n * sum(r + 1 for r in factor(n))


def model1(rel, n, k, t, smooth):
    ell = k - t - 1                          # ZK: t distinct openings < k - l (Ligero Lemma 4.15)
    if ell < 16:
        return None
    m = rows1(rel, ell)
    dist = n * (1 - (1 - 1 / n) ** t)
    npad = 1 << (n - 1).bit_length()
    polys = (2 * (2 * k - 1) + (2 * k - 1 - ell)) * EXT * EB
    cols = dist * ((m + BLIND_ROWS) * EB + SALT)
    merkle = dist * max(0.0, math.log2(npad) - math.log2(dist)) * DIG
    size = 32 + 8 + polys + cols + merkle
    ver = own_rows(rel, ell) * ell * dist * EXT + 3 * (2 * k) * dist * EXT
    n2 = n2_of(k, smooth)
    if n2 is None:
        return None
    prover = (m + BLIND_ROWS) * (fft_cost(k) + fft_cost(n)) + (m + 40) * fft_cost(n2)
    return dict(ell=ell, m=m, dist=round(dist), size=round(size), polys=polys, cols=round(cols),
                merkle=round(merkle), ver=round(ver), prover=round(prover), n2=n2)


def search1(rel, reg, smooth):
    out = []
    for n in smooth:
        if n > NMAX:
            continue
        for k in smooth:
            if 4 * k > n or k < 64:
                continue
            f = factor_proven(n, k) if reg == 'proven' else factor_conj(n, k)
            t = t_of(f)
            r = model1(rel, n, k, t, smooth)
            if r and r['prover'] <= PMAX:
                out.append((r['size'], n, k, t, f, r))
    out.sort(key=lambda x: x[0])
    return out


def main1():
    f = checks()
    print('## Field\n')
    print(f'- q = 2^42 - 215 = {Q}; q - 1 = {" * ".join(map(str, f))} (2-adicity 3)')
    print(f'- F_q^4 = F_q[X]/(X^4 - {W}) ({W} is a non-square, q = 1 mod 4); |F_q^4| = 2^{4 * math.log2(Q):.2f}')
    print(f'- radices 2/19/43 sizes: {SMOOTH3}')
    print(f'- with radix 431 (<= {NMAX:,}): {[s for s in SMOOTH4 if s <= NMAX]}')
    print(f'- prover budget: modelled FFT + product work <= {PMAX:.0e} base products (rejects n/k in the thousands)\n')
    print('Layout (cs.rs): rows m = sum over big groups ceil(2048/l) (2 + bits) + 2 ceil(n_small/l) + ceil(bits_small/l);'
          ' 12 blinding base rows; proof = root + w, q (2k-1 coeffs) + h (2k-1-l) in F_q^4 + nonce + distinct columns'
          ' (salt + (m + 12) x 6 B) + pruned Keccak multiproof. t from 112 query bits + 16 grinding bits.\n')
    print('| relation | regime | radices | n | k | n/k | factor | t | l | m | N2 | dist cols | test polys B | columns B '
          '| Merkle B | proof B | verifier mults | prover mults |')
    print('|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|')
    for rel in ['R_REG', 'R_TX']:
        for reg in ['proven', 'conj']:
            for name, sm in [('2/19/43', SMOOTH3), ('2/19/43/431', SMOOTH4)]:
                for size, n, k, t, fac, r in search1(rel, reg, sm)[:3]:
                    print(f"| {rel} | {reg} | {name} | {n} | {k} | {n / k:.1f} | {fac:.4f} | {t} | {r['ell']} | "
                          f"{r['m']} | {r['n2']} | {r['dist']} | {r['polys']:,} | {r['cols']:,} | {r['merkle']:,} | "
                          f"{size:,} | {r['ver']:,} | {r['prover']:,} |")


# ---- p0: the first model (kept so that runs/p0-params.txt can be regenerated) ----
SMOOTH = SMOOTH3
BIG0 = {'R_REG': [(2048, 7, True), (2048, 9, True)],
        'R_TX': [(2048, 7, True), (2048, 9, True), (2048, 7, True), (2048, 9, True)]}
SMALL0 = {'R_REG': 2 + 11 + 15,
          'R_TX': (48 * (2 + 8)) + 32 * 5 + 16 * 15 + 16 * 12 + 16 * 26 + 7 + 2 * 11 + 2 * 15 + 3 * 13}
BLINDS = 3


def per_column(rho, regime):
    if regime == 'proven':
        r2 = 2 * rho
        f = max((1 + r2) / 2, r2)
    elif regime == 'theorem':
        r2 = 2 * rho
        f = min(max(1 - d, d + r2) for d in [i / 1000 * (1 - r2) / 2 for i in range(1, 1000)])
    else:
        f = 2 * rho
    return -math.log2(f)


def t_for(rho, regime):
    return math.ceil((LAMBDA - POW) / per_column(rho, regime))


def rows(rel, ell):
    m = sum(math.ceil(v / ell) * (1 + b + (1 if nm else 0)) for v, b, nm in BIG0[rel])
    return m + math.ceil(SMALL0[rel] / ell)


def model(rel, n, k, t):
    ell = k - t - 1
    if ell < 64:
        return None
    m = rows(rel, ell)
    tu = n * (1 - (1 - 1 / n) ** t)
    lin, quad, prox = 2 * k - 1, 2 * k - 1, 2 * k - 1 - ell
    polys = (prox + lin + quad) * EXT * EB
    cols = tu * ((m + BLINDS) * EB + SALT)
    merkle = tu * max(0, math.log2(n) - math.log2(tu)) * DIG
    size = 32 + 8 + polys + cols + merkle
    distinct = sum(math.ceil(v / ell) * 2 for v, _, _ in BIG0[rel]) + math.ceil(SMALL0[rel] / ell) + 2
    ver = distinct * ell * tu * EXT + 3 * (m + BLINDS) * tu * EXT
    return dict(ell=ell, m=m, tu=round(tu), size=round(size), polys=polys, cols=round(cols), merkle=round(merkle),
                ver_mults=round(ver))


def main0():
    f = checks()
    print('## Field\n')
    print(f'- q = 2^42 - 215 = {Q}; q - 1 = {" * ".join(map(str, f))} (2-adicity 3)')
    print(f'- F_q^4 = F_q[X]/(X^4 - {W}) ({W} is a non-square, q = 1 mod 4); |F_q^4| = 2^{4 * math.log2(Q):.2f}')
    print(f'- multiplicative generator 3; q mod 128 = {Q % 128} (X^64 + 1 splits only over F_q^16)')
    print(f'- FFT-friendly domain sizes (2^a 19^b 43^c): {SMOOTH}\n')
    print('## Opened columns t per rate (128 bits = 112 query bits + 16 grinding bits)\n')
    print('| rate k/n | proven (one test over RS[n,2k-1], App. C terms) | Thm 4.7 form | conjectured (capacity) |')
    print('|---|---|---|---|')
    for rho in [1 / 4, 1 / 8, 1 / 16, 1 / 19, 1 / 32, 1 / 38, 1 / 43]:
        print(f'| 1/{round(1 / rho)} | {t_for(rho, "proven")} | {t_for(rho, "theorem")} | {t_for(rho, "conj")} |')
    print('\n## Best (n, k) per relation and regime (smooth n and k, k | n)\n')
    print('| relation | regime | n | k | rate | t | l | rows m | distinct cols | test polys B | columns B | Merkle B '
          '| proof B | verifier mults |')
    print('|---|---|---|---|---|---|---|---|---|---|---|---|---|---|')
    for rel in ['R_REG', 'R_TX']:
        for reg in ['proven', 'conj']:
            best = []
            for n in SMOOTH:
                for k in SMOOTH:
                    if n % k or n // k < 4:
                        continue
                    t = t_for(k / n, reg)
                    r = model(rel, n, k, t)
                    if r:
                        best.append((r['size'], n, k, t, r))
            best.sort()
            for size, n, k, t, r in best[:3]:
                print(f"| {rel} | {reg} | {n} | {k} | 1/{n // k} | {t} | {r['ell']} | {r['m']} | {r['tu']} | "
                      f"{r['polys']:,} | {r['cols']:,} | {r['merkle']:,} | {size:,} | {r['ver_mults']:,} |")


if __name__ == '__main__':
    main0() if '--p0' in sys.argv else main1()
