#!/usr/bin/env python3
"""Ligero over F_q for PQZH (docs/research/pqzh-ligero.md §2-§5): field checks, soundness per regime, and the
parameter choice (rate, k, l, t) with a proof-size and verifier-work model. Stdlib only; every number printed is an
[estimate] from the layout model below, nothing is measured here.

  python3 pqz-core/pqzh/ligero/ligero_params.py   > pqz-core/pqzh/ligero/runs/p0-params.txt
"""
import math

Q = 2**42 - 215
EXT = 4                      # F_{q^4} = F_q[X]/(X^4 - 3)
W = 3
LAMBDA, POW = 128, 16        # target bits, grinding bits before the column query (as the STARK config)
EB, DIG, SALT = 6, 32, 32    # bytes per F_q element (42 bits in 6), Keccak-256 digest, per-column salt
# FFT-friendly sizes: divisors of q - 1 built from 2^3 * 19 * 43 (431 and 1,561,243 are too large as radices)
SMOOTH = sorted({2**a * 19**b * 43**c for a in range(4) for b in range(2) for c in range(2)})


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


# Groups of R_REG / R_TX witness values: (values, bits per value, normed). Bits: x + 2^b' in [0, 2^(b'+1)) with
# 2^b' > the l2 bound (36 -> 7 bits, 164 -> 9, 64 -> 8); "normed" groups also get a squares row.
BIG = {'R_REG': [(2048, 7, True), (2048, 9, True)],
       'R_TX': [(2048, 7, True), (2048, 9, True), (2048, 7, True), (2048, 9, True)]}
# small values packed horizontally (values + their bits): e2 (48 x 8 bits, squared), d, d' (32 x 4), M (16 x 14),
# c + 64 (16 x 11), e_T + 2^24 (16 x 25), l2 slacks (s 11, e 15, e2 13 bits)
SMALL = {'R_REG': 2 + 11 + 15,
         'R_TX': (48 * (2 + 8)) + 32 * 5 + 16 * 15 + 16 * 12 + 16 * 26 + 7 + 2 * 11 + 2 * 15 + 3 * 13}
BLINDS = 3                   # u_0 (proximity), u_lin (sum 0 on H_k), u_quad (0 on the message points)


def per_column(rho, regime):
    """log2 of 1/(per-column acceptance probability of a cheating prover)."""
    if regime == 'proven':       # one proximity test over RS[n, 2k-1] (rate 2 rho, unique decoding, BCIKS20 Thm 1.2 =
        r2 = 2 * rho             # Ligero Lemma 4.6), consistency terms as Ligero App. C: max((1 + 2rho)/2, 2rho)
        f = max((1 + r2) / 2, r2)
    elif regime == 'theorem':    # Ligero Thm 4.7 form: (1 - e/n)^t + 2((e + 2k)/n)^t, e < d/2 of RS[n, 2k-1]
        r2 = 2 * rho
        f = min(max(1 - d, d + r2) for d in [i / 1000 * (1 - r2) / 2 for i in range(1, 1000)])
    else:                        # conjectured: proximity up to capacity of RS[n, 2k-1], consistency 2k/n
        f = 2 * rho
    return -math.log2(f)


def t_for(rho, regime):
    return math.ceil((LAMBDA - POW) / per_column(rho, regime))


def rows(rel, ell):
    m = sum(math.ceil(v / ell) * (1 + b + (1 if nm else 0)) for v, b, nm in BIG[rel])
    return m + math.ceil(SMALL[rel] / ell)


def model(rel, n, k, t):
    ell = k - t - 1                       # k > l + t (Ligero Lemma 4.15)
    if ell < 64:
        return None
    m = rows(rel, ell)
    tu = n * (1 - (1 - 1 / n) ** t)        # distinct opened columns
    lin, quad, prox = 2 * k - 1, 2 * k - 1, 2 * k - 1 - ell  # quad sent as h = p_0 / Z_msg
    polys = (prox + lin + quad) * EXT * EB
    cols = tu * ((m + BLINDS) * EB + SALT)
    merkle = tu * max(0, math.log2(n) - math.log2(tu)) * DIG
    size = 32 + 8 + polys + cols + merkle
    distinct = sum(math.ceil(v / ell) * 2 for v, _, _ in BIG[rel]) + math.ceil(SMALL[rel] / ell) + 2
    ver = distinct * ell * tu * EXT + 3 * (m + BLINDS) * tu * EXT   # base x base products (u128, lazy reduction)
    return dict(ell=ell, m=m, tu=round(tu), size=round(size), polys=polys, cols=round(cols), merkle=round(merkle),
                ver_mults=round(ver))


def main():
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
    main()
