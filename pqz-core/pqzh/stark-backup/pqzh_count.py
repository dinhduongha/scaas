#!/usr/bin/env python3
"""PQZH design study (docs/research/pqzh-design.md): constraint, lookup, trace-cell and proof-size estimates for
the five PQZ relations as hash-based proofs. Stdlib only; nothing is proved or measured; every number printed is
an [estimate] from the relation shapes of pqz-core/src/pqz_rel.c (build_reg, build_debit, build_ds, build_dr) and
pq-zether.md (CTR-PQZ-03, §7.4, §7.5, §7.9).

  python3 pqz-core/pqzh/pqzh_count.py              # all tables, markdown (output committed as counts.txt)
  python3 pqz-core/pqzh/pqzh_count.py --selftest   # the bound checks the arithmetisation relies on

Designs counted (note §2):
  D1  challenge-free: R_q products in the NTT domain of the proof field (X^64 + 1 splits), public A as
      preprocessed columns, quotient witnesses for mod-q identities, LogUp range checks; any AIR + LogUp framework.
  D2  Schwartz-Zippel: every R_q identity checked at one random point rho after the witness is committed;
      the verifier computes the public-side coefficients (A(rho), pk(rho)); needs challenge-derived constants.
  LG  Ligero over F_q itself: mod-q identities are linear constraints, range checks by bits.
"""
import math, sys

Q = 2**42 - 215
K, D = 32, 64
N = K * D                      # coefficients of one module vector (2048)
DELTA = 2**26 - 1
LAMBDA, POW = 128, 16          # target bits, proof-of-work grinding bits (STARK)

FIELDS = {  # p, base bytes, extension degree, limbs for 42-bit values, NTT-domain cost (mults, cells) per op
    'Goldilocks': dict(p=2**64 - 2**32 + 1, B=8, ext=2, limbs=1, nm=1, nc=1),
    'KoalaBear': dict(p=2**31 - 2**24 + 1, B=4, ext=4, limbs=3, nm=1, nc=1),
    'M31 (Circle)': dict(p=2**31 - 1, B=4, ext=4, limbs=3, nm=3, nc=2),   # X^64+1 splits only over CM31
}
LIMB = 14                      # limb width for 31-bit fields: 3 x 14 bits >= 42

# short witness vectors: (name, coefficients, l2 bound); digit-like values: (count, bits)
S36, E164 = 36, 164
REL = {
    'R_REG': dict(short=[('s', N, S36), ('e', N, E164)], mats=1, wit_ops=1, ips=0, evq=0,
                  digits=[], row7=0, stmt=N),
    'R_TX': dict(short=[('s_f', N, S36), ('e_f', N, E164), ('r', N, S36), ('e1', N, E164),
                        ('e2_t', 16, 64), ('e2_f', 16, 64), ('e2_a', 16, 64)],
                 mats=2, wit_ops=2, ips=4, evq=64, digits=[(16, 4), (16, 4), (16, 14), (15, 11), (16, 25)],
                 row7=16, stmt=5 * N + 4 * 16),
    'R_BURN': dict(short=[('s_f', N, S36), ('e_f', N, E164), ('r', N, S36), ('e1', N, E164), ('e2_f', 16, 64)],
                   mats=2, wit_ops=2, ips=2, evq=32, digits=[(16, 4), (16, 14), (15, 11), (16, 25)],
                   row7=16, stmt=3 * N + 2 * 16),
    'R_DS': dict(short=[('r', N, S36), ('e1', N, E164), ('e2_t', 16, 64)], mats=1, wit_ops=1, ips=1, evq=16,
                 digits=[], row7=0, stmt=2 * N + 16),
    'R_DR': dict(short=[('s', N, S36), ('e', N, E164)], mats=1, wit_ops=1, ips=1, evq=16,
                 digits=[(16, 25)], row7=0, stmt=2 * N + 16),
}


def l1(n, b2):                 # l1 bound implied by an exact l2 bound over Z
    return math.isqrt(n * b2 * b2)


def bounds():
    """Largest |integer| a mod-q identity can reach once every witness value is range-checked (note §2.2)."""
    h = Q // 2
    mat = h * l1(N, S36) + E164 + h                            # (A s)_k + e_k - pk_k, centred A and pk
    ev = h * l1(N, S36) + 64 + DELTA * (2**14 - 1) + 2**24 + h  # rows 3-6, worst of the four
    tq = -(-max(mat, ev) // Q)                                  # quotient magnitude
    limb = 2**LIMB * l1(N, S36) + 2**LIMB * tq + E164           # one 14-bit limb sum in a 31-bit field
    l2 = N * E164**2                                            # sum of squares with |e_i| <= 164
    return dict(mat=mat, ev=ev, tq=tq, limb=limb, l2=l2)


def lk(bits):                  # range lookups per value: one into a 2^16 table up to 16 bits, else two
    return 1 if bits <= 16 else 2


def count_d1(r, f):
    L = f['limbs']
    short = sum(n for _, n, _ in r['short'])
    ids = r['mats'] * N + r['evq']                       # mod-q integer identities (coefficients)
    quot, carries = ids, (L - 1) * ids
    ntts = r['wit_ops'] * K + r['mats'] * K * L + r['ips'] * K * L + r['ips'] * L
    macs = (r['mats'] * K * K + r['ips'] * K) * D * L     # pointwise products in the NTT domain
    dig = sum(c * lk(b) for c, b in r['digits'])
    look = short + quot + carries + dig + len(r['short'])  # + one slack check per l2 norm
    bus = r['mats'] * K * K * D * L + 2 * r['ips'] * K * D * L + r['mats'] * N * L + r['stmt'] * L
    main = (short + quot + carries + sum(c for c, _ in r['digits']) + short          # values, squares
            + 6 * D * ntts * f['nc'] + 2 * macs * f['nc'] + r['stmt'] * L)
    pre = r['mats'] * K * K * D * L * f['nc'] + 2**16                                 # A-hat limbs, range table
    return dict(look=look, macs=macs * f['nm'], ntts=ntts, bfly=ntts * 192 * f['nm'], main=main, pre=pre,
                aux=look + bus)


def count_d2(r, f):
    L = f['limbs']
    short = sum(n for _, n, _ in r['short'])
    ids = r['mats'] * N + r['evq']
    # in-circuit evaluations at rho (one extension MAC per coefficient): operands, then per identity group
    # the product / linear-side polynomials (L limbs) and the X^64+1 quotient polynomials (63 coefficients)
    horner = r['wit_ops'] * N + r['mats'] * (L * N + N + L * K * 63) + r['ips'] * L * (D + 63)
    carries = (L - 1) * ids
    look = short + ids + carries + sum(c * lk(b) for c, b in r['digits']) + len(r['short'])
    main = 2 * short + ids + carries + sum(c for c, _ in r['digits']) + r['mats'] * L * (N + K * 63) \
        + r['ips'] * L * (D + 63) + r['stmt'] * L * 0          # statement never enters the trace in D2
    ver = (K * K * D if r['mats'] else 0) + r['mats'] * K * K + r['stmt'] * L   # verifier base x ext MACs
    return dict(look=look, horner=horner, main=main, aux=look + horner, ver=ver)


def stark_shape(c, f, rows_per_cell=8):
    """One virtual trace: tall and narrow (proof size grows with opened width, not with height)."""
    h = max(2**16, 1 << math.ceil(math.log2(max(1, c['main'] / rows_per_cell))))
    w = dict(main=math.ceil(c['main'] / h), pre=math.ceil(c.get('pre', 2**16) / h),
             aux=math.ceil(c['aux'] / h) * f['ext'], quot=2 * f['ext'])
    return h, w


def queries(b, regime):        # b = log2 blowup; conjectured: b bits/query; Johnson (provable): b/2 bits/query
    return math.ceil((LAMBDA - POW) / (b if regime == 'conj' else b / 2))


def fri_bytes(h, w, f, b, a, regime, final_log=5, digest=32):
    q = queries(b, regime)
    lde = int(math.log2(h)) + b
    dedup = int(math.log2(q))                  # Merkle multi-proofs share roughly the top log2(Q) levels
    eb = f['B'] * f['ext']
    per_q = sum(wi * f['B'] + digest * max(0, lde - dedup) for wi in w.values() if wi)
    rounds = math.ceil((int(math.log2(h)) - final_log) / a)
    for i in range(rounds):
        per_q += (2**a - 1) * eb + digest * max(0, lde - a * (i + 1) - dedup)
    fixed = 4 * digest + 2 * sum(w.values()) * eb // f['B'] * f['B'] + 2**final_log * eb + rounds * digest
    return q, q * per_q + fixed


def stark_verify_perms(h, w, f, b, a, regime, final_log=5):
    q = queries(b, regime)
    lde = int(math.log2(h)) + b
    perms = sum(math.ceil(wi * f['B'] / 136) + lde for wi in w.values() if wi)
    rounds = math.ceil((int(math.log2(h)) - final_log) / a)
    perms += sum(1 + lde - a * (i + 1) for i in range(rounds))
    return q * perms


def ligero(r, rho, regime, ext=3, eb=6, digest=32):
    """Ligero over F_q (pq-zether.md q, 42-bit elements packed in 6 bytes); challenges in F_{q^ext}."""
    short = sum(n for _, n, _ in r['short'])
    bits = sum(n * (math.ceil(math.log2(b + 1)) + 1) for _, n, b in r['short'])     # x + 2^k in [0, 2^(k+1))
    bits += sum(c * b for c, b in r['digits']) + sum((b * b).bit_length() for _, _, b in r['short'])
    n = short + short + bits                                   # values, squares, bits
    lin = r['mats'] * N + r['evq'] + r['row7'] + short + len(r['short']) + sum(c for c, _ in r['digits'])
    quad = bits + short
    if regime == 'classic':    # unique decoding, e < d/3 (Ligero CCS'17)
        per = -math.log2(1 - (1 - rho) / 3)
    else:                      # proximity gaps up to the Johnson bound
        per = -math.log2(math.sqrt(rho))
    t = math.ceil(LAMBDA / per)
    best = None
    for m in range(8, 2048):
        l = math.ceil(n / m)
        nn = 1 << math.ceil(math.log2((l + t) / rho))
        size = (t * (m + 3) * eb                                # opened columns (+ 3 masking rows)
                + (4 * l + 3 * t) * ext * eb                    # degree, linear and quadratic test vectors
                + t * digest * max(0, int(math.log2(nn)) - int(math.log2(t))))
        if best is None or size < best[0]:
            best = (size, m, l, nn)
    size, m, l, nn = best
    # verifier: the linear test needs r_i(x_j) for every row i and opened column j, the interpolation of the
    # verifier's own combination vector r^T M restricted to row i: min(FFT per row, direct = n * t) F_{q^ext}
    # multiplications; degree and quadratic tests are t * m each; the structured r^T M itself (A blocks through
    # an NTT mod q) is ≈ 1 ms
    ver = min(m * nn * int(math.log2(nn)), m * t * l) + 2 * t * m
    return dict(n=n, lin=lin, quad=quad, t=t, size=size, m=m, l=l, N=nn, ver=ver)


def gas_floor(proof):
    """EIP-7623 floor of a transfer: non-proof calldata as pq-zether.md §9.3 (≈ 119 k tokens), proof ≈ 3.99
    tokens/byte, 10 gas per token."""
    return 10 * (119_000 + 3.99 * proof)


def selftest():
    bd = bounds()
    g, kb = FIELDS['Goldilocks']['p'], FIELDS['KoalaBear']['p']
    assert max(bd['mat'], bd['ev']) < g // 2, 'Goldilocks: one quotient per identity must not wrap'
    assert bd['limb'] < kb // 2 and bd['l2'] < kb // 2, '31-bit fields: 14-bit limb sums must not wrap'
    assert bd['tq'] < 2**11, 'quotient fits an 11-bit signed range'
    assert (g - 1) % 128 == 0 and (kb - 1) % 128 == 0, 'X^64 + 1 splits'
    assert (2**31 - 2) % 128 != 0 and ((2**31 - 1)**2 - 1) % 128 == 0, 'M31: splits over CM31 only'
    assert (Q - 1) % 16 == 8, 'q - 1 has 2-adicity 3 (Ligero over F_q needs a mixed-radix or direct encoding)'
    return bd


def main():
    bd = selftest()
    if '--selftest' in sys.argv:
        print('selftest ok', {k: f'2^{math.log2(v):.2f}' for k, v in bd.items()})
        return
    print('## Bounds (selftest passed)\n')
    for k, v in bd.items():
        print(f'- {k}: {v:,} (2^{math.log2(v):.2f})')
    print('\n## Relation shapes (field-independent)\n')
    print('| Relation | short coeffs | l2 norms | A-products (R_q) | statement products (R_q) | mod-q identities | '
          'digit values | statement coeffs |')
    print('|---|---|---|---|---|---|---|---|')
    for name, r in REL.items():
        print(f"| {name} | {sum(n for _, n, _ in r['short']):,} | {len(r['short'])} | {r['mats'] * K * K:,} | "
              f"{r['ips'] * K} | {r['mats'] * N + r['evq']:,} | {sum(c for c, _ in r['digits'])} | {r['stmt']:,} |")
    print('\n## D1 (challenge-free, NTT domain) per relation and field\n')
    print('| Relation | Field | range lookups | NTT-domain mults | NTTs (64-pt) | main cells | preprocessed cells | '
          'LogUp interactions |')
    print('|---|---|---|---|---|---|---|---|')
    for name, r in REL.items():
        for fn, f in FIELDS.items():
            c = count_d1(r, f)
            print(f"| {name} | {fn} | {c['look']:,} | {c['macs']:,} | {c['ntts']:,} | {c['main']:,} | "
                  f"{c['pre']:,} | {c['aux']:,} |")
    print('\n## D2 (Schwartz-Zippel at one point) per relation and field\n')
    print('| Relation | Field | range lookups | in-circuit ext MACs | main cells | verifier base x ext MACs |')
    print('|---|---|---|---|---|---|')
    for name, r in REL.items():
        for fn in ('Goldilocks', 'KoalaBear'):
            c = count_d2(r, FIELDS[fn])
            print(f"| {name} | {fn} | {c['look']:,} | {c['horner']:,} | {c['main']:,} | {c['ver']:,} |")
    print('\n## STARK (FRI) proof size, R_TX and R_REG, D1 layout, 128-bit target, 16 grinding bits\n')
    print('| Relation | Field | trace rows | opened width (main/pre/aux/quot) | blowup | FRI arity | regime | '
          'queries | proof KB | verify hash perms | prover LDE MB |')
    print('|---|---|---|---|---|---|---|---|---|---|---|')
    for name, fn in (('R_TX', 'Goldilocks'), ('R_TX', 'KoalaBear'), ('R_REG', 'Goldilocks')):
        f = FIELDS[fn]
        c = count_d1(REL[name], f)
        h, w = stark_shape(c, f)
        for b, a in ((1, 1), (2, 1), (3, 1), (3, 3), (4, 1), (4, 4)):
            for reg in ('conj', 'johnson'):
                q, size = fri_bytes(h, w, f, b, a, reg)
                perms = stark_verify_perms(h, w, f, b, a, reg)
                mem = h * 2**b * sum(w.values()) * f['B'] * 1.5 / 2**20
                print(f"| {name} | {fn} | 2^{int(math.log2(h))} | {w['main']}/{w['pre']}/{w['aux']}/{w['quot']} "
                      f"| {2**b} | {2**a} | {reg} | {q} | {size / 1000:.0f} | {perms:,} | {mem:.0f} |")
    # Prover throughput band, LDE base cells per second per thread, native [inference]: Polygon's > 2 M Poseidon2
    # permutations/s (M3 Max, all cores, 2024) x ~300 trace columns per permutation x blowup 2 / ~16 threads
    # ≈ 7.5e7; taken as 2e7..8e7 for KoalaBear, half for Goldilocks (64-bit products), wasm32 3-4x slower.
    print('\n## Prover estimate, R_TX, blowup 8, one thread [inference: throughput band, see source comment]\n')
    print('| Design | Field | base cells (main+pre+aux+quot) | LDE cells | native s | wasm32 s | LDE + tree MB |')
    print('|---|---|---|---|---|---|---|')
    for dn, fn in (('D1', 'Goldilocks'), ('D1', 'KoalaBear'), ('D2', 'Goldilocks'), ('D2', 'KoalaBear')):
        f = FIELDS[fn]
        c = (count_d1 if dn == 'D1' else count_d2)(REL['R_TX'], f)
        h, w = stark_shape(c, f)
        cells = c['main'] + c.get('pre', 2**16) + c['aux'] * f['ext'] + h * w['quot']
        lde = cells * 8
        lo, hi = (2e7, 8e7) if fn == 'KoalaBear' else (1e7, 4e7)
        mb = (lde * f['B'] + 2 * h * 8 * 32 * 4) / 2**20
        print(f"| {dn} | {fn} | {cells:,} | {lde:,} | {lde / hi:.2f}-{lde / lo:.2f} | "
              f"{3 * lde / hi:.2f}-{4 * lde / lo:.2f} | {mb:.0f} |")
    print('\n## Ligero over F_q, per relation\n')
    print('| Relation | witness elems | linear constraints | quadratic constraints | rate | regime | queries t | '
          'rows m | proof KB | verifier ext mults | verify ms (6 mulmod x 1.5 ns each, + 1 ms) |')
    print('|---|---|---|---|---|---|---|---|---|---|---|')
    for name, r in REL.items():
        for rho in (1 / 4, 1 / 8):
            for reg in ('classic', 'johnson'):
                g = ligero(r, rho, reg)
                print(f"| {name} | {g['n']:,} | {g['lin']:,} | {g['quad']:,} | 1/{int(1 / rho)} | {reg} | {g['t']} | "
                      f"{g['m']} | {g['size'] / 1000:.0f} | {g['ver']:,} | {g['ver'] * 9e-6 + 1:.0f} |")
    print('\n## Transfer gas floor (EIP-7623) and input limits by proof size\n')
    print('| proof KB | floor gas (M) | +16 inline credits (M) | R_TX input bytes (MAX_INPUT 262,144) |')
    print('|---|---|---|---|')
    for kb in (42.7, 64, 96, 128, 150, 179, 200, 250):
        p = kb * 1000
        inl = gas_floor(p) + 16 * 2064 * 25.2 * 10
        print(f'| {kb} | {gas_floor(p) / 1e6:.2f} | {inl / 1e6:.2f} | {int(5 + 83_072 + p):,} |')


if __name__ == '__main__':
    main()
