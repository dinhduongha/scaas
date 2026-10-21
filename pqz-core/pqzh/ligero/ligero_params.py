#!/usr/bin/env python3
"""Ligero over F_q for PQZH (docs/research/pqzh-ligero.md §2-§5): field checks, soundness per regime, and the
parameter choice (n, k, l, t) with a proof-size and verifier-work model. Stdlib only; every number printed is an
[estimate] from the layout model below, nothing is measured here.

  python3 pqz-core/pqzh/ligero/ligero_params.py          > runs/p1-params.txt   (layout of the crate, radices 2/19/43
                                                                                  and 2/19/43/431 side by side)
  python3 pqz-core/pqzh/ligero/ligero_params.py --p0     > runs/p0-params.txt   (the first model, kept for reference)
  python3 -I pqz-core/pqzh/ligero/ligero_params.py --set <set> > runs/c8-params-<set>.txt   (plan 5h Task 8c: one
        parameter set of pqz-core/params/sets/: field, domains, soundness, the crate's layout and exact proof bounds per
        form (checked against the crate's runs/c8-*-sizes.jsonl where it exists), precompile inputs, transaction
        calldata under EIP-7976, a preset search with the set's radices)

p1 (2026-10-14, crate layout): blinding rows in F_q^4 (3 polynomials = 12 base rows, needed for ZK since w, q, h have
F_q^4 coefficients), small values packed as the crate does (cs.rs), k need not divide n (the encoding is an inverse
FFT on H_k and a coset FFT on 3 H_n; 3 H_n and H_k are always disjoint because 3 generates F_q^*), n >= 4k (degree
correction, §5.1), exact proven factor of RS[n, 2k-1] at its unique-decoding radius.
"""
import json
import math
import os
import re
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


FBITS = EXT * math.log2(Q)                   # |F_q^4| = 2^168


def johnson(n, k, m=3):
    """Johnson-bound proven regime (reference only, owner 2026-10-14 (b)). Proximity: BCIKS20 Thm 1.5/1.6 list-decoding
    regime for RS[n, 2k-1] (rate r = (2k-1)/n): delta = 1 - sqrt(r) - eta, m = max(ceil(sqrt(r)/(2 eta)), 3), error
    eps = (m + 1/2)^7 / (3 r^1.5) n^2 / |F|. Consistency tests: per query max(1 - delta, (2k-2)/n), which needs mutual
    correlated agreement up to delta (without it the per-query term is delta + (2k-2)/n and the Johnson radius gains
    nothing over unique decoding). Returns (per-query factor, field bits charged once, field bits per spanning word
    of the m_rows-row affine space is done by the caller), or None if the degree correction fails ((1-delta) n < 3k - 2)."""
    r = (2 * k - 1) / n
    eta = math.sqrt(r) / (2 * m)
    one_minus_delta = math.sqrt(r) + eta
    if one_minus_delta * n < 3 * k - 2:
        return None
    f = max(one_minus_delta, (2 * k - 2) / n)
    eps = (m + 0.5) ** 7 / (3 * r ** 1.5) * n * n
    return f, FBITS - math.log2(eps)


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


def search_johnson(rel, smooth):
    out = []
    for n in smooth:
        if n > NMAX:
            continue
        for k in smooth:
            if 4 * k > n or k < 64:
                continue
            for m in range(3, 12):
                j = johnson(n, k, m)
                if not j:
                    continue
                f, jb = j
                t = t_of(f)
                r = model1(rel, n, k, t, smooth)
                if r and r['prover'] <= PMAX:
                    per_word = jb - math.log2(2 * r['m'] + 3)
                    out.append((r['size'], n, k, t, f, m, jb, per_word, r))
    return out


def main_johnson():
    print('\n## Johnson-bound proven regime (reference only; owner 2026-10-14 (b))\n')
    print('Field term: BCIKS20 list-decoding error (m + 1/2)^7 / (3 r^1.5) n^2 / 2^168, r = (2k-1)/n, charged once for the')
    print('affine space ("once") or once per spanning word, 2m + 3 words ("per word"). Per query max(sqrt(r) + eta,')
    print('(2k-2)/n), eta = sqrt(r)/(2m): assumes mutual correlated agreement up to the Johnson radius.\n')
    print('| relation | selection | n | k | m (BCIKS) | factor | t | l | rows | proof B | field bits once / per word |')
    print('|---|---|---|---|---|---|---|---|---|---|---|')
    for rel in ['R_REG', 'R_TX']:
        res = search_johnson(rel, SMOOTH4)
        picks = [('smallest, any field bits', min(res, key=lambda x: x[0])),
                 ('smallest with once >= 128', min((x for x in res if x[6] >= 128), key=lambda x: x[0])),
                 ('most field bits (per word)', max(res, key=lambda x: x[7]))]
        for name, (size, n, k, t, f, m, jb, pw, r) in picks:
            print(f"| {rel} | {name} | {n} | {k} | {m} | {f:.4f} | {t} | {r['ell']} | {r['m']} | {size:,} | {jb:.1f} / {pw:.1f} |")


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



# ---- per parameter set (plan 5h Task 8c): --set <name> ----
HERE = os.path.dirname(os.path.abspath(__file__))
SETS_DIR = os.path.join(HERE, '..', '..', 'params', 'sets')
# a set whose directory Task 8b has not created yet: (n, K_MAX, q) for n-study's budget(), as gen_set.py derives them
PENDING = {'n2560-kmax16384': (2560, 16_384, 2**50 - 42_310_535)}
# pqzh_set.rs defaults (every set so far)
PQZH_DEFAULT = {'GEN': 3, 'NR': 3, 'RADICES': [2, 19, 43, 431], 'PRESET_N': 32756, 'PRESET_K': 817, 'PRESET_T': 121}
MAX_PROOF_PQZH, MAX_INPUT_TODAY, MAX_INPUT_8D = 262_144, 393_216, 512 * 1024
CAP = 2**24                  # Ethereum-like regular gas per transaction (EIP-7825)
TX_LIMIT = (CAP - 15_000) // 64   # EIP-7976: 15,000 + 64 gas per calldata byte <= the cap (Task 7b: 261,909 B)
BLIND_B, DIGEST = 12, 32


def read_rs(path):
    """`pub(crate) const NAME: T = value;` lines of a generated / hand-written set file"""
    out = {}
    for name, v in re.findall(r'pub\(crate\) const (\w+): [^=]+= ([^;]+);', open(path).read()):
        v = v.strip()
        if v.startswith('"'):
            out[name] = v.strip('"')
        elif v.startswith('&[') or v.startswith('['):
            out[name] = [int(x.replace('_', '')) for x in v.strip('&[]').split(',') if x.strip()]
        else:
            out[name] = int(v.replace('_', ''))
    return out


def set_consts(name):
    d = os.path.join(SETS_DIR, name)
    if os.path.exists(os.path.join(d, 'rust', 'set.rs')):
        c = read_rs(os.path.join(d, 'rust', 'set.rs'))
        ph = os.path.join(d, 'pqzh_set.rs')
        c.update(read_rs(ph) if os.path.exists(ph) else PQZH_DEFAULT)
        src = f'pqz-core/params/sets/{name}/rust/set.rs + ' + ('pqzh_set.rs' if os.path.exists(ph) else 'defaults (no pqzh_set.rs)')
        return c, src
    n, kmax, q = PENDING[name]
    sys.path.insert(0, os.path.join(HERE, '..', '..', 'pqzl', 'params', 'n-study'))
    from budget import budget
    b = budget(n, kmax, q)
    c = dict(SET_NAME=name, N=n, K=b['k'], Q=q, LOG2Q=(q - 1).bit_length(), K_MAX=kmax, MBITS=b['m'], CBITS=b['m'] - 3,
             EBITS=b['e_bits'] + 1, BETA_S=b['bs'], BETA_E=b['be'], BETA_2=64, DELTA=b['D'])
    c.update(PQZH_DEFAULT)
    return c, f'n-study budget({n}, {kmax}, {q}) as gen_set.py (no set directory yet: Task 8b creates it) + defaults'


def is_prime(n):
    return n > 1 and all(n % d for d in range(2, math.isqrt(n) + 1))


class Lay:
    """cs::Layout::new's widths of a set: CBD(1) / CBD(20) groups x + 2^blen(beta) in blen(beta) + 1 bits, slacks
    B^2 - ||x||^2 in blen(B^2) bits, e2 likewise with BETA_2, M / carries / e_T widths of the set"""
    def __init__(self, c):
        bl = lambda x: x.bit_length()  # noqa: E731
        self.N, self.eb = c['N'], (c['LOG2Q'] + 7) // 8
        self.s_bits, self.e_bits = bl(c['BETA_S']) + 1, bl(c['BETA_E']) + 1
        self.sl_s, self.sl_e = bl(c['BETA_S']**2), bl(c['BETA_E']**2)
        self.e2_bits, self.sl_2 = bl(c['BETA_2']) + 1, bl(c['BETA_2']**2)
        self.m_bits, self.c_bits, self.et_bits = c['MBITS'], c['CBITS'], c['EBITS']


def rows_set(p, rel, ell):
    """cs::Layout::new(rel, ell).m; rel = ('reg' | 'tx' | 'tx0' | 'burn' | 'ds' | 'dr') or ('txm', M, aud)"""
    se, sl = [p.s_bits, p.e_bits], [(1, p.sl_s), (1, p.sl_e)]

    def debit(legs, nd, pairs):
        v = [(16 * legs, p.e2_bits)] + ([(16 * nd, 4)] if nd else [])
        v += [(16, 4), (16, p.m_bits), (16, p.c_bits), (16, p.et_bits)] + sl * pairs + [(1, p.sl_2)] * legs
        return v

    name = rel[0]
    if name == 'reg':
        bigs, smalls = se, sl
    elif name in ('tx', 'tx0', 'burn'):
        bigs, smalls = se * 2, debit({'tx': 3, 'tx0': 2, 'burn': 1}[name], 0 if name == 'burn' else 1, 2)
    elif name == 'ds':
        bigs, smalls = se, [(16, p.e2_bits)] + sl + [(1, p.sl_2)]
    elif name == 'dr':
        bigs, smalls = se, [(16, p.et_bits)] + sl
    else:
        _, m, aud = rel
        pairs = 1 + (m + 3) // 4
        bigs, smalls = se * pairs, debit(m + 1 + aud * m, m, pairs)
    nr = -(-p.N // ell)
    return (sum(nr * (2 + b) for b in bigs) + 2 * -(-sum(c for c, _ in smalls) // ell)
            + -(-sum(c * b for c, b in smalls) // ell))


def bound_set(p, rel, n, k, t):
    """Params::max_len_exact: root, w, q, h, nonce, t distinct columns, the largest pruned multiproof"""
    ell, d = k - t - 1, (n - 1).bit_length()
    mid = sum(min(t, -(-n // (1 << lv))) for lv in range(1, d))
    poly = (2 * (2 * k - 1) + (2 * k - 1 - ell)) * EXT * p.eb
    return 32 + poly + 8 + t * (32 + (rows_set(p, rel, ell) + BLIND_B) * p.eb) + (mid + 2 - t) * DIGEST


def stmt_set(p, rel):
    """pqz-stmt lengths: header 640, pk / u 8 N bytes, v 128"""
    pk, v, h = 8 * p.N, 128, 640
    name = rel[0]
    if name == 'reg':
        return 96 + pk
    if name in ('ds', 'dr'):
        return 288 + 2 * pk + v
    if name in ('tx', 'tx0', 'burn'):
        legs = {'tx': 3, 'tx0': 2, 'burn': 1}[name]
        return h + legs * pk + (pk + v) + pk + legs * v
    _, m, aud = rel
    return h + (1 + m + aud) * pk + (pk + v) + (m + 3) // 4 * pk + v * (m + 1) + aud * v * m


def pad32(n):
    return n + (-n % 32)


def calldata(p, rel, proof):
    """one transaction's calldata through the token / registry (pqzl/params/p16k/inputs16k.py's ABI layout, Task 7b,
    with pk = 8 N): (bytes, path)"""
    pk, v, auth = 8 * p.N, 128, 3_456

    def relayed(inner):
        return 516 + pad32(inner)

    def tail(payload, head=160):
        return 4 + head + 32 + pad32(payload) + 32 + pad32(proof) + 32 + auth + 32

    name = rel[0]
    if name == 'reg':
        return 4 + 160 + 32 + 1_952 + 32 + pad32(3_309) + 32 + pk + 32 + pad32(proof), 'UARegistry.register'
    if name in ('ds', 'dr'):
        return 4 + 160 + 32 + pad32(proof), 'verifyTransferAmount (eth_call)'
    if name in ('tx', 'tx0'):
        return relayed(tail(208 + pk + v + v + (v if name == 'tx' else 0))), 'relayed mtxExecute (op 1)'
    if name == 'burn':
        return relayed(tail(160 + pk + v, head=224)), 'relayed mtxExecute (op 2)'
    _, m, aud = rel
    out = pk * ((m + 3) // 4) + v * (m + 1) + (v * m if aud else 0)
    return relayed(tail(224 + 16 + 32 * m + out)), 'relayed mtxExecute (op 7)'


SET_RELS = [('reg',), ('tx',), ('burn',), ('ds',), ('dr',), ('tx0',), ('txm', 1, 1), ('txm', 1, 0), ('txm', 2, 1),
            ('txm', 2, 0), ('txm', 4, 1), ('txm', 4, 0), ('txm', 8, 1), ('txm', 8, 0)]
CRATE_NAMES = {('reg',): 'R_REG', ('tx',): 'R_TX', ('burn',): 'R_BURN', ('ds',): 'R_DS', ('dr',): 'R_DR', ('tx0',): 'R_TX0'}


def label(rel):
    if rel[0] != 'txm':
        return CRATE_NAMES[rel]
    return f"R_TXM{rel[1]}{'' if rel[2] else '_0'}"


def crate_sizes(name):
    """the crate's own exact bounds (ligero_kat sizes) if this set was built: runs/c8-<tag>-sizes.jsonl"""
    for f in os.listdir(os.path.join(HERE, 'runs')):
        if f.startswith('c8-') and f.endswith('-sizes.jsonl'):
            rows = [json.loads(x) for x in open(os.path.join(HERE, 'runs', f))]
            if rows and rows[0]['set'] == name:
                return f, {r['rel']: r for r in rows}
    return None, {}


def main_set(name):
    c, src = set_consts(name)
    q, L = c['Q'], c['LOG2Q']
    p = Lay(c)
    f = factor(q - 1)
    print(f'# PQZH Ligero at parameter set {name} (plan 5h Task 8c; [model] = this layout model, [crate] = the crate)\n')
    print(f'constants: {src}\n')
    print('## Field and domains\n')
    assert is_prime(q) and q % 16 == 9 and 2**(L - 1) < q < 2**L
    assert sorted(f) == sorted(c['QM1']) if 'QM1' in c else True, (f, c.get('QM1'))
    gen, nr = c['GEN'], c['NR']
    assert all(pow(gen, (q - 1) // r, q) != 1 for r in set(f)), 'GEN generates F_q^*'
    assert pow(nr, (q - 1) // 2, q) == q - 1 and q % 4 == 1, 'X^4 - NR irreducible'
    nl = 2 if L <= 42 else 3
    print(f'- q = {q:,} (2^{math.log2(q):.2f}), prime, q mod 16 = 9; q - 1 = {" * ".join(map(str, f))}')
    print(f'- F_q element {L} bits in {p.eb} bytes (EB); F_q^4 = F_q[X]/(X^4 - {nr}) ({nr} a non-square, q = 1 mod 4), '
          f'|F_q^4| = 2^{4 * math.log2(q):.1f}; generator {gen}')
    print(f'- native: Barrett (products < 2^{2 * L}, u128); wasm32: {nl} limbs of {-(-L // nl)} bits in u64')
    rad = c['RADICES']
    nmax = 4 * math.prod(rad)
    extra = sorted({r for r in f if r not in rad and r <= 431})
    assert (q - 1) % nmax == 0
    n, k, t = c['PRESET_N'], c['PRESET_K'], c['PRESET_T']
    ell = k - t - 1
    fac = factor_proven(n, k)
    assert t_of(fac) == t and all(pow(gen, (q - 1) // r, q) != 1 for r in set(factor(n)) | set(factor(k)))
    lcm = n * k // math.gcd(n, k)
    assert pow(gen, lcm, q) != 1, 'GEN H_n meets H_k'
    print(f'- radices {"/".join(map(str, rad))} divide q - 1 (domain sizes | {nmax:,}); small primes of q - 1 the crate '
          f'does not use: {extra or "none"}')
    print(f'- THE preset: proven, n = {n:,} = {" * ".join(map(str, factor(n)))} (H_n, the commitment coset {gen} H_n), '
          f'k = {k} = {" * ".join(map(str, factor(k)))} (H_k), t = {t}, l = {ell}, N2 = {n2_of(k, SMOOTH4)}; '
          f'{gen} H_n and H_k disjoint ({gen}^lcm(n, k) != 1)\n')
    print('## Soundness (THE preset; per-query factor depends on n, k only)\n')
    qb = t * -math.log2(fac) + POW
    print(f'- query: t = {t} x {-math.log2(fac):.4f} + {POW} grinding = {qb:.2f} bits (same as v3); field terms grow '
          f'with q: |F_q^4| = 2^{4 * math.log2(q):.1f} (v3 2^168.0); the crate\'s per-relation totals: '
          f'`ligero_kat sizes` (runs/c8-*-sizes.jsonl)\n')
    cf, cs = crate_sizes(name)
    print('## Sizes per form [model] (exact verifier bound = the largest proof the verifier parses)\n')
    print(f'| relation | rows m | proof bound B | <= MAX_PROOF_PQZH {MAX_PROOF_PQZH:,} | statement B | input 5 + stmt + '
          f'bound B | <= MAX_INPUT {MAX_INPUT_TODAY:,} today / {MAX_INPUT_8D:,} (8d) | crate bound [crate] | crate soundness bits |')
    print('|---|---|---|---|---|---|---|---|---|')
    checked = 0
    for rel in SET_RELS:
        b, st = bound_set(p, rel, n, k, t), stmt_set(p, rel)
        inp = 5 + st + b
        cr = cs.get(label(rel))
        if cr:
            assert (cr['max_proof_len'], cr['stmt_bytes'], cr['rows_m']) == (b, st, rows_set(p, rel, ell)), (rel, cr)
            checked += 1
        snd = cr['soundness'].get('total') if cr else None
        print(f"| {label(rel)} | {rows_set(p, rel, ell)} | {b:,} | {'yes' if b <= MAX_PROOF_PQZH else 'NO'} | {st:,} | "
              f"{inp:,} | {'yes' if inp <= MAX_INPUT_TODAY else 'no'} / {'yes' if inp <= MAX_INPUT_8D else 'NO'} | "
              f"{cr['max_proof_len'] if cr else '-'} | {snd if snd is not None else ('not built' if cr else '-')} |")
    print(f'\nmodel = crate on {checked} relations ({cf or "no crate build of this set yet"}); op 7 M = 8: G = 2, not a '
          f'built PQZH shape\n')
    print(f'## One transaction (EIP-7976: 15,000 + 64 x calldata bytes <= the regular-gas cap; at 2^24: <= {TX_LIMIT:,} B)\n')
    print('Calldata through the token / registry (Task 7b ABI model, inputs16k.py, pk = 8 N) with the proof at its bound; '
          'the precompile input itself is built in memory (only a direct call carries it as calldata).\n')
    print('| relation | path | tx calldata B | EIP-7976 floor gas | fits 2^24 | smallest cap (floor) | direct-call input B '
          '| direct fits 2^24 | largest proof one 2^24 tx carries |')
    print('|---|---|---|---|---|---|---|---|---|')
    for rel in SET_RELS[:12]:
        b = bound_set(p, rel, n, k, t)
        cd, path = calldata(p, rel, b)
        inp = 5 + stmt_set(p, rel) + b
        lo, hi = 0, TX_LIMIT
        while lo < hi:
            mid = (lo + hi + 1) // 2
            lo, hi = (mid, hi) if calldata(p, rel, mid)[0] <= TX_LIMIT else (lo, mid - 1)
        floor = 15_000 + 64 * cd
        print(f"| {label(rel)} | {path} | {cd:,} | {floor:,} | {'yes' if cd <= TX_LIMIT else 'NO'} | {floor / 1e6:.2f} M | "
              f"{inp:,} | {'yes' if inp <= TX_LIMIT else 'NO'} | {lo:,} |")
    print('\n## Preset search (proven, n >= 4k, k >= 64, l >= 16, prover <= %.0e products): the smallest R_TX and '
          'R_TXM4 bounds, radices of the crate and with the small primes of q - 1 it does not use\n' % PMAX)
    print('| radices | relation | n | k | t | l | rows m | proof bound B | <= 262,144 | prover products |')
    print('|---|---|---|---|---|---|---|---|---|---|')
    mult = {r: f.count(r) for r in set(f)}
    for rs in [rad] + ([rad + extra] if extra else []):
        sm = {1}
        for r in rs:
            sm = {x * r**e for x in sm for e in range(mult[r] + (2 if r == 2 else 0) + 1) if r**e <= 2**21}
        sm = sorted(x for x in sm if (q - 1) % x == 0 and x <= NMAX)
        for rel in (('tx',), ('txm', 4, 1)):
            res = []
            for nn in sm:
                for kk in sm:
                    if 4 * kk > nn or kk < 64:
                        continue
                    tt = t_of(factor_proven(nn, kk))
                    if kk - tt - 1 < 16:
                        continue
                    m_rows = rows_set(p, rel, kk - tt - 1)
                    n2 = min(x for x in sm if x >= 2 * kk - 1) if 2 * kk - 1 <= sm[-1] else None
                    if n2 is None:
                        continue
                    pr = (m_rows + BLIND_B) * (fft_cost(kk) + fft_cost(nn)) + (m_rows + 40) * fft_cost(n2)
                    if pr <= PMAX:
                        res.append((bound_set(p, rel, nn, kk, tt), nn, kk, tt, m_rows, pr))
            for b, nn, kk, tt, m_rows, pr in sorted(res)[:4]:
                print(f"| {'/'.join(map(str, rs))} | {label(rel)} | {nn:,} | {kk} | {tt} | {kk - tt - 1} | {m_rows} | {b:,} | "
                      f"{'yes' if b <= MAX_PROOF_PQZH else 'no'} | {pr:.3g} |")


if __name__ == '__main__':
    if '--set' in sys.argv:
        main_set(sys.argv[sys.argv.index('--set') + 1])
    elif '--p0' in sys.argv:
        main0()
    else:
        main1()
        main_johnson()
