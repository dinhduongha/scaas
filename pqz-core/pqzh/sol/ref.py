#!/usr/bin/env python3
"""PQZH Solidity verifier study (docs/research/pqzh-solidity-verifier.md): stdlib-only references and the test
vectors of smartcontracts/evm/test/pqzh/PqzhTest.t.sol.

References: Goldilocks (p = 2^64 - 2^32 + 1), its quadratic extension (u^2 = 7) and cubic extension (x^3 = x + 1),
both as in Plonky3 0.8 (p3-goldilocks extension.rs), Keccak-256 (pure Python Keccak-f[1600]), Merkle paths with
Plonky3's mixed-height injection (p3-merkle-tree mmcs/batch.rs verify_batch), FRI fold_row for arity 2 / 8 / 16
(p3-fri two_adic_pcs.rs: closed form for arity 2, Lagrange interpolation otherwise), the LogUp public sum
sum m_i / (beta - k_i), a Horner fingerprint of the statement coefficients; and a synthetic proof for the
end-to-end verifier skeleton (`Skeleton` below, the byte format `PqzhSkeleton.verify` reads).

  python3 pqz-core/pqzh/sol/ref.py --selftest     # asserts only
  python3 pqz-core/pqzh/sol/ref.py                # writes smartcontracts/evm/test/vectors/pqzh/*

Field elements are 8-byte big-endian everywhere (EVM-friendly: calldataload + shr, no byte swap); an extension
element is its E coefficients in order. Ext elements in the Solidity code are packed in one word, coefficient i at
bits 64 i.
"""
import json, os, random, sys

P = 0xFFFFFFFF00000001
M64 = (1 << 64) - 1
SHIFT = 7                                   # Goldilocks GENERATOR: the LDE coset shift
G32 = 0x185629DCDA58878C                    # TWO_ADIC_GENERATORS[32], order 2^32
TAG = b'SCAAS-PQZH-TRANSCRIPT-V1'

# ---------------------------------------------------------------- base field and extensions


def inv(a):
    assert a % P
    return pow(a, P - 2, P)


def g(bits):                                 # Goldilocks::two_adic_generator(bits)
    return pow(G32, 1 << (32 - bits), P)


def rev(i, bits):
    return int(format(i, f'0{bits}b')[::-1], 2) if bits else 0


def e(x, E):                                 # base -> ext
    return (x % P,) + (0,) * (E - 1)


def eadd(a, b):
    return tuple((x + y) % P for x, y in zip(a, b))


def esub(a, b):
    return tuple((x - y) % P for x, y in zip(a, b))


def escale(a, s):
    return tuple(x * s % P for x in a)


def emul(a, b):
    if len(a) == 2:                          # u^2 = 7
        return ((a[0] * b[0] + 7 * a[1] * b[1]) % P, (a[0] * b[1] + a[1] * b[0]) % P)
    c = [0] * 5                              # x^3 = x + 1, x^4 = x^2 + x
    for i in range(3):
        for j in range(3):
            c[i + j] += a[i] * b[j]
    return ((c[0] + c[3]) % P, (c[1] + c[3] + c[4]) % P, (c[2] + c[4]) % P)


def einv(a):
    if len(a) == 2:
        n = inv((a[0] * a[0] - 7 * a[1] * a[1]) % P)
        return (a[0] * n % P, (P - a[1]) * n % P)
    a0, a1, a2 = a                           # adjugate of the multiplication matrix (columns a, a.x, a.x^2)
    m = [[a0, a2, a1], [a1, (a0 + a2) % P, (a1 + a2) % P], [a2, a1, (a0 + a2) % P]]
    c0 = (m[1][1] * m[2][2] - m[1][2] * m[2][1]) % P
    c1 = (m[1][2] * m[2][0] - m[1][0] * m[2][2]) % P
    c2 = (m[1][0] * m[2][1] - m[1][1] * m[2][0]) % P
    d = inv((m[0][0] * c0 + m[0][1] * c1 + m[0][2] * c2) % P)
    return (c0 * d % P, c1 * d % P, c2 * d % P)


def epow(a, n):
    r = e(1, len(a))
    while n:
        if n & 1:
            r = emul(r, a)
        a, n = emul(a, a), n >> 1
    return r


def pack(a):                                 # Solidity word: coefficient i at bits 64 i
    return sum(x << (64 * i) for i, x in enumerate(a))


def be(a):                                   # bytes of an ext (or base) element
    return b''.join(x.to_bytes(8, 'big') for x in (a if isinstance(a, tuple) else (a,)))


# ---------------------------------------------------------------- Keccak-256

RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
      0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
      0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
      0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
      0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14]  # [x + 5 y]


def keccak_f(A):
    for rc in RC:
        C = [A[x] ^ A[x + 5] ^ A[x + 10] ^ A[x + 15] ^ A[x + 20] for x in range(5)]
        D = [C[(x - 1) % 5] ^ (((C[(x + 1) % 5] << 1) | (C[(x + 1) % 5] >> 63)) & M64) for x in range(5)]
        B = [0] * 25
        for x in range(5):
            for y in range(5):
                v, r = A[x + 5 * y] ^ D[x], ROT[x + 5 * y]
                B[y + 5 * ((2 * x + 3 * y) % 5)] = ((v << r) | (v >> (64 - r))) & M64 if r else v
        A = [B[i] ^ (~B[(i % 5 + 1) % 5 + 5 * (i // 5)] & B[(i % 5 + 2) % 5 + 5 * (i // 5)]) for i in range(25)]
        A[0] ^= rc
    return A


def keccak(data, rate=136, pad=0x01, out=32):
    """Keccak-256 (pad 0x01) or SHAKE256 (pad 0x1F, any output length)."""
    m = bytearray(data) + bytes([pad]) + bytes((-len(data) - 1) % rate)
    m[-1] |= 0x80
    A = [0] * 25
    for o in range(0, len(m), rate):
        for i in range(rate // 8):
            A[i] ^= int.from_bytes(m[o + 8 * i:o + 8 * i + 8], 'little')
        A = keccak_f(A)
    res = b''
    while len(res) < out:
        res += b''.join(A[i].to_bytes(8, 'little') for i in range(rate // 8))
        A = keccak_f(A)
    return res[:out]


def compress(l, r):
    return keccak(l + r)


# ---------------------------------------------------------------- FRI fold, LogUp, Horner


def lagrange_at(xs, ys, z):                  # p3-fri lagrange_interpolate_at (xs base, ys and z ext)
    E = len(z)
    acc = e(0, E)
    for i, xi in enumerate(xs):
        num, den = e(1, E), 1
        for j, xj in enumerate(xs):
            if j != i:
                num = emul(num, esub(z, e(xj, E)))
                den = den * (xi - xj) % P
        acc = eadd(acc, emul(ys[i], escale(num, inv(den))))
    return acc


def fold_row(index, log_height, log_arity, beta, evals):
    """TwoAdicFriFolding::fold_row: evals at s * w^rev(j), s = g(log_height + log_arity)^rev(index, log_height)."""
    s = pow(g(log_height + log_arity), rev(index, log_height), P)
    if log_arity == 1:
        lo, hi = evals
        h = inv(2)
        return eadd(escale(eadd(lo, hi), h), emul(escale(esub(lo, hi), inv(2 * s % P)), beta))
    k = 1 << log_arity
    xs = [s * pow(g(log_arity), rev(j, log_arity), P) % P for j in range(k)]
    return lagrange_at(xs, evals, beta)


def logup_sum(keys, mults, beta):
    acc = e(0, len(beta))
    for k, m in zip(keys, mults):
        acc = eadd(acc, escale(einv(esub(beta, e(k, len(beta)))), m))
    return acc


def horner(coeffs, gamma):
    acc = e(0, len(gamma))
    for c in coeffs:
        acc = eadd(emul(acc, gamma), e(c, len(gamma)))
    return acc


# ---------------------------------------------------------------- Merkle (sparse, many queries)


class Sparse:
    """A Merkle tree of which only the queried paths are real: rows of each height group at the queried positions,
    every other subtree a random digest. Mixed heights as Plonky3: the leaf hashes every row of the tallest height
    (one group here), a shorter group is injected as compress(node, hash(rows)) once the walk reaches its height."""

    def __init__(self, rng, depth, groups, idxs, rows):
        # groups: [(log_h, width)] tallest first, groups[0] log_h == depth; rows[gi][row index] = element list
        self.depth, self.paths = depth, {}
        lvl = {}
        for i in idxs:
            lvl[i] = keccak(b''.join(be(v) for v in rows[0][i]))
        sib = {}
        for l in range(depth):
            nxt = {}
            for i in sorted(lvl):
                j = i ^ 1
                if j not in lvl and (l, j) not in sib:
                    sib[(l, j)] = rng.randbytes(32)
                s = lvl.get(j, sib.get((l, j)))
                node = compress(lvl[i], s) if i % 2 == 0 else compress(s, lvl[i])
                h = depth - l - 1
                for gi, (lh, _) in enumerate(groups):
                    if gi and lh == h:
                        node = compress(node, keccak(b''.join(be(v) for v in rows[gi][i >> 1])))
                nxt[i >> 1] = node
            self.paths[l] = (dict(lvl), sib)
            lvl = nxt
        assert len(lvl) == 1
        self.root = lvl[0]

    def path(self, idx):                     # unpruned siblings, leaf level first
        out = []
        for l in range(self.depth):
            lvl, sib = self.paths[l]
            j = (idx >> l) ^ 1
            out.append(lvl.get(j, sib.get((l, j))))
        return out


def pruned_siblings(depth, idxs):            # what a pruned multiproof (p3 pruning.rs) sends
    n, s = 0, set(idxs)
    for _ in range(depth):
        n += sum(1 for i in s if i ^ 1 not in s)
        s = {i >> 1 for i in s}
    return n


# ---------------------------------------------------------------- end-to-end skeleton proof


class Transcript:
    """Keccak-256 duplex: observe(d): st = keccak(st || d); sample(): st = keccak(st), E 64-bit limbs mod p."""

    def __init__(self, seed):
        self.st = seed

    def observe(self, d):
        self.st = keccak(self.st + d)

    def sample(self, E):
        self.st = keccak(self.st)
        w = int.from_bytes(self.st, 'big')
        return tuple(((w >> (64 * i)) & M64) % P for i in range(E))


def shape_words(sh):
    """Encode a shape (dict) as the 32-byte words PqzhSkeleton reads; see the Solidity `_shape`."""
    w = [sh['E'], sh['Q'], sh['pow'], sh['logH0'], sh['logBlowup'], len(sh['trees'])]
    for t in sh['trees']:
        w += [1 if t['fixed'] else 0, int.from_bytes(t.get('root', bytes(32)), 'big'), t['npts'], len(t['groups'])]
        for lh, wd in t['groups']:
            w += [lh, wd]
    w += [len(sh['arity'])] + sh['arity'] + [sh['finalLen'], sh['oodMuls'], sh['perMacs'], sh['stmtOff'], sh['op']]
    return b''.join(x.to_bytes(32, 'big') for x in w)


def skeleton_proof(sh, stmt, seed_rng=1):
    """Synthetic proof for `sh` that passes every Merkle check and the proof-of-work of PqzhSkeleton.verify; the
    final-polynomial and constraint values are random (computed by the verifier, not enforced). Query indices come
    from the statement digest (a synthetic shortcut so that the sparse trees can be built first; same gas)."""
    rng = random.Random(seed_rng)
    E, Q, H0, lb = sh['E'], sh['Q'], sh['logH0'], sh['logBlowup']
    rnd = lambda: rng.randrange(P)
    rext = lambda: tuple(rnd() for _ in range(E))
    seed = keccak(TAG + bytes([sh['op']]) + len(stmt).to_bytes(4, 'big') + stmt)
    qs = keccak(seed + b'QUERY')
    idxs = [int.from_bytes(keccak(qs + j.to_bytes(32, 'big')), 'big') & ((1 << H0) - 1) for j in range(Q)]
    tr = Transcript(seed)
    proof, trees = b'', []
    for t in sh['trees']:
        depth = t['groups'][0][0]
        rows = [{i >> (H0 - lh): [rnd() for _ in range(wd)] for i in idxs} for lh, wd in t['groups']]
        sp = Sparse(rng, depth, t['groups'], [i >> (H0 - depth) for i in idxs], rows)
        trees.append((sp, rows))
        if t['fixed']:
            t['root'] = sp.root
        else:
            proof += sp.root
    # challenges, as the Solidity verifier: after the 1st proof root betaL and gamma, the 2nd alpha, the 3rd zeta
    ch, k = {}, 0
    for t, (sp, _) in zip(sh['trees'], trees):
        if t['fixed']:
            continue
        tr.observe(sp.root)
        if k == 0:
            ch['betaL'], ch['gamma'] = tr.sample(E), tr.sample(E)
        elif k == 1:
            ch['alpha'] = tr.sample(E)
        else:
            ch['zeta'] = tr.sample(E)
        k += 1
    ood = []                                   # per tree, group, point: width ext values
    for t in sh['trees']:
        ood.append([[[rext() for _ in range(wd)] for _ in range(t['npts'])] for _, wd in t['groups']])
    ood_bytes = b''.join(be(v) for tg in ood for gp in tg for pt in gp for v in pt)
    proof += ood_bytes
    tr.observe(ood_bytes)
    ad = tr.sample(E)
    # DEEP: per (tree, group, point) lambda = ad^offset, O = sum_c ad^c ood_c
    maxw = max(wd for t in sh['trees'] for _, wd in t['groups'])
    apow = [e(1, E)]
    for _ in range(maxw):
        apow.append(emul(apow[-1], ad))
    terms, off = [], 0                         # (tree, group, point, lambda, O, log_h)
    zeta = ch['zeta']
    for ti, t in enumerate(sh['trees']):
        for gi, (lh, wd) in enumerate(t['groups']):
            for p in range(t['npts']):
                O = e(0, E)
                for c in range(wd):
                    O = eadd(O, emul(apow[c], ood[ti][gi][p][c]))
                terms.append((ti, gi, p, epow(ad, off), O, lh))
                off += wd
    ro = []                                    # per query: {log_h: value}
    for i in idxs:
        x = SHIFT * pow(g(H0), rev(i, H0), P) % P
        r = {}
        for ti, gi, p, lam, O, lh in terms:
            t = sh['trees'][ti]
            wd = t['groups'][gi][1]
            vals = trees[ti][1][gi][i >> (H0 - lh)]
            R = e(0, E)
            for c in range(wd):
                R = eadd(R, escale(apow[c], vals[c]))
            xh = pow(x, 1 << (H0 - lh), P)
            z = zeta if p == 0 else escale(zeta, g(lh - lb))
            num = emul(lam, esub(R, O))
            r[lh] = eadd(r.get(lh, e(0, E)), emul(num, einv(esub(e(xh, E), z))))
        ro.append(r)
    # FRI
    cur = {i: ro[q][H0] for q, i in enumerate(idxs)}   # value at each queried index of the current layer
    h, layers, betas = H0, [], []
    for a in sh['arity']:
        k = 1 << a
        leaves = {}
        for i, v in cur.items():
            leaves.setdefault(i >> a, {})[i & (k - 1)] = v
        full = {li: [pos[j] if j in pos else rext() for j in range(k)] for li, pos in sorted(leaves.items())}
        flat = {li: [c for v in full[li] for c in v] for li in full}
        sp = Sparse(rng, h - a, [(h - a, k * E)], list(flat), [flat])
        proof += sp.root
        tr.observe(sp.root)
        beta = tr.sample(E)
        layers.append((sp, full, a, h))
        betas.append(beta)
        nxt = {}
        for i in cur:
            li = i >> a
            nxt[li] = fold_row(li, h - a, a, beta, full[li])
        h -= a
        bk = epow(beta, k)                    # roll in the reduced openings of height h: folded += beta^k * ro
        added = set()
        for q, i in enumerate(idxs):
            li = i >> (H0 - h)
            if h in ro[q] and li not in added:
                nxt[li] = eadd(nxt[li], emul(bk, ro[q][h]))
                added.add(li)
        cur = nxt
    final = [rext() for _ in range(sh['finalLen'])]
    fb = b''.join(be(v) for v in final)
    proof += fb
    tr.observe(fb)
    w = 0
    while True:
        hsh = keccak(tr.st + w.to_bytes(8, 'big'))
        if int.from_bytes(hsh, 'big') >> (256 - sh['pow']) == 0:
            break
        w += 1
    proof += w.to_bytes(8, 'big')
    # per query openings
    for q, i in enumerate(idxs):
        for ti, t in enumerate(sh['trees']):
            sp, rows = trees[ti]
            depth = t['groups'][0][0]
            for gi, (lh, wd) in enumerate(t['groups']):
                proof += b''.join(be(v) for v in rows[gi][i >> (H0 - lh)])
            proof += b''.join(sp.path(i >> (H0 - depth)))
        ii = i
        for sp, full, a, hh in layers:
            k = 1 << a
            li, pos = ii >> a, ii & (k - 1)
            proof += b''.join(be(full[li][j]) for j in range(k) if j != pos)
            proof += b''.join(sp.path(li))
            ii = li
    return proof, idxs


# ---------------------------------------------------------------- shapes (from model.py) and vector files

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, '..', '..', '..', 'smartcontracts', 'evm', 'test', 'vectors', 'pqzh')


def words(xs):
    return '0x' + b''.join(int(x).to_bytes(32, 'big') for x in xs).hex()


def components(rng):
    v = {}
    a, b = [rng.randrange(1, P) for _ in range(8)], [rng.randrange(P) for _ in range(8)]
    v['fp'] = words(x for i in range(8) for x in (a[i], b[i], a[i] * b[i] % P, (a[i] + b[i]) % P,
                                                     (a[i] - b[i]) % P, inv(a[i])))
    for E in (2, 3):
        rows = []
        for _ in range(8):
            x, y = tuple(rng.randrange(P) for _ in range(E)), tuple(rng.randrange(P) for _ in range(E))
            rows += [pack(x), pack(y), pack(emul(x, y)), pack(einv(x))]
        v[f'fp{E}'] = words(rows)
    # Merkle depth 10, one leaf row of 24 elements, one injected group of 6 elements at height 2^7
    groups, idx = [(10, 24), (7, 6)], rng.randrange(1 << 10)
    rows = [{idx: [rng.randrange(P) for _ in range(24)]}, {idx >> 3: [rng.randrange(P) for _ in range(6)]}]
    sp = Sparse(rng, 10, groups, [idx], rows)
    v['merkle'] = dict(index=idx, root='0x' + sp.root.hex(), rows='0x' + b''.join(be(x) for x in rows[0][idx]).hex(),
                       inj='0x' + b''.join(be(x) for x in rows[1][idx >> 3]).hex(),
                       path='0x' + b''.join(sp.path(idx)).hex())
    for E in (2, 3):
        for a in (1, 3, 4):
            lh = 12
            index = rng.randrange(1 << lh)
            beta = tuple(rng.randrange(P) for _ in range(E))
            ev = [tuple(rng.randrange(P) for _ in range(E)) for _ in range(1 << a)]
            v[f'fold{E}_{1 << a}'] = words([index, lh, a, pack(beta), pack(fold_row(index, lh, a, beta, ev))]
                                           + [pack(x) for x in ev])
        n = 64
        keys, mults = [rng.randrange(1 << 13) for _ in range(n)], [rng.randrange(1, 9) for _ in range(n)]
        beta = tuple(rng.randrange(P) for _ in range(E))
        v[f'logup{E}'] = words([n, pack(beta), pack(logup_sum(keys, mults, beta))] + keys + mults)
        coeffs = [rng.randrange((1 << 42) - 215) for _ in range(100)]
        gam = tuple(rng.randrange(P) for _ in range(E))
        v[f'horner{E}'] = dict(gamma=pack(gam), result=pack(horner(coeffs, gam)),
                               coeffs='0x' + b''.join(c.to_bytes(8, 'big') for c in coeffs).hex())
    # SHAKE256 / Keccak-256 of a 1,000-byte message (the R_TX statement transcript is timed by length in forge)
    m = bytes(rng.randrange(256) for _ in range(1000))
    v['shake'] = dict(msg='0x' + m.hex(), shake256='0x' + keccak(m, pad=0x1F, out=32).hex(),
                      keccak256='0x' + keccak(m).hex())
    for k in v:
        if isinstance(v[k], dict):
            v[k] = {kk: (hex(vv) if isinstance(vv, int) else vv) for kk, vv in v[k].items()}
    return v


def e2e_file(name, sh, stmt):
    proof, _ = skeleton_proof(sh, stmt)
    shw = shape_words(sh)
    blob = len(shw).to_bytes(4, 'big') + len(stmt).to_bytes(4, 'big') + len(proof).to_bytes(4, 'big') + shw + stmt + proof
    with open(os.path.join(OUT, f'{name}.bin'), 'wb') as f:
        f.write(blob)
    return len(proof)


def selftest():
    assert keccak(b'').hex() == 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
    assert keccak(b'', pad=0x1F).hex() == '46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f'
    assert keccak(b'a' * 200).hex() == keccak(b'a' * 200)[:32].hex()
    assert g(1) == P - 1 and g(8) == 0xBF79143CE60CA966 and pow(G32, 1 << 32, P) == 1
    rng = random.Random(7)
    for E in (2, 3):
        x = tuple(rng.randrange(P) for _ in range(E))
        assert emul(x, einv(x)) == e(1, E)
        assert epow(x, P ** E - 1) == e(1, E), 'irreducible modulus: x^(p^E - 1) = 1'
        beta = tuple(rng.randrange(P) for _ in range(E))
        ev = [tuple(rng.randrange(P) for _ in range(E)) for _ in range(2)]
        s = pow(g(6), rev(5, 5), P)
        assert fold_row(5, 5, 1, beta, ev) == lagrange_at([s, P - s], ev, beta), 'arity-2 closed form'
        # a degree < k polynomial folds to its value at beta (fold = interpolation)
        for a in (3, 4):
            k = 1 << a
            cf = [tuple(rng.randrange(P) for _ in range(E)) for _ in range(k)]
            sp = pow(g(9 + a), rev(3, 9), P)
            xs = [sp * pow(g(a), rev(j, a), P) % P for j in range(k)]
            ys = [sum_ext(cf, e(xx, E)) for xx in xs]
            assert fold_row(3, 9, a, beta, ys) == sum_ext(cf, beta)
    assert pruned_siblings(3, [1, 2, 5]) == 4, 'pruning.rs doc example'
    return True


def sum_ext(cf, X):                          # sum_t cf[t] X^t
    acc = e(0, len(X))
    for c in reversed(cf):
        acc = eadd(emul(acc, X), c)
    return acc


def main():
    selftest()
    if '--selftest' in sys.argv:
        print('selftest ok')
        return
    import model
    os.makedirs(OUT, exist_ok=True)
    rng = random.Random(2026_10_13)
    with open(os.path.join(OUT, 'components.json'), 'w') as f:
        json.dump(components(rng), f, indent=1)
        f.write('\n')
    stmt_tx = bytes(640) + b''.join(rng.randrange((1 << 42) - 215).to_bytes(8, 'big') for _ in range(10_304))
    for name, rel, cfg in model.E2E:
        sh = model.skeleton_shape(rel, cfg)
        n = e2e_file(name, sh, stmt_tx if rel == 'R_TX' else stmt_tx[:640 + 8 * model.REL[rel]['stmt']])
        print(name, rel, cfg, 'proof bytes', n)


if __name__ == '__main__':
    main()
