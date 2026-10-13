#!/usr/bin/env python3
"""PQZH Solidity verifier study (docs/research/pqzh-solidity-verifier.md): proof shapes and the gas / calldata grid.

  python3 pqz-core/pqzh/sol/model.py --selftest   # calibration against the prototype's measured proof sizes
  python3 pqz-core/pqzh/sol/model.py > pqz-core/pqzh/sol/grid.txt

Shapes. The prototype (branch pqzh-proto, crate pqz-core/pqzh, Plonky3 0.8.0) has four AIRs: Poly, Mv, Range,
Digit (R_TX only). Its proof format was measured with `pqzh_bench --sizes-only` (PROTO below). An EVM verifier
cannot evaluate the prototype's full-height periodic columns (NTT(A), selectors: O(height) Lagrange work per column
at the out-of-domain point), so the EVM layout here moves them into a preprocessed tree whose root is a verifier
constant, puts the statement polynomials into the Poly AIR (their NTT values reach Mv over the existing bus) and
binds their coefficients to the statement by a Horner fingerprint (one extension MAC per coefficient in the
verifier). That layout is a design estimate, not built: widths below are the prototype's plus the columns it adds.

Gas. Unit costs are the forge measurements of PqzhTest.t.sol (UNIT, [measured]); the end-to-end skeleton
(PqzhSkeleton) was measured on the shapes of E2E and the model is checked against it (selftest).
"""
import math, random, sys

LAMBDA, POW, LOG_FINAL = 128, 16, 3          # target bits, grinding bits, log2 final polynomial length
CAP = 16_777_216                             # EIP-7825 transaction gas cap

# AIRs per relation: (name, log2 trace height, main width, aux ext columns, quotient ext chunks, preprocessed width)
# prototype (measured widths, pqzh-proto e1fa752): R_REG Poly 13/72, Mv 14/12, Range 13/2; R_TX Poly 14/72,
# Mv 15/12, Range 13/2, Digit 4/30; aux and quotient split per AIR so the totals match the measured rows.
PROTO = {
    'R_REG': [('Poly', 13, 72, 2, 5, 0), ('Mv', 14, 12, 1, 2, 0), ('Range', 13, 2, 1, 2, 0)],
    'R_TX': [('Poly', 14, 72, 2, 5, 0), ('Mv', 15, 12, 1, 2, 0), ('Range', 13, 2, 1, 2, 0), ('Digit', 4, 30, 2, 15, 0)],
}
# measured with pqzh_bench --sizes-only (2026-10-13): (log blowup, queries, max log arity) -> proof bytes
PROTO_MEASURED = {('R_REG', 4, 28, 3): 110_388, ('R_TX', 4, 28, 3): 143_965,
                  ('R_REG', 3, 38, 3): 130_700, ('R_TX', 3, 38, 3): 178_000}

# EVM layout [estimate]: + statement polynomials in Poly (+1 aux column: the Horner accumulator), the statement
# products' NTT coefficients from the bus in Mv (+1 main, +1 aux), Mv's and Poly's full-height fixed columns
# preprocessed (Mv 12: F1, MM, ID, MN x 9; Poly 6: NTT, RC, COEF, GEND, INCN, BSQ). Period-64 and period-16 columns
# (Poly's NTT weights, Mv's block end, Digit's statement values and fee nibbles) stay periodic.
REL = {
    'R_REG': dict(airs=[('Poly', 13, 72, 3, 5, 6), ('Mv', 14, 12, 1, 2, 12), ('Range', 13, 2, 1, 2, 0)],
                  stmt=2_048, stmt_bytes=96 + 16_384, calldata_tokens=67_000, exec_other=3_450_000, op=3),
    'R_TX': dict(airs=[('Poly', 15, 72, 3, 5, 6), ('Mv', 15, 13, 2, 3, 12), ('Range', 13, 2, 1, 2, 0),
                       ('Digit', 4, 30, 2, 15, 0)],
                 stmt=10_304, stmt_bytes=83_072, calldata_tokens=119_000, exec_other=310_000, op=1),
    'R_BURN': dict(airs=[('Poly', 15, 72, 3, 5, 6), ('Mv', 15, 13, 2, 3, 12), ('Range', 13, 2, 1, 2, 0),
                         ('Digit', 4, 18, 2, 10, 0)],
                   stmt=6_176, stmt_bytes=50_048, calldata_tokens=98_000, exec_other=250_000, op=2),
    'R_DS': dict(airs=[('Poly', 14, 72, 3, 5, 6), ('Mv', 14, 13, 2, 3, 12), ('Range', 13, 2, 1, 2, 0),
                       ('Digit', 4, 9, 1, 5, 0)],
                 stmt=4_112, stmt_bytes=233 + 32_896, calldata_tokens=54_000, exec_other=50_000, op=4),
    'R_DR': dict(airs=[('Poly', 14, 72, 3, 5, 6), ('Mv', 14, 13, 2, 3, 12), ('Range', 13, 2, 1, 2, 0),
                       ('Digit', 4, 8, 1, 5, 0)],
                 stmt=4_112, stmt_bytes=233 + 32_896, calldata_tokens=54_000, exec_other=50_000, op=5),
}
# calldata_tokens: non-proof calldata (EIP-7623 tokens) and exec_other: execution besides the verifier, from
# pq-zether.md §9.3 [estimate there]: transfer ≈ 119 k tokens and ≈ 0.31 M (statement build, storage, events,
# auth); burn / refresh ≈ 258 k tokens with a 40 KB proof; register: the 16 KB pk (2,048 be8 coefficients at
# ≈ 25.2 tokens) + the ≈ 3.4 KB ML-DSA authPop, and the SSTORE2 of the pk ≈ 3.3 M + log + auth; disclosure:
# the bundle (u, v ≈ 16.5 KB) + ABI, a view (pk read from the registry).


def queries(lb, regime):                     # conjectured: lb bits per query; Johnson (provable): lb / 2
    return math.ceil((LAMBDA - POW) / (lb if regime == 'conj' else lb / 2))


def ext_degree(regime):                      # 128 provable bits need a field above Goldilocks^2 (pqzh-design §5.1)
    return 2 if regime == 'conj' else 3


def fri_schedule(log_h0, inputs, log_final, max_log_arity):
    """p3-fri compute_log_arity_for_round: a round never folds past the next input height or the final height."""
    sched, h, ins = [], log_h0, sorted({x for x in inputs if x < log_h0}, reverse=True)
    while h > log_final:
        nxt = next((x for x in ins if log_final < x < h), None)
        a = min(h - log_final, (h - nxt) if nxt else h, max_log_arity)
        sched.append(a)
        h -= a
    return sched


def trees(airs, lb, E):
    """Committed trees as (name, fixed root, points, [(log LDE height, width in base elements)] tallest first);
    AIRs of equal height share a group (one leaf hash)."""
    def groups(sel):
        g = {}
        for a in airs:
            if sel(a):
                g[a[1] + lb] = g.get(a[1] + lb, 0) + sel(a)
        return sorted(g.items(), reverse=True)
    out = [('main', False, 2, groups(lambda a: a[2])), ('aux', False, 2, groups(lambda a: a[3] * E)),
           ('quot', False, 1, groups(lambda a: a[4] * E))]
    pre = groups(lambda a: a[5])
    if pre:
        out.append(('pre', True, 2, pre))
    return out


def skeleton_shape(rel, cfg, airs=None):
    """The shape PqzhSkeleton.verify reads (ref.shape_words encodes it)."""
    lb, la, regime = cfg
    E = ext_degree(regime)
    tr = trees(airs or REL[rel]['airs'], lb, E)
    h0 = max(g[0][0] for _, _, _, g in tr)
    inputs = {lh for _, _, _, g in tr for lh, _ in g}
    sh = dict(E=E, Q=queries(lb, regime), pow=POW, logH0=h0, logBlowup=lb, op=REL[rel]['op'],
              trees=[dict(fixed=f, npts=n, groups=g) for _, f, n, g in tr],
              arity=fri_schedule(h0, inputs, LOG_FINAL + lb, la), finalLen=1 << LOG_FINAL,
              oodMuls=ood_muls(airs or REL[rel]['airs']), perBf=64 * 6 // 2, stmtOff=stmt_off(rel))
    return sh


def stmt_off(rel):                           # byte offset of the first be8 coefficient in the statement
    return REL[rel]['stmt_bytes'] - 8 * REL[rel]['stmt']


def ood_muls(airs):
    """Out-of-domain constraint evaluation, extension multiplications [estimate from the prototype's AIRs]: Poly 64
    rotation constraints (x2: selector, alpha) + the 64-term NTT form + norms, slack, index (≈ 30) + 6 LogUp
    interactions x 6; Mv 4 per accumulator + 10 + 2 x 6; Range 5 + 6; Digit ≈ 25 constraints x 2 + 25 interactions x 6;
    plus selectors and quotient recomposition ≈ 20 per AIR; the 64 Lagrange weights of the period-64 columns (one
    batched inversion, 3 per weight). The 64 NTT-weight columns at the point are one 64-point transform of those
    weights (W_m(y) = sum_k L_k(y) z_k^k z_k^m): the `perBf` = 192 butterflies."""
    n = 0
    for name, _, w, aux, q, _ in airs:
        n += 20 + 2 * q
        if name == 'Poly':
            n += 64 * 2 + 64 + 30 + 6 * 6 + 64 * 3     # + the 64 Lagrange weights (batched inversion)
        elif name == 'Mv':
            n += 4 * (w - 4) + 10 + 2 * 6
        elif name == 'Range':
            n += 5 + 6
        else:
            n += 2 * w + 6 * w
    return n


E2E = [('e2e_tx_b16_a8_conj', 'R_TX', (4, 3, 'conj')),
       ('e2e_tx_b16_a8_johnson', 'R_TX', (4, 3, 'johnson')),
       ('e2e_tx_b8_a2_conj', 'R_TX', (3, 1, 'conj'))]


def pruned(depth, idxs):                     # digests a pruned multiproof sends (p3-merkle-tree pruning.rs)
    n, s = 0, set(idxs)
    for _ in range(depth):
        n += sum(1 for i in s if i ^ 1 not in s)
        s = {i >> 1 for i in s}
    return n


def nodes(depth, idxs):                      # compressions a pruned verifier computes
    n, s = 0, set(idxs)
    for _ in range(depth):
        s = {i >> 1 for i in s}
        n += len(s)
    return n


def counts(sh, seeds=8, digest=32):
    """Proof bytes (Plonky3 layout: fixed 8-byte elements, pruned Merkle multiproofs) and the hashing counts of a
    pruned and an unpruned verifier, averaged over `seeds` random query sets."""
    E, Q, H0 = sh['E'], sh['Q'], sh['logH0']
    tr = sh['trees']
    n_ood = sum(w * t['npts'] for t in tr for _, w in t['groups'])
    rows = sum(w for t in tr for _, w in t['groups'])
    fixed = digest * (sum(1 for t in tr if not t['fixed']) + len(sh['arity'])) + 8 * E * (n_ood + sh['finalLen']) + 8
    sib_vals = sum((1 << a) - 1 for a in sh['arity']) * E * 8
    tot = dict(pruned_dig=0, pruned_cmp=0)
    for sd in range(seeds):
        rng = random.Random(sd)
        idx = [rng.randrange(1 << H0) for _ in range(Q)]
        for t in tr:
            d = t['groups'][0][0]
            ii = [i >> (H0 - d) for i in idx]
            tot['pruned_dig'] += pruned(d, ii)
            tot['pruned_cmp'] += nodes(d, ii)
        h = H0
        for a in sh['arity']:
            ii = [i >> (H0 - h + a) for i in idx]
            tot['pruned_dig'] += pruned(h - a, ii)
            tot['pruned_cmp'] += nodes(h - a, ii)
            h -= a
    dig = tot['pruned_dig'] / seeds
    unpruned_dig = Q * (sum(t['groups'][0][0] for t in tr) + sum(H0 - sum(sh['arity'][:r + 1]) for r in range(len(sh['arity']))))
    return dict(n_ood=n_ood, rows=rows, proof=fixed + Q * (8 * rows + sib_vals) + digest * dig,
                proof_unpruned=fixed + Q * (8 * rows + sib_vals) + digest * unpruned_dig,
                cmp_pruned=tot['pruned_cmp'] / seeds, cmp_unpruned=unpruned_dig)


def proto_shape(rel, lb, q, la):
    sh = skeleton_shape(rel, (lb, la, 'conj'), airs=PROTO[rel])
    sh['Q'] = q
    return sh


def selftest():
    for (rel, lb, q, la), meas in PROTO_MEASURED.items():
        # the prototype's digests are [u64; 4] (Keccak-f sponge) in postcard varints: ≈ 38 bytes on average
        c = counts(proto_shape(rel, lb, q, la), digest=38)
        err = c['proof'] / meas - 1
        print(f'calibration {rel} blowup {1 << lb} queries {q}: model {c["proof"]:,.0f} B, measured {meas:,} B, '
              f'{100 * err:+.1f} %')
        assert abs(err) < 0.05, 'proof-size model within 5 % of the prototype'
    assert pruned(3, [1, 2, 5]) == 4 and nodes(3, [1, 2, 5]) == 3 + 2 + 1


# ---------------------------------------------------------------- gas

# [measured] PqzhTest.t.sol (solc 0.8.37, osaka, optimizer 200 runs), 2026-10-13; e2e-derived units from the
# `profile` stages of the three skeleton runs (E2E); E = 5 extrapolated from E = 2, 3 along the measured cost of one
# extension multiplication (fp5 mul measured in memory form).
UNIT = {
    'emul': {2: 292, 3: 443, 5: 788},        # one extension multiplication (E = 5: unrolled, memory buffers)
    'einv': {2: 5_056, 3: 5_391, 5: 3 * 788 + 4_668 + 1_000},  # E = 5: Itoh-Tsujii [estimate]
    'horner': {2: 183, 3: 289},               # per statement coefficient (incl. the < q check)
    'row': {2: 160, 3: 191},                  # per opened base value: sum_c ad^c v_c + canonical check
    'fold': {2: {1: 1_496, 3: 12_572, 4: 28_762}, 3: {1: 1_897, 3: 13_629, 4: 31_027}},
    'path': 176,                              # one Merkle level, keccak opcode (plain path)
    'leaf_b': 0.44,                           # per hashed byte of an opened row
    'seed_b': 0.586,                          # keccak256 opcode over the statement, per byte (incl. memory)
    'shake_b': 43_316_724 / 83_101,           # SHAKE256 in Solidity (src/ua/Shake.sol), per byte
}
FIT = {}                                     # filled from the e2e profiles below (fit())

# [measured] PqzhSkeleton.profile on the E2E shapes (forge, 2026-10-13): gas by stage inside verify
PROFILE = {
    'e2e_tx_b16_a8_conj': dict(seed=48_678, commit=23_569, horner=1_855_206, deep_pre=552_238, standin=979_953,
                               rows=1_725_080, merkle=538_030, deep_inv=824_572, fri_open=1_063_076,
                               fri_fold=1_316_060, rest=866_439, total=9_811_567, call=10_770_478),
    'e2e_tx_b16_a8_johnson': dict(seed=48_678, commit=29_354, horner=2_937_137, deep_pre=784_189, standin=1_153_308,
                                  rows=4_298_280, merkle=1_080_440, deep_inv=1_871_072, fri_open=2_378_600,
                                  fri_fold=2_837_457, rest=1_766_617, total=19_203_800, call=22_192_598),
    'e2e_tx_b8_a2_conj': dict(seed=48_739, commit=29_628, horner=1_855_206, deep_pre=552_401, standin=979_953,
                              rows=2_341_180, merkle=699_706, deep_inv=1_108_346, fri_open=1_990_668,
                              fri_fold=1_277_391, rest=1_325_763, total=12_229_414, call=14_548_151),
}


def ext_unit(name, E):
    """E-dependent unit; E = 5 by linear extrapolation in the extension-multiplication cost."""
    u = UNIT[name]
    if E in u and u[E] is not None:
        return u[E]
    m = UNIT['emul']
    return u[3] + (u[3] - u[2]) * (m[5] - m[3]) / (m[3] - m[2])


def fold_unit(E, a):
    f = UNIT['fold']
    if E in f:
        d = f[E]
    else:
        m = UNIT['emul']
        d = {k: f[3][k] + (f[3][k] - f[2][k]) * (m[5] - m[3]) / (m[3] - m[2]) for k in f[3]}
    if a in d:
        return d[a]
    return d[1] + (d[3] - d[1]) * (a - 1) / 2   # arity 4: between 2 and 8


def shape_stats(sh):
    E, Q = sh['E'], sh['Q']
    tr = sh['trees']
    vals = sum(w for t in tr for _, w in t['groups'])
    terms = sum(t['npts'] * len(t['groups']) for t in tr)
    levels = sum(t['groups'][0][0] for t in tr)
    inj = sum(len(t['groups']) - 1 for t in tr)
    pairs = len({(lh, p) for t in tr for lh, _ in t['groups'] for p in range(t['npts'])})
    h, fri_levels = sh['logH0'], 0
    for a in sh['arity']:
        fri_levels += h - a
        h -= a
    return dict(vals=vals, terms=terms, levels=levels, inj=inj, pairs=pairs, fri_levels=fri_levels,
                n_ood=sum(w * t['npts'] for t in tr for _, w in t['groups']))


def skeleton_gas(sh, stmt_n, stmt_bytes):
    """Verify gas of PqzhSkeleton's code on shape `sh` (unpruned paths), by stage, from the measured units."""
    E, Q, R = sh['E'], sh['Q'], len(sh['arity'])
    s = shape_stats(sh)
    f = lambda k: ext_fit(k, E)
    g = {}
    g['seed'] = UNIT['seed_b'] * stmt_bytes
    g['commit'] = f('commit') + FIT['commit_r'] * R
    g['horner'] = ext_unit('horner', E) * stmt_n
    g['deep_pre'] = f('pre_ood') * s['n_ood']
    g['standin'] = f('standin') * (sh['oodMuls'] + 1.3 * sh['perBf'])
    g['rows'] = Q * (ext_unit('row', E) * s['vals'] + f('term') * s['terms'])
    g['merkle'] = Q * (f('walk_lvl') * s['levels'] + UNIT['leaf_b'] * 8 * s['vals'] + FIT['inj'] * s['inj'])
    g['deep_inv'] = Q * (ext_unit('einv', E) + f('pair') * s['pairs'])
    g['fri_open'] = Q * sum(f('fri_round') + f('fri_k') * (1 << a) * E for a in sh['arity']) \
        + Q * UNIT['path'] * s['fri_levels']
    g['fri_fold'] = Q * (f('fold_phi') * sum(fold_unit(E, a) for a in sh['arity']) + f('pw_bit') * s['fri_levels'])
    g['rest'] = Q * (f('q_rest') + FIT['q_rest_r'] * R)
    return g


# Floor [estimate]: a hand-scheduled verifier (Yul/Huff, values kept on the stack, no bounds checks), counted from
# the opcodes each step needs: a Merkle level ≈ 100 gas (two MSTOREs, CALLDATALOAD, KECCAK256 of 64 bytes, index
# logic), pruned multiproofs (fewer compressions), one inversion per proof (all queries batched), an extension
# multiplication ≈ 60 / 100 / 250 gas (E = 2 / 3 / 5: E^2 MUL, the reductions MOD), a base x ext MAC ≈ 15 + 8 E,
# a butterfly ≈ 12 E + 20, E statement coefficients (< 2^42) packed per extension element of the Horner fingerprint.
FLOOR_MUL = {2: 60, 3: 100, 5: 250}


def floor_gas(sh, stmt_n, stmt_bytes, cnt):
    E, Q = sh['E'], sh['Q']
    s = shape_stats(sh)
    m, mac, bf = FLOOR_MUL[E], 15 + 8 * E, 12 * E + 20
    g = {}
    g['seed'] = UNIT['seed_b'] * stmt_bytes
    g['commit'] = 20_000
    g['horner'] = stmt_n / E * (m + 20)
    g['deep_pre'] = 2 * m * s['n_ood']
    g['standin'] = m * sh['oodMuls'] + bf * sh['perBf']
    g['rows'] = Q * (mac * s['vals'] + 3 * m * s['terms'])
    g['merkle'] = 100 * cnt['cmp_pruned'] + Q * (UNIT['leaf_b'] * 8 * s['vals'] + 150 * (s['inj'] + len(sh['trees'])))
    g['deep_inv'] = Q * 3 * m * s['pairs'] + 5_000
    g['fri_open'] = Q * sum(150 + 2 * (1 << a) * E for a in sh['arity'])
    g['fri_fold'] = Q * sum((1 << a) // 2 * a * bf + (1 << a) * m for a in sh['arity'])
    g['rest'] = Q * (1_500 + 400 * len(sh['arity']))
    return g


def tx_gas(proof_bytes, rel, verify):
    """Transaction gas: intrinsic + calldata (EIP-2028 standard, EIP-7623 floor) + verify + the op's other
    execution. Proof bytes are field elements and digests: ≈ 3.99 tokens per byte (1/256 zero bytes)."""
    r = REL[rel]
    tokens = r['calldata_tokens'] + 3.99 * proof_bytes
    exe = verify + r['exec_other']
    std = 21_000 + 4 * tokens + exe
    flo = 21_000 + max(4 * tokens + exe, 10 * tokens)
    return dict(tokens=tokens, std=std, eip7623=flo, calldata_std=4 * tokens, calldata_floor=10 * tokens)


def ext_fit(name, E):
    d = FIT[name]
    if E in d:
        return d[E]
    m = UNIT['emul']
    return d[3] + (d[3] - d[2]) * (m[E] - m[3]) / (m[3] - m[2])


def fit():
    """Constants of skeleton_gas from the profiles: A (Fp2, blowup 16 / arity 8) and C (Fp2, blowup 8 / arity 2) for
    the shape terms, A and B (Fp3) for the extension-dependent ones; E = 5 extrapolates linearly in the cost of one
    extension multiplication (ext_fit). Every run is reproduced exactly by construction; the model's check is
    the arity / height structure across A and C and the E = 5 step, which is an extrapolation [estimate]."""
    sh = {n: skeleton_shape(r, c) for n, r, c in E2E}
    names = {2: 'e2e_tx_b16_a8_conj', 3: 'e2e_tx_b16_a8_johnson'}
    C, pC = sh['e2e_tx_b8_a2_conj'], PROFILE['e2e_tx_b8_a2_conj']
    sC, QC, RC = shape_stats(C), C['Q'], len(C['arity'])
    for k in ('commit', 'pre_ood', 'standin', 'term', 'walk_lvl', 'pair', 'fri_round', 'fri_k', 'fold_phi',
              'pw_bit', 'q_rest'):
        FIT[k] = {}
    FIT['inj'] = 300
    A, pA = sh[names[2]], PROFILE[names[2]]
    sA, RA = shape_stats(A), len(A['arity'])
    FIT['commit_r'] = (pC['commit'] - pA['commit']) / (RC - RA)
    FIT['q_rest_r'] = (pC['rest'] / QC - pA['rest'] / A['Q']) / (RC - RA)
    # fold stage = phi * fold_unit + pw_bit * (levels of the coset-point product); A and C (Fp2)
    fa = sum(fold_unit(2, a) for a in A['arity'])
    fc = sum(fold_unit(2, a) for a in C['arity'])
    yA, yC = pA['fri_fold'] / A['Q'], pC['fri_fold'] / QC
    pw = (yC * fa - yA * fc) / (sC['fri_levels'] * fa - sA['fri_levels'] * fc)
    phi = (yA - pw * sA['fri_levels']) / fa
    # fri_open per query = sum over rounds (fri_round + fri_k k E) + path * levels; A and C (Fp2)
    zA = pA['fri_open'] / A['Q'] - UNIT['path'] * sA['fri_levels']
    zC = pC['fri_open'] / QC - UNIT['path'] * sC['fri_levels']
    kA = sum((1 << a) for a in A['arity'])
    kC = sum((1 << a) for a in C['arity'])
    fk = (zA * RC - zC * RA) / (kA * RC - kC * RA)
    fr = (zA - fk * kA) / RA
    for E, n in names.items():
        X, p = sh[n], PROFILE[n]
        s, Q, R = shape_stats(X), X['Q'], len(X['arity'])
        FIT['commit'][E] = p['commit'] - FIT['commit_r'] * R
        FIT['pre_ood'][E] = p['deep_pre'] / s['n_ood']
        FIT['standin'][E] = p['standin'] / (X['oodMuls'] + 1.3 * X['perBf'])
        FIT['term'][E] = (p['rows'] / Q - ext_unit('row', E) * s['vals']) / s['terms']
        FIT['walk_lvl'][E] = (p['merkle'] / Q - UNIT['leaf_b'] * 8 * s['vals'] - FIT['inj'] * s['inj']) / s['levels']
        FIT['pair'][E] = (p['deep_inv'] / Q - ext_unit('einv', E)) / s['pairs']
        FIT['q_rest'][E] = p['rest'] / Q - FIT['q_rest_r'] * R
        FIT['pw_bit'][E] = pw
        FIT['fold_phi'][E] = (p['fri_fold'] / Q - pw * s['fri_levels']) / sum(fold_unit(E, a) for a in X['arity'])
        FIT['fri_round'][E] = fr
        FIT['fri_k'][E] = (p['fri_open'] / Q - UNIT['path'] * s['fri_levels'] - fr * R) / (kA * E) if E == 3 else fk / 2


fit()


# ---------------------------------------------------------------- grid

# Goldilocks^5, 128 bits, from the prototype's p3-security sweep (docs/research/pqzh-prototype.md §7, FRI arity 8,
# 24 grinding bits): queries by log blowup
Q_EXT5 = {'proven': {2: 105, 3: 70, 4: 53, 5: 42}, 'conj': {2: 53, 3: 35, 4: 27, 5: 21}}
ZK_MEASURED = {'R_TX': (141_079, 253_294), 'R_REG': (110_388, 195_134)}   # prototype plain / ZK bytes, Gl^2 b16 q28


def config_shape(rel, lb, la, field, regime, zk=False):
    """field 'gl2' / 'gl3': query count by the ethSTARK formula (the plan's grid; Gl^2 is capped at ≈ 100 bits by
    p3-security, so 'gl2' is a size / gas reference, not 128 bits); 'gl5': the p3-security counts for 128 bits.
    zk: HidingFriPcs shape [estimate, calibrated to the prototype's ZK bytes within ≈ 9 %]: committed domain one bit
    longer, quotient 8 chunks instead of 2, 8 random / salt columns per committed matrix, 4 salt elements per FRI
    leaf, a randomisation-polynomial tree; the Digit table 128 rows."""
    E = {'gl2': 2, 'gl3': 3, 'gl5': 5}[field]
    airs = REL[rel]['airs']
    if zk:
        airs = [(n, (h + 1) if n != 'Digit' else 7, w, a, 4 * q, pre) for n, h, w, a, q, pre in airs]
    tr = trees(airs, lb, E)
    if zk:
        tr = [(nm, f, n, [(lh, w + (0 if f else 8 * sum(1 for x in airs if x[1] + lb == lh))) for lh, w in g])
              for nm, f, n, g in tr]
        tr.append(('rand', False, 1, [(max(x[1] for x in airs) + lb, 8)]))
    h0 = max(g[0][0] for _, _, _, g in tr)
    q = queries(lb, 'conj' if regime == 'conj' else 'johnson') if field != 'gl5' else Q_EXT5[regime][lb]
    return dict(E=E, Q=q, pow=24 if field == 'gl5' else POW, logH0=h0, logBlowup=lb, op=REL[rel]['op'],
                trees=[dict(fixed=f, npts=n, groups=g) for _, f, n, g in tr],
                arity=fri_schedule(h0, {lh for *_, g in tr for lh, _ in g}, LOG_FINAL + lb, la),
                finalLen=1 << LOG_FINAL, oodMuls=ood_muls(airs), perBf=64 * 6 // 2, stmtOff=stmt_off(rel),
                fri_salt=4 if zk else 0)


def evaluate(rel, lb, la, field, regime, zk=False):
    sh = config_shape(rel, lb, la, field, regime, zk)
    c = counts(sh)
    proof = c['proof'] + sh['Q'] * len(sh['arity']) * 8 * sh['fri_salt']
    r = REL[rel]
    sk = sum(skeleton_gas(sh, r['stmt'], r['stmt_bytes']).values())
    fl = sum(floor_gas(sh, r['stmt'], r['stmt_bytes'], c).values())
    return dict(rel=rel, lb=lb, la=la, field=field, regime=regime, zk=zk, Q=sh['Q'], proof=proof,
                verify=sk, floor=fl, tx=tx_gas(proof, rel, sk), tx_floor=tx_gas(proof, rel, fl), arity=sh['arity'])


def row(e):
    t, tf = e['tx']['eip7623'], e['tx_floor']['eip7623']
    ok = lambda x: 'yes' if x <= CAP else 'no'
    return (f"| {e['field']}{' ZK' if e['zk'] else ''} | {1 << e['lb']} | {1 << e['la']} ({'/'.join(str(1 << a) for a in e['arity'])}) | "
            f"{e['regime']} | {e['Q']} | {e['proof'] / 1000:.0f} | {e['verify'] / 1e6:.1f} | {e['floor'] / 1e6:.1f} | "
            f"{e['tx']['calldata_std'] / 1e6:.2f} / {e['tx']['calldata_floor'] / 1e6:.2f} | {t / 1e6:.1f} ({ok(t)}) | "
            f"{tf / 1e6:.1f} ({ok(tf)}) |")


HDR = ('| Field | Blowup | Max FRI arity (rounds) | Regime | Queries | Proof KB | Verify M (skeleton code) | '
       'Verify M (floor) | Calldata M (EIP-2028 / EIP-7623 floor) | Tx M, skeleton (≤ cap?) | Tx M, floor (≤ cap?) |\n'
       '|---|---|---|---|---|---|---|---|---|---|---|')


def grid():
    out = []
    for field, regimes, lbs in (('gl2', ('conj',), (2, 3, 4)), ('gl3', ('johnson',), (2, 3, 4)),
                                ('gl5', ('conj', 'proven'), (3, 4, 5))):
        for regime in regimes:
            for lb in lbs:
                for la in (1, 3, 4):
                    out.append(evaluate('R_TX', lb, la, field, regime))
    for regime in ('conj', 'proven'):
        for lb in (4, 5):
            out.append(evaluate('R_TX', lb, 3, 'gl5', regime, zk=True))
    return out


def best(rel, floor=False):
    """Cheapest Goldilocks^5 configuration per regime and ZK setting (total transaction gas, EIP-7623)."""
    res = {}
    for regime in ('conj', 'proven'):
        for zk in (False, True):
            cands = [evaluate(rel, lb, la, 'gl5', regime, zk) for lb in (3, 4, 5) for la in (1, 2, 3, 4)]
            key = (lambda e: e['tx_floor']['eip7623']) if floor else (lambda e: e['tx']['eip7623'])
            res[(regime, zk)] = min(cands, key=key)
    return res


def main():
    if '--selftest' in sys.argv:
        selftest()
        return
    print('# PQZH Solidity verifier: gas grid (model.py output; units [measured] in forge, totals [estimate])\n')
    print('Skeleton code = the gas of test/pqzh/Pqzh.sol PqzhSkeleton on the shape (unpruned paths), from the units')
    print('fitted to its three measured runs; floor = a hand-scheduled verifier counted by opcodes (model.py).')
    print('Tx = 21,000 + max(4 tokens + execution, 10 tokens) (EIP-7623), execution = verify + the op\'s other')
    print(f'execution (pq-zether.md §9.3); cap {CAP:,} (EIP-7825). Calldata incl. the op\'s non-proof bytes.\n')
    print('## R_TX, every configuration\n')
    print(HDR)
    for e in grid():
        print(row(e))
    print('\n## Five relations, cheapest Goldilocks^5 configuration per regime (by skeleton-code total)\n')
    print('| Relation | Regime | ZK | Blowup / arity / queries | Proof KB | Verify M skeleton / floor | '
          'Calldata M (EIP-7623 floor) | Tx M skeleton / floor | ≤ cap (skeleton / floor) |')
    print('|---|---|---|---|---|---|---|---|---|')
    for rel in REL:
        for (regime, zk), e in best(rel).items():
            fe = best(rel, floor=True)[(regime, zk)]
            t, tf = e['tx']['eip7623'], fe['tx_floor']['eip7623']
            print(f"| {rel} | {regime} | {'yes' if zk else 'no'} | {1 << e['lb']} / {1 << e['la']} / {e['Q']} | "
                  f"{e['proof'] / 1000:.0f} | {e['verify'] / 1e6:.1f} / {fe['floor'] / 1e6:.1f} | "
                  f"{e['tx']['calldata_floor'] / 1e6:.2f} | {t / 1e6:.1f} / {tf / 1e6:.1f} | "
                  f"{'yes' if t <= CAP else 'no'} / {'yes' if tf <= CAP else 'no'} |")
    sh = config_shape('R_TX', 4, 3, 'gl2', 'conj')
    print('\n## Transcript seed over the R_TX statement (83,072 B)\n')
    print(f"- SHAKE256 in Solidity (src/ua/Shake.sol): {UNIT['shake_b'] * 83_101 / 1e6:.1f} M [measured]")
    print(f"- keccak256 opcode: {UNIT['seed_b'] * 83_101 / 1e3:.0f} k [measured]")
    for E in (2, 3, 5):
        print(f"- Horner fingerprint (statement into the AIR, not a transcript seed), E = {E}: "
              f"{ext_unit('horner', E) * 10_304 / 1e6:.2f} M skeleton, {10_304 / E * (FLOOR_MUL[E] + 20) / 1e6:.2f} M floor")
    print('\n## Stage breakdown, R_TX (verify gas, k)\n')
    cfgs = [('gl2 b16 a8 conj (prototype default)', ('R_TX', 4, 3, 'gl2', 'conj')),
            ('gl5 b32 a8 conj', ('R_TX', 5, 3, 'gl5', 'conj')), ('gl5 b32 a8 proven', ('R_TX', 5, 3, 'gl5', 'proven'))]
    stages = list(skeleton_gas(config_shape(*cfgs[0][1]), 1, 1))
    print('| Stage | ' + ' | '.join(f'{n}: skeleton / floor' for n, _ in cfgs) + ' |')
    print('|---|' + '---|' * len(cfgs))
    tabs = []
    for _, a in cfgs:
        sh = config_shape(*a)
        r = REL[a[0]]
        tabs.append((skeleton_gas(sh, r['stmt'], r['stmt_bytes']), floor_gas(sh, r['stmt'], r['stmt_bytes'], counts(sh))))
    for st in stages + ['total']:
        cells = []
        for sk, fl in tabs:
            v = (sum(sk.values()), sum(fl.values())) if st == 'total' else (sk[st], fl[st])
            cells.append(f'{v[0] / 1e3:,.0f} / {v[1] / 1e3:,.0f}')
        print(f'| {st} | ' + ' | '.join(cells) + ' |')


if __name__ == '__main__':
    main()
