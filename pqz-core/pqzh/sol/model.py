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
              oodMuls=ood_muls(airs or REL[rel]['airs']), perMacs=64 * 64, stmtOff=stmt_off(rel))
    return sh


def stmt_off(rel):                           # byte offset of the first be8 coefficient in the statement
    return REL[rel]['stmt_bytes'] - 8 * REL[rel]['stmt']


def ood_muls(airs):
    """Out-of-domain constraint evaluation, extension multiplications [estimate from the prototype's AIRs]: Poly 64
    rotation constraints (x2: selector, alpha) + the 64-term NTT form + norms, slack, index (≈ 30) + 6 LogUp
    interactions x 6; Mv 4 per accumulator + 10 + 2 x 6; Range 5 + 6; Digit ≈ 25 constraints x 2 + 25 interactions x 6;
    plus selectors and quotient recomposition ≈ 20 per AIR. The period-64 NTT weights (64 x 64 base x ext MACs)
    are the `perMacs` term."""
    n = 0
    for name, _, w, aux, q, _ in airs:
        n += 20 + 2 * q
        if name == 'Poly':
            n += 64 * 2 + 64 + 30 + 6 * 6
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
