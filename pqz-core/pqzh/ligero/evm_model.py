#!/usr/bin/env python3
"""EVM gas of the PQZH-Ligero verifier (docs/research/pqzh-ligero.md §11): operation counts from the crate's layout
(ligero_params.py, cs.rs) times unit costs, for (1) this code (units measured by forge, runs/l6-forge.txt,
test/pqzh/ligero/LigeroUnits.t.sol) and (2) an opcode floor (hand-scheduled EVM, every value on the stack; an
[estimate]). Checked against the six measured verifies (runs/l6-forge.txt), then a grid over (n, k) per regime for
the smallest transaction: 21,000 + max(4 tokens + execution, 10 tokens) (EIP-7623), cap 16,777,216 (EIP-7825).
Stdlib only.

  python3 pqz-core/pqzh/ligero/evm_model.py > pqz-core/pqzh/ligero/runs/e1-evm-model.txt
"""
import math
import importlib.util
import os

_spec = importlib.util.spec_from_file_location('lp', os.path.join(os.path.dirname(__file__), 'ligero_params.py'))
lp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lp)

CAP = 16_777_216
TOKENS_PER_BYTE = 3.88           # measured on the six fixtures: 3.877-3.887 EIP-7623 tokens per proof byte
OTHER = {'R_TX': (119_000, 310_000), 'R_REG': (67_000, 3_450_000)}   # pq-zero-knowledge.md §9.3 via pqz-core/pqzh/sol/model.py
SMALL_VALS = {'R_REG': 2, 'R_TX': 135}
SMALL_SQ_OWN = {'R_REG': 0, 'R_TX': 48}      # e2 squares carry the e2 norms
SMALL_BITS = {'R_REG': 26, 'R_TX': 1403}

# this code, measured (runs/l6-forge.txt "unit" lines)
UNIT = dict(mac=180.0, poly=213.0, power=88.0, lagr=346.0, dotu=194.0, quad=380.0, emul=598.0, apass=284.39,
            ring=3923.07)
# opcode floor [estimate]: MAC = 2 MLOAD + 2 MUL + 2 ADD + 2 AND + SHR + pointer/stack ~ 50; calldata coefficient +5;
# a power or a Lagrange slot = 1-4 MULMOD + memory ~ 15 / 60; F_q^4 product ~ 270; recurrence step ~ 2 products + 60
FLOOR = dict(mac=50.0, poly=55.0, power=15.0, lagr=60.0, dotu=50.0, quad=70.0, emul=270.0, apass=50.0, ring=600.0)

# measured stages (runs/l6-forge.txt): rel, preset -> (n, k, t, distinct, proof bytes, tokens, verify gas, stages)
MEASURED = {
    ('R_REG', 'conj'): (18533, 172, 20, 20, 63008, 244280, 64902173,
                        dict(stmt_seed=178709, transcript=2568232, columns=750346, a_copy=724298, comb_ring=30927576,
                             comb_rest=836087, column_checks=28916386)),
    ('R_REG', 'johnson'): (6536, 862, 152, 150, 201588, 782577, 403387183,
                           dict(stmt_seed=178709, transcript=4769432, columns=2071096, a_copy=858617,
                                comb_ring=31062978, comb_rest=1825817, column_checks=362619995)),
    ('R_REG', 'proven'): (32756, 817, 121, 121, 187994, 730778, 323817114,
                          dict(stmt_seed=178709, transcript=3774744, columns=2092977, a_copy=868712,
                               comb_ring=31055614, comb_rest=1756338, column_checks=284089481)),
    ('R_TX', 'conj'): (18533, 344, 24, 24, 92552, 358991, 176722608,
                       dict(stmt_seed=902444, transcript=2977791, columns=911858, a_copy=867092, comb_ring=98641288,
                            comb_rest=4933401, column_checks=67488195)),
    ('R_TX', 'johnson'): (6536, 862, 152, 151, 258264, 1001184, 644926422,
                          dict(stmt_seed=902444, transcript=5517373, columns=2905849, a_copy=997517,
                               comb_ring=98696977, comb_rest=5163207, column_checks=530742516)),
    ('R_TX', 'proven'): (32756, 817, 121, 121, 231950, 900290, 530159491,
                         dict(stmt_seed=902444, transcript=4203192, columns=2713450, a_copy=998719,
                              comb_ring=98768435, comb_rest=5361270, column_checks=417211442)),
}


def layout(rel, ell):
    bits = lp.BIG[rel]
    nr = math.ceil(2048 / ell)
    nsv = math.ceil(SMALL_VALS[rel] / ell)
    nsb = math.ceil(SMALL_BITS[rel] / ell)
    m = lp.rows1(rel, ell)
    ntri = sum(nr * (1 + b) for b in bits) + nsv + nsb
    return dict(nr=nr, m=m, ntri=ntri, nnz=2048 * len(bits) + SMALL_VALS[rel] + SMALL_SQ_OWN[rel] + SMALL_BITS[rel],
                groups=len(bits))


def per_column(rel, k, ell, u):
    L = layout(rel, ell)
    d2 = 2 * k - 1
    return (L['nnz'] * u['mac'] + ell * u['mac'] + (3 * d2 - ell) * u['poly'] + d2 * u['power'] + ell * u['lagr']
            + 4 * L['m'] * u['dotu'] + L['ntri'] * u['quad'] + 8 * u['emul'])


def statement(rel, u):
    """A passes (32 x 32 x 64 terms per A use), ring recurrence steps, e-terms (one F_q^4 product + add each)"""
    a_uses, ring_blocks, e_blocks = (1, 1, 1) if rel == 'R_REG' else (2, 6, 2)
    return a_uses * 65536 * u['apass'] + ring_blocks * 2048 * u['ring'] + e_blocks * 2048 * 1.5 * u['emul']


def rest(rel, n, k, t, ell, dist, size, u, this_code):
    """seed + statement checks, transcript, columns + Merkle, A copy, comb rest; this code: fitted to the six runs
    (linear in the draws and the column bytes); floor: keccak and calldata opcodes"""
    L = layout(rel, ell)
    draws = 2 * L['m'] + 3 + L['ntri']
    cw = 32 + (L['m'] + 12) * 6
    if this_code:
        seed = 178_709 if rel == 'R_REG' else 902_444
        return seed + 860_000 + draws * 3_900 + dist * cw * 12 + 0.6e6 + (1.0e6 if rel == 'R_REG' else 5.0e6)
    stmt_words = (16_480 if rel == 'R_REG' else 83_072) / 32
    return stmt_words * 10 + 40_000 + draws * 4 * 40 + dist * (cw / 32 * 12 + 60) + size / 32 * 10 + 60_000 + 0.3e6


def verify_gas(rel, n, k, t, ell, dist, size, this_code=True):
    u = UNIT if this_code else FLOOR
    return statement(rel, u) + dist * per_column(rel, k, ell, u) + rest(rel, n, k, t, ell, dist, size, u, this_code)


def tx_gas(rel, size, verify):
    otk, oex = OTHER[rel]
    tokens = TOKENS_PER_BYTE * size + otk
    exe = verify + oex
    return 21_000 + max(4 * tokens + exe, 10 * tokens), 10 * TOKENS_PER_BYTE * size


def check():
    print('## Model against the measured verifies (runs/l6-forge.txt)\n')
    print('| relation | preset | column checks measured / model | statement (A copy + ring) measured / model '
          '| verify measured / model | error |')
    print('|---|---|---|---|---|---|')
    for (rel, pre), (n, k, t, dist, size, tok, vg, st) in MEASURED.items():
        ell = k - t - 1
        cc = dist * per_column(rel, k, ell, UNIT)
        sm = statement(rel, UNIT)
        model = verify_gas(rel, n, k, t, ell, dist, size)
        print(f"| {rel} | {pre} | {st['column_checks'] / 1e6:.1f} / {cc / 1e6:.1f} M | "
              f"{(st['comb_ring'] + st['a_copy']) / 1e6:.1f} / {sm / 1e6:.1f} M | {vg / 1e6:.1f} / {model / 1e6:.1f} M | "
              f"{(model - vg) / vg * 100:+.1f} % |")


def floor_table():
    print('\n## Opcode floor of the measured presets [estimate]\n')
    print('| relation | preset | t | proof B | verify, this code (measured) | verify, floor | of which per-column '
          '| statement | proof calldata floor (EIP-7623) | tx, floor | <= cap |')
    print('|---|---|---|---|---|---|---|---|---|---|---|')
    for (rel, pre), (n, k, t, dist, size, tok, vg, st) in MEASURED.items():
        ell = k - t - 1
        fl = verify_gas(rel, n, k, t, ell, dist, size, this_code=False)
        pc = dist * per_column(rel, k, ell, FLOOR)
        tx, cd = tx_gas(rel, size, fl)
        print(f"| {rel} | {pre} | {t} | {size:,} | {vg / 1e6:.1f} M | {fl / 1e6:.1f} M | {pc / 1e6:.1f} M | "
              f"{statement(rel, FLOOR) / 1e6:.1f} M | {cd / 1e6:.2f} M | {tx / 1e6:.1f} M | {'yes' if tx <= CAP else 'no'} |")


def grid():
    print('\n## Cheapest transaction per regime over (n, k) [estimate]\n')
    print('Search: n, k smooth (radices 2/19/43/431), n >= 4k, n <= 2^21, modelled prover work <= 4e9 (ligero_params p1), '
          't from the regime, distinct columns = expected n(1 - (1 - 1/n)^t), proof bytes from the p1 size model.\n')
    print('| relation | regime | verifier | n | k | t | proof B | verify | tx (EIP-7623) | <= cap |')
    print('|---|---|---|---|---|---|---|---|---|---|')
    for rel in ['R_REG', 'R_TX']:
        for reg in ['proven', 'johnson', 'conj']:
            for this_code in [True, False]:
                best = None
                for n in lp.SMOOTH4:
                    if n > lp.NMAX:
                        continue
                    for k in lp.SMOOTH4:
                        if 4 * k > n or k < 64:
                            continue
                        if reg == 'johnson':
                            j = lp.johnson(n, k)
                            if not j or j[1] < 128:
                                continue
                            f = j[0]
                        else:
                            f = lp.factor_proven(n, k) if reg == 'proven' else lp.factor_conj(n, k)
                        t = lp.t_of(f)
                        r = lp.model1(rel, n, k, t, lp.SMOOTH4)
                        if not r or r['prover'] > lp.PMAX:
                            continue
                        vg = verify_gas(rel, n, k, t, r['ell'], r['dist'], r['size'], this_code)
                        tx, _ = tx_gas(rel, r['size'], vg)
                        if best is None or tx < best[0]:
                            best = (tx, n, k, t, r['size'], vg)
                tx, n, k, t, size, vg = best
                print(f"| {rel} | {reg} | {'this code' if this_code else 'floor'} | {n} | {k} | {t} | {size:,} | "
                      f"{vg / 1e6:.1f} M | {tx / 1e6:.1f} M | {'yes' if tx <= CAP else 'no'} |")


def bounds():
    """lower bounds independent of the code: per-column multiply-accumulates x t at >= 40 gas each"""
    print('\n## Per-column work, the code-independent part (F_q^4 x F_q multiply-accumulates per opened column)\n')
    print('| relation | preset | witness-vector MACs | test-polynomial MACs | total x t | at 40 gas / MAC |')
    print('|---|---|---|---|---|---|')
    for (rel, pre), (n, k, t, dist, size, tok, vg, st) in MEASURED.items():
        ell = k - t - 1
        L = layout(rel, ell)
        w = L['nnz'] + ell
        p = 3 * (2 * k - 1) - ell
        print(f"| {rel} | {pre} | {w:,} | {p:,} | {(w + p) * dist / 1e6:.2f} M | {(w + p) * dist * 40 / 1e6:.0f} M gas |")


if __name__ == '__main__':
    check()
    floor_table()
    bounds()
    grid()
