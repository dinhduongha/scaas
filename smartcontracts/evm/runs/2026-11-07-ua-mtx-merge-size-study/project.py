#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Projected runtime and deploy gas `asked` of every contract against 60 M: today's form with the groups still to land
(chain-neutral, 3f, 3h, T66b's registry items, the factory index), and the proposed form (variant A with forward stubs).

usage: project.py <sizes-head-all.json> <fwd-V7.json> <fwd-V6.json> <modules.json>   UNAUDITED research tooling.
asked = (regular + state) x 1.05, fitted on T10 / T33's measured rows (runs/2026-11-04-ua-mtx-merge-deploy-gas.txt):
  token release through deployImplementation: 1,675.3 gas/B + 0.88 M (state 1,530/B + 281,520; regular ~65.5/B + 204 k;
  frame 0.37 M); library: 1,674.7 gas/B + 0.23 M; a body module (a contract on the token's bases, no factory frame):
  1,675.3 gas/B + 0.51 M [estimate]; a plain contract with a constructor (registry, router, factory): 1,697 gas/B + 0.19 M
  (UARegistry's row) [estimate]. Growth ranges are the specs' [estimate]s (the note's section 6 lists them).
"""
import json, sys

TOKEN, LIB, MOD, PLAIN = (1675.3, 0.88e6), (1674.7, 0.23e6), (1675.3, 0.51e6), (1697.0, 0.19e6)
LIMIT = 60e6


def asked(b, f):
    return f[0] * b + f[1]


def limit_b(f):
    return int((LIMIT - f[1]) / f[0])


KINDS = [('NormalToken', 0, False), ('WrappedToken', 1, False), ('NormalZetherToken', 2, False),
         ('WrappedZetherToken', 3, False), ('NormalPqzToken', 4, True), ('WrappedPqzToken', 5, True),
         ('NormalRegulatedToken', 8, False), ('WrappedRegulatedToken', 9, False),
         ('NormalZetherRegulatedToken', 10, False), ('WrappedZetherRegulatedToken', 11, False),
         ('NormalPqzRegulatedToken', 12, True), ('WrappedPqzRegulatedToken', 13, True)]
# token growth, KB (lo, hi): today's form = chain-neutral 0.2-0.8 + 3f's every-kind 0.1-0.2 (+ PQZ kinds 3f 1.0-1.8 more, 3h 0.3-0.6)
G_TODAY = {False: (0.3, 1.0), True: (1.6, 3.4)}
# forward form: the token gains only stubs: chain-neutral 0.2-0.3 (chainEnv, validateEnv); PQZ kinds + 3f 0.6-0.95, 3h 0.25-0.35
G_FWD = {False: (0.2, 0.3), True: (1.05, 1.6)}
OTHERS = [  # name, form, growth KB (lo, hi), why
    ('SCaaSDex', TOKEN, (0.2, 0.8), 'chain-neutral'),
    ('UARegistry', PLAIN, (0.3, 0.7), 'T66b: requirePortable, the msig KEM refusal; before the rebalance'),
    ('UARegistryLib', LIB, (0.1, 0.3), 'T66b: the msig KEM refusal; before the rebalance'),
    ('GovernanceRouter', PLAIN, (0.8, 1.3), '3f three ops 0.5-0.8, 3h bit 24 op 0.3-0.5'),
    ('OpenFactory', PLAIN, (7.0, 11.0), 'index 2.5-4, generic catalogue 3-5, chain-neutral 1.5-2'),
    ('MandateWallet', PLAIN, (0.0, 0.2), ''),
    ('MtxPipelineLib', LIB, (0.0, 0.4), 'chain-neutral reader if placed here'),
    ('WrappedLib', LIB, (0.0, 0.0), ''),
    ('GovernanceLib', LIB, (0.1, 0.2), '3h bit 24'),
    ('TradeLib', LIB, (0.0, 0.0), ''),
    ('RegulatedLib', LIB, (0.3, 0.8), 'chain-neutral validateEnv + reader for 10-13 (spec 7.1)'),
    ('ZetherLib', LIB, (0.3, 0.8), 'chain-neutral validateEnv + reader for 10, 11'),
    ('ZetherWrappedLib', LIB, (0.0, 0.0), ''),
    ('PqzViewLib', LIB, (0.6, 1.0), '3f 0.3-0.5, 3h 0.3-0.5'),
    ('PqzTransferLib', LIB, (1.0, 1.7), '3f 0.4-0.7, 3h 0.6-1.0'),
    ('PqzBurnLib', LIB, (1.0, 1.7), '3f 0.4-0.7, 3h 0.6-1.0'),
    ('PqzStateLib', LIB, (1.0, 1.9), '3f 0.6-1.0, 3h 0.1, chain-neutral reader 0.3-0.8 for 12, 13'),
    ('PqzWrappedLib', LIB, (0.6, 1.0), '3f 0.6-1.0'),
    ('HederaLib', LIB, (0.0, 0.0), ''),
]


def fmt(b, f):
    a = asked(b, f)
    return f'{b:,.0f} / {a / 1e6:.1f} M {"yes" if a <= LIMIT else "**no**"}'


def main():
    head = json.load(open(sys.argv[1]))
    v7 = json.load(open(sys.argv[2]))
    v6 = json.load(open(sys.argv[3]))
    print(f'60 M lines: token {limit_b(TOKEN):,} B, library {limit_b(LIB):,} B, module {limit_b(MOD):,} B, plain {limit_b(PLAIN):,} B')
    print()
    print('| contract | HEAD B / asked | today\'s form + growth (hi) B / asked | V6 token + growth (hi) | V7 token + growth (lo-hi) B / asked |')
    print('|---|---|---|---|---|')
    for n, k, pqz in KINDS:
        h = head[n]['runtime_size']
        t = h + G_TODAY[pqz][1] * 1024
        s6 = v6[n]['runtime_size'] + G_FWD[pqz][1] * 1024
        lo, hi = (v7[n]['runtime_size'] + g * 1024 for g in G_FWD[pqz])
        print(f'| `{n}` ({k}) | {fmt(h, TOKEN)} | {fmt(t, TOKEN)} | {fmt(s6, TOKEN)} | {lo:,.0f}-{fmt(hi, TOKEN)} |')
    print()
    print('| contract | form | HEAD B / asked | + growth (hi) B / asked | growth |')
    print('|---|---|---|---|---|')
    for n, f, g, why in OTHERS:
        h = head[n]['runtime_size']
        form = {TOKEN: 'release', LIB: 'library', PLAIN: 'plain'}[f]
        print(f'| `{n}` | {form} | {fmt(h, f)} | {fmt(h + g[1] * 1024, f)} | {why} |')
    print()
    mods = json.load(open(sys.argv[4]))
    # module plan of the proposal (V7 form), growth KB (lo, hi) into each module; Transfer absorbs MtxPipelineLib (+3-6 KB)
    PLAN = [('Transfer', 'MA', (3.2, 6.4), 'pipeline, named transfers, pay; MtxPipelineLib inlined (+3-6 KB), the env reader'),
            ('Trade', 'MB', (0.0, 0.0), 'trade entries, mtxWrapOrder'),
            ('Admin', 'MC', (0.4, 1.0), 'governance, init, tables, metadata views, mint/burn; chain-neutral and 3f config bodies'),
            ('Pqz', 'MD1', (0.6, 1.4), 'PQZ entries; 3f and 3h bodies'),
            ('Wrapped+Reg', 'MD2', (0.0, 0.3), 'wrapped entries, regulated powers'),
            ('Zether', 'MD3', (0.0, 0.3), 'Zether entries')]
    print('Modules per kind (proposal, V7 form): upper bound = the complement build less the forwarded stubs, + growth hi;')
    print('lower bound = less the residue every complement build carries (the V8 build), + growth lo. Line: module', f'{limit_b(MOD):,} B.')
    print('| kind | ' + ' | '.join(p[0] for p in PLAN) + ' | largest (upper) | release asked today+growth -> proposed (lower-upper) |')
    print('|' + '---|' * (len(PLAN) + 3))
    for n, k, pqz in KINDS:
        m = mods[n]
        res = m['V8']['module']
        cells, big, tot_lo, tot_hi = [], 0, 0.0, 0.0
        for name, key, g, _ in PLAN:
            if m[key]['kept'] == 0:
                cells.append('')
                continue
            hi = m[key]['module'] + g[1] * 1024
            lo = m[key]['module'] - res + g[0] * 1024
            big = max(big, hi)
            tot_lo += asked(lo, MOD)
            tot_hi += asked(hi, MOD)
            cells.append(f'{lo / 1024:.1f}-{hi / 1024:.1f} KB')
        tok_lo, tok_hi = (v7[n]['runtime_size'] + gg * 1024 for gg in G_FWD[pqz])
        today = asked(head[n]['runtime_size'] + G_TODAY[pqz][1] * 1024, TOKEN)
        print(f'| `{n}` ({k}) | ' + ' | '.join(cells) + f' | {big:,.0f} {"yes" if big <= limit_b(MOD) else "**no**"} | '
              f'{today / 1e6:.0f} M -> {(asked(tok_lo, TOKEN) + tot_lo) / 1e6:.0f}-{(asked(tok_hi, TOKEN) + tot_hi) / 1e6:.0f} M |')
    print()
    for name, key, g, why in PLAN:
        print(f'- {name} ({key}): {why}')


if __name__ == '__main__':
    main()
