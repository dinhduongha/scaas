#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T0 of the ua*/mtx* merge plan: the results tables from sizes-<run>.json and t0-<run>.txt (beside this script).
Prints Markdown tables to stdout: sizes, deploy gas asked against 60 M / 70 M (probe + the factory frame measured on the
same run), gas rows base vs each run, and the Q3 fit table. Every figure is [M] (forge, deterministic)."""
import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
RUNS = ['base', 'M', 'ML', 'MD', 'MLD']
REG = ['M-reg', 'ML-reg', 'MD-reg', 'MLD-reg']
NAMES = {'base': 'base', 'M': 'M', 'ML': 'M + L', 'MD': 'M + D', 'MLD': 'M + L + D',
         'M-reg': 'M, stand-in', 'ML-reg': 'M + L, stand-in', 'MD-reg': 'M + D, stand-in', 'MLD-reg': 'M + L + D, stand-in'}
KINDS = ['NormalToken', 'WrappedToken', 'NormalZetherToken', 'WrappedZetherToken', 'NormalPqzToken', 'WrappedPqzToken']
OTHERS = ['SCaaSDex', 'GovernanceRouter', 'MtxRelayFee', 'MtxPipelineLib', 'WrappedLib', 'ZetherLib', 'ZetherWrappedLib',
          'PqzWrappedLib', 'TradeLib', 'GovernanceLib', 'TokenBodyLib', 'MandateWallet', 'SmartKeyAccount']
M60, M70 = 60_000_000, 70_000_000


def sizes(run):
    p = os.path.join(HERE, 'sizes-%s.json' % run)
    return json.load(open(p)) if os.path.exists(p) else {}


def deploy(run):
    d = {}
    p = os.path.join(HERE, 't0-%s.txt' % run)
    if not os.path.exists(p):
        return d
    for line in open(p):
        m = re.match(r'T0DEPLOY \| (.+?) \| runtime (\d+) \| init (\d+) \| regular (\d+) \| state (\d+) \| asked (\d+)', line)
        if m:
            d[m[1]] = dict(runtime=int(m[2]), regular=int(m[4]), state=int(m[5]), asked=int(m[6]))
    return d


def gas(run):
    g = {}
    p = os.path.join(HERE, 't0-%s.txt' % run)
    if not os.path.exists(p):
        return g
    for line in open(p):
        m = re.match(r'T0GAS \| \w+ \| (.+?) \| calldata (\d+) \| (\d+)', line.strip())
        if m:
            g[m[1]] = (int(m[3]), int(m[2]))
    return g


def frame(d):
    a, b = d.get('NormalToken via deployImplementation'), d.get('NormalToken via probe, same env')
    return a['asked'] - b['asked'] if a and b else 0


def mb(x):
    return '%.2f M' % (x / 1e6)


def main():
    out = []
    out.append('### Runtime bytes [M]\n')
    out.append('| Contract | ' + ' | '.join(NAMES[r] for r in RUNS) + ' |')
    out.append('|---|' + '---:|' * len(RUNS))
    S = {r: sizes(r) for r in RUNS + REG}
    for k in KINDS + OTHERS:
        row = [str(S[r][k]['runtime']) if k in S[r] else '' for r in RUNS]
        out.append('| `%s` | %s |' % (k, ' | '.join(row)))
    out.append('\nRegulated stand-in (six direct stubs + the hook in `_update` and `_uaMove`), runtime bytes [M]:\n')
    out.append('| Kind | ' + ' | '.join(NAMES[r] for r in REG) + ' |')
    out.append('|---|' + '---:|' * len(REG))
    for k in ['NormalToken', 'WrappedToken']:
        out.append('| `%s` | %s |' % (k, ' | '.join(str(S[r][k]['runtime']) if k in S[r] else '' for r in REG)))

    out.append('\n### Deploy gas asked, one release transaction each [M]\n')
    out.append('Asked = (regular x 64/63 + EIP-8037 state) x 1.05 of the CREATE2 probe, plus the frame `deployImplementation` '
               'adds (measured on the same run: the `NORMAL` release through the factory minus through the probe). Fits '
               '= asked <= the limit (EIP-8037: regular + state; never `gas_used`). Every regular x 1.05 is under 2^24.\n')
    out.append('| Release | ' + ' | '.join(NAMES[r] for r in RUNS + REG) + ' |')
    out.append('|---|' + '---:|' * len(RUNS + REG))
    D = {r: deploy(r) for r in RUNS + REG}
    F = {r: frame(D[r]) for r in RUNS + REG}
    for k in KINDS + ['SCaaSDex', 'GovernanceRouter', 'MtxRelayFee', 'MtxPipelineLib', 'WrappedLib', 'TradeLib',
                      'GovernanceLib', 'ZetherLib', 'ZetherWrappedLib', 'PqzWrappedLib', 'TokenBodyLib']:
        cells = []
        for r in RUNS + REG:
            x = D[r].get(k)
            if not x:
                cells.append('')
                continue
            a = x['asked'] + (F[r] if k in KINDS else 0)
            mark = '' if a <= M60 else (' (70)' if a <= M70 else ' (no)')
            cells.append(mb(a) + mark)
        out.append('| `%s` | %s |' % (k, ' | '.join(cells)))
    out.append('| frame (factory) | %s |' % ' | '.join(mb(F[r]) if F[r] else '' for r in RUNS + REG))
    out.append('\nMarks: none = fits 60 M (and 70 M); (70) = fits 70 M only; (no) = fits neither. A token kind\'s figure '
               'includes the frame; a library or the router is its own plain transaction (no frame).\n')

    out.append('\n### Gas, forge (`GovGas.t.sol`\'s method; isolate) [M]\n')
    G = {r: gas(r) for r in RUNS}
    rows = sorted(set(G['base']) | set(G['M']))
    out.append('| Row | base | ' + ' | '.join(NAMES[r] for r in RUNS[1:]) + ' | M - base | calldata base -> M |')
    out.append('|---|---:|' + '---:|' * (len(RUNS) - 1) + '---:|---|')
    for row in rows:
        b = G['base'].get(row)
        cells = [str(G[r][row][0]) if row in G[r] else '' for r in RUNS[1:]]
        d = '%+d' % (G['M'][row][0] - b[0]) if b and row in G['M'] else ''
        cd = '%s -> %s' % (b[1] if b else '', G['M'][row][1] if row in G['M'] else '')
        out.append('| %s | %s | %s | %s | %s |' % (row, b[0] if b else '', ' | '.join(cells), d, cd))
    out.append('\n### Q3: which lever set fits 60 M and 70 M (spec §4 rule 1: `NormalToken`, `WrappedToken` and their '
               'stand-ins) [M]\n')
    out.append('Gap = (asked - limit) / (the run\'s asked per runtime byte of that kind): the runtime bytes still to remove. '
               '0 = fits.\n')
    sets = [('M', 'M-reg'), ('ML', 'ML-reg'), ('MD', 'MD-reg'), ('MLD', 'MLD-reg')]
    out.append('| Set | Kind | asked | 60 M gap (B) | 70 M gap (B) | stand-in asked | stand-in 60 M gap (B) | stand-in 70 M gap (B) |')
    out.append('|---|---|---:|---:|---:|---:|---:|---:|')
    for r, rr in sets:
        for k in ['NormalToken', 'WrappedToken', 'NormalZetherToken', 'WrappedZetherToken']:
            cells = []
            for run in (r, rr):
                x = D[run].get(k)
                if not x:
                    cells += ['', '', '']
                    continue
                a = x['asked'] + F[run]
                per = x['asked'] / x['runtime']
                g = [max(0, -(-(a - lim) // per)) for lim in (M60, M70)]
                cells += [mb(a), '%d' % g[0], '%d' % g[1]]
            out.append('| %s | `%s` | %s |' % (NAMES[r], k, ' | '.join(cells)))
    print('\n'.join(out))


if __name__ == '__main__':
    main()
