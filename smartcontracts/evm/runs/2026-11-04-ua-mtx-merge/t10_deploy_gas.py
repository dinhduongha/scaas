#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-merge T10: the deploy-gas summary's tables (stdout, Markdown). T0's M column (t0-M.txt) against this tree
(t10-deploy.txt, `t10_deploy_gas.sh`), T0's formula: asked = (regular x 64/63 + EIP-8037 state) x 1.05 of the CREATE2
probe, a token kind plus the frame `deployImplementation` adds (each run's own: the NORMAL release through the factory
minus through the probe); fits = asked <= the limit (EIP-8037: regular + state, never a block's gas_used); regular x 1.05
against 2^24. Then the public gate's own figures (DeployBase, RELEASE_GAS_GATE=public, `forge script` on a local anvil:
each release transaction, intrinsic and calldata in its regular gas) from the log given as argv[1], if any."""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
KINDS = ['NormalToken', 'WrappedToken', 'NormalZetherToken', 'WrappedZetherToken', 'NormalPqzToken', 'WrappedPqzToken']
ROWS = KINDS + ['SCaaSDex', 'GovernanceRouter', 'MtxRelayFee', 'UARegistryLib', 'MtxPipelineLib', 'WrappedLib', 'TradeLib',
                'GovernanceLib', 'HederaLib', 'ZetherLib', 'ZetherWrappedLib', 'PqzWrappedLib', 'PqzStateLib', 'PqzTransferLib',
                'PqzBurnLib', 'PqzViewLib']
M60, M70, CAP = 60_000_000, 70_000_000, 1 << 24


def rows(name):
    d = {}
    for line in open(os.path.join(HERE, name)):
        m = re.match(r'T0DEPLOY \| (.+?) \| runtime (\d+) \| init \d+ \| regular (\d+) \| state (\d+) \| asked (\d+)', line)
        if m:
            d[m[1]] = dict(runtime=int(m[2]), regular=int(m[3]), state=int(m[4]), asked=int(m[5]))
    d['frame'] = d['NormalToken via deployImplementation']['asked'] - d['NormalToken via probe, same env']['asked']
    return d


def asked(d, k):
    return d[k]['asked'] + (d['frame'] if k in KINDS else 0)


def fit(a):
    return 'yes' if a <= M60 else 'no', 'yes' if a <= M70 else 'no'


def mb(x):
    return '%.2f M' % (x / 1e6)


def main():
    old, new = rows('t0-M.txt'), rows('t10-deploy.txt')
    out = ['| Release | runtime B, T0 M -> T10 | regular | state | asked, T0 M -> T10 | 60 M | 70 M | regular x 1.05 < 2^24 |',
           '|---|---:|---:|---:|---:|---|---|---|']
    for k in ROWS:
        n = new[k]
        o = '%s -> ' % format(old[k]['runtime'], ',') if k in old else '(not in T0) '
        oa = '%s -> ' % mb(asked(old, k)) if k in old else ''
        a = asked(new, k)
        out.append('| `%s` | %s%s | %s | %s | %s%s | %s | %s | %s |' % (
            k, o, format(n['runtime'], ','), format(n['regular'], ','), format(n['state'], ','), oa, mb(a), *fit(a),
            'yes' if n['regular'] * 105 // 100 < CAP else 'NO'))
    out.append('| frame (`deployImplementation`, in each kind row) | | | | %s -> %s | | | |' % (mb(old['frame']), mb(new['frame'])))
    if len(sys.argv) > 1:
        out += ['', '| Release (public gate, `forge script`) | regular | state | asked | 60 M | 70 M | regular x 1.05 < 2^24 |',
                '|---|---:|---:|---:|---|---|---|']
        seen = set()
        for line in open(sys.argv[1]):
            m = re.search(r'release gas \| (\w+) \| regular (\d+) \| state (\d+) \| asked (\d+)', line)
            if m and m[1] not in seen:
                seen.add(m[1])
                r, s, a = int(m[2]), int(m[3]), int(m[4])
                out.append('| `%s` | %s | %s | %s | %s | %s | %s |' % (m[1], format(r, ','), format(s, ','), mb(a), *fit(a),
                                                                    'yes' if r * 105 // 100 < CAP else 'NO'))
    print('\n'.join(out))


if __name__ == '__main__':
    main()
