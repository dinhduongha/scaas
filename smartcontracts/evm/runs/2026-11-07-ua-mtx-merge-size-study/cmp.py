#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Sizes of one or more `forge build --sizes --json` files against a base, for the kinds and named contracts.
usage: cmp.py <base.json> <name>=<variant.json> ...   UNAUDITED research tooling."""
import json, sys
from size_map import KINDS, KIND_ID
base = json.load(open(sys.argv[1]))
vs = [(a.split('=', 1)[0], json.load(open(a.split('=', 1)[1]))) for a in sys.argv[2:]]
names = KINDS + ['SCaaSDex', 'UARegistry', 'GovernanceRouter', 'MandateWallet']
print('| contract | HEAD | ' + ' | '.join(f'{n} (Δ)' for n, _ in vs) + ' |')
print('|' + '---|' * (2 + len(vs)))
for n in names:
    b = base[n]['runtime_size']
    cells = []
    for _, v in vs:
        r = v.get(n, {}).get('runtime_size')
        cells.append(f'{r} ({r - b:+d})' if r is not None else '-')
    tag = f' ({KIND_ID[n]})' if n in KIND_ID else ''
    print(f'| {n}{tag} | {b} | ' + ' | '.join(cells) + ' |')
