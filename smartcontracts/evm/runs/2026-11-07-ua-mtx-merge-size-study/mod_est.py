#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Body-module sizes from the complement builds: a module is the kind compiled with every entry outside the module's
domains forwarded (same bases, same storage layout, same hooks), less the stubs of those forwarded entries, which a real
module would not have. Stub cost per entry = the kind's floor (gen_floor.py) / its entry count.
usage: mod_est.py <solc-output.json> <floor-sizes.json> [--json out.json] <name>=<domains>=<build.json> ...   UNAUDITED research tooling."""
import json, sys
from size_map import KINDS, KIND_ID, entry_domain, sel_decls
import evmmap
from fwd_spike import KEEP_ALWAYS

o = evmmap.load(sys.argv[1])
floor = json.load(open(sys.argv[2]))
args = sys.argv[3:]
jout = None
if args and args[0] == '--json':
    jout, args = args[1], args[2:]
res = {}
mods = []
for a in args:
    n, doms, path = a.split('=', 2)
    mods.append((n, set(doms.split(',')), json.load(open(path))))
src = evmmap.Sources(o)
print('| kind | entries | floor B/entry | ' + ' | '.join(f'{n}: kept / build / module' for n, _, _ in mods) + ' |')
print('|' + '---|' * (3 + len(mods)))
for k in KINDS:
    decl = sel_decls(o, k)
    path = next(p for p, cs in o['contracts'].items() if k in cs)
    sels = list(o['contracts'][path][k]['evm']['methodIdentifiers'].values())
    N = len(sels)
    per = floor['Floor' + k]['runtime_size'] / N
    cells = []
    for n, doms, b in mods:
        kept = 0
        for s in sels:
            c, f, _ = decl.get(s, ('?', '?', '?'))
            d = 'erc20-core' if f in KEEP_ALWAYS else entry_domain(c, f)
            if d in doms:
                kept += 1
        size = b[k]['runtime_size']
        est = round(size - per * (N - kept))
        res.setdefault(k, {})[n] = {'kept': kept, 'build': size, 'module': est}
        cells.append(f'{kept} / {size} / {est}')
    print(f'| {k} ({KIND_ID[k]}) | {N} | {per:.0f} | ' + ' | '.join(cells) + ' |')
if jout:
    json.dump(res, open(jout, 'w'), indent=1)
