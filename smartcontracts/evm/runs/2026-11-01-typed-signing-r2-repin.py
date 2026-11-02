#!/usr/bin/env python3
"""typed-signing R2: the UA-8 regression pins (`UARegistryUA8Test._pin`, GAS rows) from the logs of the four sets, the same rows
on the pre-split source next to them. Not a calibrated row, not `debit_min_gas`: regression guards, re-pinned as P3, P1b, R1 did.
  repin.py <after logs ...> -- <before logs ...>     rewrites `_pin`, prints name | before | after | delta."""
import re, sys
split = sys.argv.index("--")
def rows(files):
    r = {}
    for f in files:
        for l in open(f, errors="replace"):
            m = re.match(r"\s*GAS\|(.*)\|(\d+)\|(\d+)\s*$", l)
            if m:
                r[m[1]] = (int(m[2]), int(m[3]))
    return r
after, before = rows(sys.argv[1:split]), rows(sys.argv[split + 1:])
p = "test/ua/UARegistryUA8.t.sol"
s = open(p).read()
seen = set()
def sub(m):
    name = m[1]
    seen.add(name)
    if name not in after:
        raise SystemExit(f"no row for {name}")
    return f'if (h == keccak256("{name}")) return ({after[name][0]}, {after[name][1]});'
s2 = re.sub(r'if \(h == keccak256\("([^"]+)"\)\) return \(\d+, \d+\);', sub, s)
missing = set(after) - seen
if missing:
    raise SystemExit(f"rows without a pin: {sorted(missing)}")
open(p, "w").write(s2)
print("name | regular before | regular after | delta | state before | state after")
for n in sorted(after):
    a, b = after[n], before.get(n, (0, 0))
    print(f"{n} | {b[0]} | {a[0]} | {a[0] - b[0]:+d} | {b[1]} | {a[1]}")
