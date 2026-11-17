# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Research sketch: factor r-1 and r+1 of BLS12-381 (zether.md §3) for the static-DH (Cheon / Brown-Gallant) estimate.
from sympy import factorint
from math import log2
r = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
f = factorint(r - 1); print('r-1 =', ' * '.join(f'{p}^{e}' if e > 1 else str(p) for p, e in sorted(f.items())))
assert max(f) < 2**28
g = factorint(r + 1, limit=10**7); print('r+1 small part =', {p: e for p, e in g.items() if p < 10**7}, 'largest cofactor bits', round(log2(max(g)), 1))
# Cheon with d | r-1: cost ~ sqrt(r/d) + sqrt(d) group ops, needs [x^d]G, i.e. about d oracle queries
for qb in (20, 30, 40):
    d = 1
    for p, e in sorted(f.items()):             # largest divisor of r-1 below 2^qb (greedy is enough for an estimate)
        for _ in range(e):
            if d * p <= 2**qb: d *= p
    print(f'queries <= 2^{qb}: d = 2^{log2(d):.1f}, cost ~ 2^{log2((r/d)**0.5 + d**0.5):.1f} (generic 2^{log2(r**0.5):.1f})')
