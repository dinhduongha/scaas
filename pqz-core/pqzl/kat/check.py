#!/usr/bin/env python3
"""Compare the arithmetic-layer cases of two lazer_dump JSON files (golden upstream vs pqz-core).

  python3 -I kat/check.py ../params/sets/<set>/lazer-3330e48-kat.json build/native/kat-pqz.json
Exit 0 iff every case is equal (the "meta" block may differ: backend, build, CPU), except the one intended deviation
(R0 review fix, R1-C1 / R2-C2): case power2round, where pqz-core's "p2r_wrap" {q, D} names the wrap case r1 * 2^D >= q
in which upstream's r1 is no high part mod q and pqz-core gives r1 = 0; exactly those coefficients may differ, as
golden r1 (r1 << D >= q) -> 0, and they are counted.
"""
import json
import sys

gold, mine = (json.load(open(p)) for p in sys.argv[1:3])
g, m = gold["cases"], mine["cases"]
wrap = mine.get("p2r_wrap")


def p2r_ok(x, y):
    """golden x, mine y (nested lists): equal, or each differing coefficient is the wrap case"""
    if isinstance(x, list):
        return isinstance(y, list) and len(x) == len(y) and all(p2r_ok(u, v) for u, v in zip(x, y))
    if x == y:
        return True
    if wrap and y == 0 and x << wrap["D"] >= wrap["q"]:
        p2r_ok.n += 1
        return True
    return False


p2r_ok.n = 0
bad = [k for k in g if not (p2r_ok(g[k], m.get(k)) if k == "power2round" else g[k] == m.get(k))]
bad += [k for k in m if k not in g]
if p2r_ok.n:
    print(f"power2round: {p2r_ok.n} wrap-case coefficients r1 = 0 (golden r1 << D >= q; the intended deviation)")
for k in bad:
    print(f"MISMATCH {k}")
print(f"{len(g) - len(bad)}/{len(g)} cases equal; golden: {gold['meta']['backend']} ({gold['meta']['build']}, "
      f"avx512f={gold['meta']['cpu_avx512f']}); checked: {mine['meta']['backend']}")
sys.exit(1 if bad else 0)
