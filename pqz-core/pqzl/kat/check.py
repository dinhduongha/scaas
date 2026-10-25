#!/usr/bin/env python3
"""Compare the arithmetic-layer cases of two lazer_dump JSON files (golden upstream vs pqz-core).

  python3 -I kat/check.py ../params/sets/<set>/lazer-3330e48-kat.json build/native/kat-pqz.json
Exit 0 iff every case is equal (the "meta" block may differ: backend, build, CPU).
"""
import json
import sys

gold, mine = (json.load(open(p)) for p in sys.argv[1:3])
g, m = gold["cases"], mine["cases"]
bad = [k for k in g if g[k] != m.get(k)] + [k for k in m if k not in g]
for k in bad:
    print(f"MISMATCH {k}")
print(f"{len(g) - len(bad)}/{len(g)} cases equal; golden: {gold['meta']['backend']} ({gold['meta']['build']}, "
      f"avx512f={gold['meta']['cpu_avx512f']}); checked: {mine['meta']['backend']}")
sys.exit(1 if bad else 0)
