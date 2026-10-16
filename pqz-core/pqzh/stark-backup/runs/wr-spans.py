#!/usr/bin/env python3
"""PROBE helper (pqzh-zk-whir.md §10.3): summarise a tracing-subscriber span log (FmtSpan::CLOSE lines): total busy
time and count per span name, then every span closing with >= 0.5 s busy. Stdlib only.
    python3 runs/wr-spans.py runs/wr-tx2-debug-spans.txt > runs/wr-tx2-debug-summary.txt"""
import collections, re, sys

UNIT = {'ns': 1e-9, 'µs': 1e-6, 'ms': 1e-3, 's': 1.0}
agg, big = collections.defaultdict(lambda: [0, 0.0]), []
for line in open(sys.argv[1], encoding='utf-8', errors='replace'):
    line = re.sub(r'\x1b\[[0-9;]*m', '', line)
    m = re.search(r'Z\s+\w+\s+(.*?): (\S+): close time.busy=([0-9.]+)(ns|µs|ms|s)', line)
    if not m:
        continue
    t = float(m.group(3)) * UNIT[m.group(4)]
    key = (re.sub(r'\{.*?\}', '', m.group(1).split(':')[-1]), m.group(2))
    agg[key][0] += 1
    agg[key][1] += t
    if t >= 0.5:
        big.append((t, m.group(1)[:160]))
print('busy_s  count  span  [module]  (nested spans are counted inside their parents too)')
for (k, mod), (n, t) in sorted(agg.items(), key=lambda x: -x[1][1])[:25]:
    print(f'{t:9.2f} {n:7d}  {k}  [{mod}]')
print('--- spans closing with >= 0.5 s busy, in order')
for t, s in big:
    print(f'{t:8.2f}  {s}')
