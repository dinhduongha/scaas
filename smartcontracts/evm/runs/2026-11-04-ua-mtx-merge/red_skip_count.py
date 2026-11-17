#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T0: the recount's summary from <copy>/_moved and red_skip.jsonl: files and `test*` functions that no longer compile on M,
by directory, split into an own compile error and a dependency (a helper or another moved file); and what is left.
`red_skip_count.py <copy>` prints the table (it replaces the spec's §7 test counts)."""
import json, os, re, sys
copy = sys.argv[1]
here = os.path.dirname(os.path.abspath(__file__))
rec = [json.loads(l) for l in open(os.path.join(here, 'red_skip.jsonl'))]
TEST = re.compile(r'^\s*function (test\w*|invariant\w*)\s*\(', re.M)


def tests(p):
    return len(TEST.findall(open(p).read()))


own, dep, rows = 0, 0, {}
for r in rec:
    f = r['file']
    p = os.path.join(copy, '_moved', f)
    n = tests(p) if os.path.exists(p) else 0
    kind = 'dependency' if r['code'] == '6275' else 'own error'
    d = f.split('/')[1] if f.startswith('test/') else f.split('/')[0]
    rows.setdefault(d, [0, 0, 0])
    rows[d][0] += 1
    rows[d][1] += n
    rows[d][2] += f.endswith('.t.sol') is False
    if kind == 'own error':
        own += 1
    else:
        dep += 1
left = []
for root, _, fs in os.walk(os.path.join(copy, 'test')):
    for f in fs:
        if f.endswith('.t.sol'):
            left.append(tests(os.path.join(root, f)))
print('files moved: %d (own compile error %d, only through a moved import %d); test functions in them: %d'
      % (len(rec), own, dep, sum(v[1] for v in rows.values())))
print('left that compile: %d test files, %d test functions' % (len(left), sum(left)))
print('dir | files moved | test functions | of them helpers / non-.t.sol')
for d, v in sorted(rows.items(), key=lambda x: -x[1][1]):
    print('%s | %d | %d | %d' % (d, v[0], v[1], v[2]))
