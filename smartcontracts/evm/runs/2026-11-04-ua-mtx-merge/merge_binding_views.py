#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T0 of the ua*/mtx* merge plan, spec §2.1 and §2.3 (R35, R36): on the Zether and PQZ kinds the public address view
`envelopeBinding(MetaTransaction)` goes (legacy in the build) and `uaEnvelopeBinding(UAMetaTransaction)` takes the name
`envelopeBinding`. Run once from smartcontracts/evm on the scratch tree; prints what it changed, fails on no match.
"""
import re
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from merge_router import block  # noqa: E402

for p in ['src/zether/ZetherLayer.sol', 'src/zether/IZetherToken.sol', 'src/pqz/PqzLayer.sol']:
    s = open(p).read()
    m = re.search(r'^[ \t]*function envelopeBinding\(MetaTxLib\.MetaTransaction', s, re.M)
    if m:
        a, b = block(s, m) if p != 'src/zether/IZetherToken.sol' else (None, None)
        if a is None:  # an interface line
            e = s.index(';', m.end()) + 1
            lines = s[:m.start()].split('\n')
            while len(lines) > 1 and lines[-2].lstrip().startswith('///'):
                lines.pop(-2)
            a = len('\n'.join(lines))
            b = e + (s[e:e + 1] == '\n')
        s = s[:a] + s[b:]
        print(p, 'address envelopeBinding view deleted')
    s, n = re.subn(r'\bfunction uaEnvelopeBinding\(', 'function envelopeBinding(', s)
    assert n == 1, (p, n)
    print(p, 'uaEnvelopeBinding renamed')
    open(p, 'w').write(s)
