#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T0 of the ua*/mtx* merge plan: after spike A, the address builders the Zether libraries kept for the address entries
(CTR-ZTH-94 moved them there after the spike) have no caller; they go, so the libraries' sizes are the merged ones.
Run once from smartcontracts/evm on the scratch tree; prints what it deleted, fails on a pattern that matches nothing.
"""
import re
import sys

sys.path.insert(0, __file__.rsplit('/', 1)[0])
from merge_router import block  # noqa: E402

CUT = {
    'src/zether/ZetherLib.sol': ['multiCall(MetaTxLib.Envelope', 'singleCall(MetaTxLib.Envelope',
                                 'unshieldCall(MetaTxLib.Envelope'],
    'src/zether/ZetherWrappedLib.sol': ['unwrapCall(MetaTxLib.Envelope'],
    'src/zether/ZetherLayer.sol': ['_namedZ(bytes4 sel, bool compact, MetaTxLib.Envelope'],
}

for p, heads in CUT.items():
    s = open(p).read()
    for h in heads:
        m = re.search(r'^[ \t]*function ' + re.escape(h), s, re.M)
        assert m, (p, h)
        a, b = block(s, m)
        s = s[:a] + s[b:]
        print(p, 'deleted', h)
    open(p, 'w').write(s)
