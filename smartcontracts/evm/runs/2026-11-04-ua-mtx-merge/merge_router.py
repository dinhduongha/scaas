#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T0 of the ua*/mtx* merge plan (spec R14): the router's 19 pairs become one entry each. The address `mtx<Op>` body and its
typehash go, the `ua<Op>` body takes the `mtx<Op>` name; `_mtx` / `_mtxCall` go; the generic overrides follow the rename.
Run once from smartcontracts/evm on the scratch tree (after spike A); prints what it changed, fails on a pattern that matches
nothing. Scratch only: the build (T6) moves the bodies to legacy instead.
"""
import re

BASE = 'src/governance/GovernanceRouterBase.sol'
KINDS = 'src/governance/GovernanceRouter.sol'


def block(s, m):
    """[start, end) of the function whose `function` keyword `m` matched, with its doc comment."""
    lines = s[:m.start()].split('\n')
    while len(lines) > 1 and lines[-2].lstrip().startswith('///'):
        lines.pop(-2)
    start = len('\n'.join(lines))
    j = m.end()
    while s[j] not in '{;':
        j += 1
    depth = 0
    while True:
        depth += {'{': 1, '}': -1}.get(s[j], 0)
        j += 1
        if depth == 0:
            break
    end = j + (s[j:j + 2] == '\n\n') + (s[j:j + 1] == '\n')
    return start, end


def delete_all(s, regex, label):
    n = 0
    while True:
        m = re.search(regex, s, re.M)
        if not m:
            break
        a, b = block(s, m)
        s = s[:a] + s[b:]
        n += 1
    assert n, label
    print(label, n)
    return s


def main():
    total = 0
    for p in (BASE, KINDS):
        s = open(p).read()
        s = delete_all(s, r'^[ \t]*function mtx[A-Z]\w*\(MetaTxLib\.Envelope calldata e', p + ': address entries deleted')
        s, n = re.subn(r'\bfunction ua([A-Z]\w*)\(MetaTxLib\.UAEnvelope', r'function mtx\1(MetaTxLib.UAEnvelope', s)
        assert n, p
        print(p, ': ua entries renamed', n)
        total += n
        if p == BASE:
            s, k = re.subn(r'\n    bytes32 internal constant (?!UA_|GRANT_TERMS)[A-Z_]+ = keccak256\(\n        "[A-Za-z]+\(address from,[^;]*?\);', '', s)
            assert k == 19, k
            print(p, ': address typehashes deleted', k)
            s = delete_all(s, r'^[ \t]*function _mtx\(', p + ': _mtx')
            s = delete_all(s, r'^[ \t]*function _mtxCall\(', p + ': _mtxCall')
            for a, b in (('function uaExecute(', 'function mtxExecute('), ('function uaBatch(', 'function mtxBatch(')):
                assert a in s, a
                s = s.replace(a, b)
        open(p, 'w').write(s)
    assert total == 19, total


if __name__ == '__main__':
    main()
