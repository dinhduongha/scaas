# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T66b task 4.3: a test's `new <Kind>(factory, coreArgs)` becomes `new <Kind>(factory, kindArgs(<id>, factory, coreArgs))`
(the kind's body modules deployed first, `script/KindModules.sol`), and the file imports `kindArgs`. One-shot.
usage (from smartcontracts/evm): python3 script/t66b/migrate_new.py <file> ...   UNAUDITED tooling."""
import os
import re
import sys

KIND = {'NormalToken': 0, 'WrappedToken': 1, 'NormalZetherToken': 2, 'WrappedZetherToken': 3, 'NormalPqzToken': 4,
        'WrappedPqzToken': 5, 'NormalRegulatedToken': 8, 'WrappedRegulatedToken': 9, 'NormalZetherRegulatedToken': 10,
        'WrappedZetherRegulatedToken': 11, 'NormalPqzRegulatedToken': 12, 'WrappedPqzRegulatedToken': 13}
PAT = re.compile(r'\bnew (' + '|'.join(KIND) + r')(\{[^}]*\})?\(')


def args_end(s, i):
    depth = 0
    for j in range(i, len(s)):
        if s[j] == '(':
            depth += 1
        elif s[j] == ')':
            depth -= 1
            if depth == 0:
                return j
    raise SystemExit('unbalanced')


def split_top(a):
    out, depth, cur = [], 0, ''
    for ch in a:
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth -= 1
        if ch == ',' and depth == 0:
            out.append(cur)
            cur = ''
        else:
            cur += ch
    out.append(cur)
    return [x.strip() for x in out]


for path in sys.argv[1:]:
    s = open(path).read()
    pos, n = 0, 0
    while (m := PAT.search(s, pos)):
        open_i = m.end() - 1
        close_i = args_end(s, open_i)
        a = split_top(s[open_i + 1:close_i])
        if len(a) != 2 or a[1].startswith('kindArgs('):
            pos = close_i
            continue
        new = f'{a[0]}, kindArgs({KIND[m.group(1)]}, {a[0]}, {a[1]})'
        s = s[:open_i + 1] + new + s[close_i:]
        pos = open_i + len(new)
        n += 1
    if n and 'kindArgs}' not in s and '{kindArgs' not in s:
        rel = os.path.relpath('script/KindModules.sol', os.path.dirname(path))
        s = re.sub(r'(pragma solidity [^;]+;\n)', r'\1\nimport {kindArgs} from "' + rel + '";\n', s, count=1)
    if n:
        open(path, 'w').write(s)
        print(path, n)
