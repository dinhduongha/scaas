# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T66b task 4.3: a test's or script's cast to a token base (`MetaTokenBase(x).f(...)`, `ZetherLayer(x).f`, ...) and an entry's
selector through it (`MetaTokenBase.f.selector`) name a kind's face instead (the bases hold no entries since the split): the
face of the base's own kind, imported where it is missing. One-shot. usage: python3 script/t66b/migrate_casts.py <file> ...
UNAUDITED tooling."""
import json
import os
import re
import sys

FACE = {'MetaTokenBase': ('NormalToken', 'src/metatx/NormalToken.sol'), 'ERC20MetaTx': ('NormalToken', 'src/metatx/NormalToken.sol'),
        'ZetherLayer': ('NormalZetherToken', 'src/zether/NormalZetherToken.sol'),
        'PqzLayer': ('NormalPqzToken', 'src/pqz/NormalPqzToken.sol'),
        'RegulatedBase': ('NormalRegulatedToken', 'src/regulated/NormalRegulatedToken.sol')}
E = json.load(open('script/t66b/entries.json'))
ENTRY = {e['name'] for es in E['kinds'].values() for e in es}
for path in sys.argv[1:]:
    s = open(path).read()
    o = s
    used = set()
    for base, (face, _) in FACE.items():
        # casts: `Base(expr).member` where the member is an entry
        out, i = '', 0
        for m in re.finditer(r'(?<![\w.])' + base + r'\(', s):
            if m.start() < i:
                continue
            j, depth = m.end() - 1, 0
            while True:
                depth += {'(': 1, ')': -1}.get(s[j], 0)
                if depth == 0:
                    break
                j += 1
            mm = re.match(r'\.(\w+)', s[j + 1:])
            prev = s[max(0, m.start() - 12):m.start()]
            if mm and mm.group(1) in ENTRY:
                out += s[i:m.start()] + face + '('
                i = m.end()
                used.add(base)
        s = out + s[i:]
        s2 = re.sub(r'(?<![\w.])' + base + r'\.(\w+)\.selector', lambda m: (face + '.' + m.group(1) + '.selector')
                    if m.group(1) in ENTRY else m.group(0), s)
        if s2 != s:
            used.add(base)
        s = s2
    for base in used:
        face, fp = FACE[base]
        if re.search(r'import \{[^}]*\b' + face + r'\b', s):
            continue
        rel = os.path.relpath(fp, os.path.dirname(path))
        s = re.sub(r'(pragma solidity [^;]+;\n)', r'\1\nimport {' + face + '} from "' + rel + '";\n', s, count=1)
    if s != o:
        open(path, 'w').write(s)
        print(path, sorted(used))


def types(path):
    """The bases as variable, parameter and return types (`PqzLayer t`, `returns (PqzLayer)`): the kind's face."""
    s = open(path).read()
    o = s
    used = set()
    for base, (face, _) in FACE.items():
        pat = re.compile(r'(?<![\w.{,]\s)(?<![\w.])' + base + r'(?=\s+(?:internal|public|private|immutable|memory|[a-z_]\w*\s*[,)=;])|\))')
        s2 = pat.sub(face, s)
        if s2 != s:
            used.add(base)
        s = s2
    for base in used:
        face, fp = FACE[base]
        if not re.search(r'import \{[^}]*\b' + face + r'\b', s):
            rel = os.path.relpath(fp, os.path.dirname(path))
            s = re.sub(r'(pragma solidity [^;]+;\n)', r'\1\nimport {' + face + '} from "' + rel + '";\n', s, count=1)
    if s != o:
        open(path, 'w').write(s)
        print('types', path, sorted(used))


if os.environ.get('TYPES'):
    for p in sys.argv[1:]:
        types(p)
