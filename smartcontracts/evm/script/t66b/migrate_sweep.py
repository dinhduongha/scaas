# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T66b task 4.3: every remaining use of a token base as a type in tests and scripts (`PqzLayer t`, `PqzLayer(addr)`,
`MetaTokenBase.f` of an entry) names its kind's face; imports, inheritance, constructor chains, comments, strings and the
bases' own members (errors, events, constants, structs) keep the base. One-shot. UNAUDITED tooling."""
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
PAT = re.compile(r'\b(' + '|'.join(FACE) + r')\b')
for path in sys.argv[1:]:
    lines = open(path).read().split('\n')
    used = set()
    for k, line in enumerate(lines):
        st = line.strip()
        if st.startswith(('import ', '//', '*', '/*')) or re.search(r'\bcontract\s+\w+\s+is\b', line):
            continue
        out, last = '', 0
        for m in PAT.finditer(line):
            pre, post = line[:m.start()], line[m.end():]
            if pre.count('"') % 2 == 1 or '//' in pre:
                continue
            if re.match(r'\.(\w+)', post) and re.match(r'\.(\w+)', post).group(1) not in ENTRY:
                continue
            if re.search(r'\)\s*$', pre) and post.startswith('('):  # a constructor chain `) Base(...)`
                continue
            out += line[last:m.start()] + FACE[m.group(1)][0]
            last = m.end()
            used.add(m.group(1))
        lines[k] = out + line[last:]
    s = '\n'.join(lines)
    for base in used:
        face, fp = FACE[base]
        if not re.search(r'import \{[^}]*\b' + face + r'\b', s):
            rel = os.path.relpath(fp, os.path.dirname(path))
            s = re.sub(r'(pragma solidity [^;]+;\n)', r'\1\nimport {' + face + '} from "' + rel + '";\n', s, count=1)
    if used:
        open(path, 'w').write(s)
        print(path, sorted(used))
