# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T66b task 4.3: a test's or script's `X.Member` of a non-entry member (error, event, constant, struct) of a shared base or a
kind names the core that declares it now (`SaltedEIP712Core.ChainUidZero`, `NormalTokenCore.X`); imports follow. One-shot."""
import json
import os
import re
import sys

E = json.load(open('script/modules/entries.json'))
ENTRY = {e['name'] for es in E['kinds'].values() for e in es}
FILES = {'SaltedEIP712': 'src/common/SaltedEIP712.sol', 'MetaTxBase': 'src/metatx/MetaTxBase.sol',
         'UAMetaTxBase': 'src/metatx/UAMetaTxBase.sol', 'GovernanceBase': 'src/governance/GovernanceBase.sol'}
KF = {'NormalToken': 'src/metatx', 'WrappedToken': 'src/metatx', 'NormalZetherToken': 'src/zether', 'WrappedZetherToken': 'src/zether',
      'NormalPqzToken': 'src/pqz', 'WrappedPqzToken': 'src/pqz'}
for k in ['NormalRegulatedToken', 'WrappedRegulatedToken', 'NormalZetherRegulatedToken', 'WrappedZetherRegulatedToken',
          'NormalPqzRegulatedToken', 'WrappedPqzRegulatedToken']:
    KF[k] = 'src/regulated'
for k, d in KF.items():
    FILES[k] = f'{d}/{k}Core.sol'
PAT = re.compile(r'(?<![\w.])(' + '|'.join(FILES) + r')\.([A-Za-z_]\w*)')
for path in sys.argv[1:]:
    s = open(path).read()
    used = set()

    def sub(m):
        if m.group(2) in ENTRY or m.group(2) in ('selector',):
            return m.group(0)
        used.add(m.group(1))
        return m.group(1) + 'Core.' + m.group(2)
    s2 = '\n'.join(line if line.strip().startswith(('import', '//', '*')) else PAT.sub(sub, line) for line in s.split('\n'))
    for x in used:
        if re.search(r'import \{[^}]*\b' + x + r'Core\b', s2):
            continue
        rel = os.path.relpath(FILES[x], os.path.dirname(path))
        s2 = re.sub(r'(pragma solidity [^;]+;\n)', r'\1\nimport {' + x + 'Core} from "' + rel + '";\n', s2, count=1)
    if used:
        open(path, 'w').write(s2)
        print(path, sorted(used))
