#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""One step of the red-test count (ported from the spike's merge-harness/red_skip.py): read `forge build --format-json`
output, move every test/script file with an error out to `_moved/`, append one JSON line per file to the record.
`red_skip.py <root> <build log> <record>`; prints the count and every file it moved (a src file with an error stops it).
Run on a scratch copy of smartcontracts/evm at M, repeated until the build has no error (`run_red_skip.sh`)."""
import json, os, sys, shutil
root, log, out = sys.argv[1], sys.argv[2], sys.argv[3]
txt = open(log).read()
i = txt.find('{')
d = json.JSONDecoder().raw_decode(txt[i:])[0] if i >= 0 else {}  # forge may print more after the object
errs = [e for e in d.get('errors', []) if e.get('severity') in ('error', 'Error')]
files = {}
for e in errs:
    f = (e.get('sourceLocation') or {}).get('file', '?')
    files.setdefault(f, []).append((e.get('errorCode'), e.get('message', '')[:90]))
print(len(errs), 'errors in', len(files), 'files')
rec = open(out, 'a')
bad = 0
for f, es in sorted(files.items()):
    print(f, len(es), es[0])
    if f.startswith(('test/', 'script/')):
        p = os.path.join(root, f)
        if os.path.exists(p):
            q = os.path.join(root, '_moved', f)
            os.makedirs(os.path.dirname(q), exist_ok=True)
            shutil.move(p, q)
            rec.write(json.dumps({'file': f, 'n': len(es), 'code': es[0][0], 'msg': es[0][1]}) + '\n')
    else:
        print('NOT A TEST FILE', f)
        bad = 1
sys.exit(2 if bad else (0 if errs else 1))
