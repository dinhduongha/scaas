#!/usr/bin/env python3
"""`artifacts.json` = {app: {approval_sha512_256, clear_sha512_256}} of the built programs in `out/` (ruling R7: one
key per deployed app; the test-only Probe is not one). The deploy gate and the node compare a deployed program's
hash with it. `--check`: exit 1 when the committed file differs from the fresh build (test.sh)."""
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APPS = {'token': 'Token', 'account': 'Account'}   # artifacts.json key → puyapy contract name
OUT, FILE = os.path.join(ROOT, 'out'), os.path.join(ROOT, 'artifacts.json')


def h(name, part):
    return hashlib.new('sha512_256', open(os.path.join(OUT, '%s.%s.bin' % (name, part)), 'rb').read()).hexdigest()


doc = {k: {'approval_sha512_256': h(n, 'approval'), 'clear_sha512_256': h(n, 'clear')} for k, n in APPS.items()}
text = json.dumps(doc, indent=1) + '\n'
if '--check' in sys.argv:
    if not os.path.exists(FILE) or open(FILE).read() != text:
        sys.exit('smartcontracts/algorand/artifacts.json differs from the fresh build: run build.sh algorand')
    print('ok artifacts.json')
else:
    open(FILE, 'w').write(text)
    print('wrote artifacts.json')
