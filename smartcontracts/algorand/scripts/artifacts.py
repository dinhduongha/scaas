#!/usr/bin/env python3
"""`artifacts.json` = {app: {approval_sha512_256, clear_sha512_256}} of the built programs in `out/` (ruling R7: one
key per deployed app; the test-only Probe and RelayTarget are not one); "relayfee" also records the executor LogicSig
template (T15): its program is `executor_prefix ‖ router app id (u64 BE) ‖ executor_suffix`, its address the sha512_256 of
"Program" ‖ that (the router derives it on chain; the node and clients the same way). The deploy gate and the node
compare a deployed program's hash with it. `--check`: exit 1 when the committed file differs from the fresh build (test.sh)."""
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APPS = {'token': 'Token', 'account': 'Account', 'mandate': 'Mandate', 'dex': 'Dex', 'relayfee': 'RelayFee'}
# artifacts.json key → puyapy contract name (above)
OUT, FILE = os.path.join(ROOT, 'out'), os.path.join(ROOT, 'artifacts.json')


def h(name, part):
    return hashlib.new('sha512_256', open(os.path.join(OUT, '%s.%s.bin' % (name, part)), 'rb').read()).hexdigest()


doc = {k: {'approval_sha512_256': h(n, 'approval'), 'clear_sha512_256': h(n, 'clear')} for k, n in APPS.items()}
doc['relayfee'].update({'executor_' + p: open(os.path.join(OUT, 'Executor.%s.bin' % p), 'rb').read().hex()
                        for p in ('prefix', 'suffix')})
text = json.dumps(doc, indent=1) + '\n'
if '--check' in sys.argv:
    if not os.path.exists(FILE) or open(FILE).read() != text:
        sys.exit('smartcontracts/algorand/artifacts.json differs from the fresh build: run build.sh algorand')
    print('ok artifacts.json')
else:
    open(FILE, 'w').write(text)
    print('wrote artifacts.json')
