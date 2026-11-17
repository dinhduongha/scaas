#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Re-run solc on a forge build-info with the outputs forge's artifacts drop (generatedSources, functionDebugData).

usage: solc_full.py <evm dir> <out.json> [--solc <path>]
Reads <evm dir>/out/build-info/*.json (the newest), writes solc's standard-json output, deployed contracts only. Checks
that every contract's runtime object equals forge's, so the map attributes the bytes that are measured. UNAUDITED tooling.
"""
import glob, json, os, subprocess, sys

evm, out = sys.argv[1], sys.argv[2]
solc = sys.argv[sys.argv.index('--solc') + 1] if '--solc' in sys.argv else os.path.expanduser('~/.local/share/svm/0.8.37/solc-0.8.37')
bi = max(glob.glob(os.path.join(evm, 'out/build-info/*.json')), key=os.path.getmtime)
d = json.load(open(bi))
inp = {'language': d['input']['language'], 'sources': d['input']['sources'], 'settings': dict(d['input']['settings'])}
inp['settings']['outputSelection'] = {'*': {'': ['ast'], '*': [
    'evm.deployedBytecode.object', 'evm.deployedBytecode.sourceMap', 'evm.deployedBytecode.generatedSources',
    'evm.deployedBytecode.functionDebugData', 'evm.deployedBytecode.linkReferences',
    'evm.deployedBytecode.immutableReferences', 'evm.methodIdentifiers', 'evm.bytecode.object']}}
r = subprocess.run([solc, '--standard-json'], input=json.dumps(inp).encode(), stdout=subprocess.PIPE, check=True)
o = json.loads(r.stdout)
errs = [e for e in o.get('errors', []) if e['severity'] == 'error']
if errs:
    sys.exit('solc errors: ' + json.dumps(errs)[:2000])
# same bytes as forge
bad = 0
for path, cs in d['output']['contracts'].items():
    for name, c in cs.items():
        a = c['evm']['deployedBytecode']['object']
        b = o['contracts'][path][name]['evm']['deployedBytecode']['object']
        if a.removeprefix('0x') != b.removeprefix('0x'):
            bad += 1
            print('DIFFERS', path, name, len(a), len(b))
print('contracts', sum(len(v) for v in o['contracts'].values()), 'differ', bad)
o['source_id_to_path'] = d['source_id_to_path']
json.dump(o, open(out, 'w'))
sys.exit(1 if bad else 0)
