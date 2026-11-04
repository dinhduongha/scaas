#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T0 of the ua*/mtx* merge plan: one run's sizes. Reads `forge build src --sizes --json` output and the built artifacts,
writes `sizes-<run>.json` (runtime and init bytes of the contracts T0 lists, plus the wallets' runtime hash with the CBOR
metadata stripped). Run from smartcontracts/evm after the build: `sizes.py <forge-json> <run>`.
"""
import hashlib, json, os, sys

NAMES = ['NormalToken', 'WrappedToken', 'NormalZetherToken', 'WrappedZetherToken', 'NormalPqzToken', 'WrappedPqzToken',
         'SCaaSDex', 'GovernanceRouter', 'MtxRelayFee', 'MtxPipelineLib', 'WrappedLib', 'ZetherLib', 'ZetherWrappedLib',
         'PqzWrappedLib', 'TradeLib', 'GovernanceLib', 'TokenBodyLib', 'MandateWallet', 'SmartKeyAccount',
         'RegNormalToken', 'RegWrappedToken']
WALLETS = ['MandateWallet', 'SmartKeyAccount']


def stripped_hash(name):
    """Runtime bytecode without its CBOR metadata tail (its length is the last two bytes)."""
    a = json.load(open(os.path.join('out', name + '.sol', name + '.json')))
    code = bytes.fromhex(a['deployedBytecode']['object'][2:])
    n = int.from_bytes(code[-2:], 'big')
    return hashlib.sha256(code[:-(n + 2)]).hexdigest()[:16]


def main():
    src, run = sys.argv[1], sys.argv[2]
    txt = open(src).read()
    d = json.loads(txt[txt.find('{'):])
    out = {n: {'runtime': d[n]['runtime_size'], 'init': d[n]['init_size']} for n in NAMES if n in d}
    for n in NAMES:  # forge leaves out a library with unlinked references: its artifact (a link slot is 20 bytes)
        f = os.path.join('out', n + '.sol', n + '.json')
        src = [r for r, _, fs in os.walk('src') if n + '.sol' in fs]  # a stale artifact of a removed file does not count
        if n not in out and src and os.path.exists(f):
            a = json.load(open(f))
            rt, ini = a['deployedBytecode']['object'][2:], a['bytecode']['object'][2:]
            if rt:
                out[n] = {'runtime': len(rt) // 2, 'init': len(ini) // 2, 'from': 'artifact'}
    for w in WALLETS:
        if w in out:
            out[w]['code_sha256_16_no_metadata'] = stripped_hash(w)
    here = os.path.dirname(os.path.abspath(__file__))
    json.dump(out, open(os.path.join(here, 'sizes-' + run + '.json'), 'w'), indent=1, sort_keys=True)
    for n, v in out.items():
        print(f"{run} | {n} | {v['runtime']} | {v['init']} | {v.get('code_sha256_16_no_metadata', '')}")


if __name__ == '__main__':
    main()
