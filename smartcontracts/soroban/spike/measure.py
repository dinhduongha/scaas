#!/usr/bin/env python3
"""T0 spike network figures (plan UA-Soroban T0): per call `stellar contract invoke … --build-only`, RPC simulateTransaction,
`stellar xdr decode` of the SorobanTransactionData; prints the figures next to the limits read from the network.

usage: measure.py <settings.json>   (env: STELLAR_BIN, SPIKE_ID, SPIKE_RPC, SPIKE_PASSPHRASE, SPIKE_CFG; run by run.sh)
Exit 1 when a GATE call (register_model, msig_model n=3, ua_pay_model) fails to simulate or is over a limit; the other
calls are data (the msig scan, the BLS12-381 primitives, the Zether model: the S13a estimate, Z0 decides)."""
import base64
import json
import os
import subprocess
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
VEC = os.path.join(HERE, '..', '..', 'vectors', 'ua')
STELLAR, CID, RPC = os.environ['STELLAR_BIN'], os.environ['SPIKE_ID'], os.environ['SPIKE_RPC']
NET = ['--rpc-url', RPC, '--network-passphrase', os.environ['SPIKE_PASSPHRASE'], '--config-dir', os.environ['SPIKE_CFG']]


def flat(o, out):
    """Every leaf `key: number` of the settings JSON (key names are unique across the config entries we read)."""
    if isinstance(o, dict):
        for k, v in o.items():
            if isinstance(v, str) and v.lstrip('-').isdigit():
                v = int(v)  # the XDR JSON writes 64-bit integers as strings
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                out.setdefault(k, v)
            flat(v, out)
    elif isinstance(o, list):
        for v in o:
            flat(v, out)
    return out


def cli(*args, stdin=None):
    r = subprocess.run([STELLAR, *args], input=stdin, capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(r.stderr.strip()[-600:])
    return r.stdout.strip()


def invoke(fn, args, build_only=True):
    return cli('contract', 'invoke', '--id', CID, '--source-account', 'spike', *NET,
               *(['--build-only'] if build_only else []), '--', fn, *args)


def rpc(method, params):
    req = urllib.request.Request(RPC, json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(),
                                 {'content-type': 'application/json'})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.load(r)


def find(o, key):
    if isinstance(o, dict):
        for k, v in o.items():
            if k == key:
                return v
            x = find(v, key)
            if x is not None:
                return x
    elif isinstance(o, list):
        for v in o:
            x = find(v, key)
            if x is not None:
                return x
    return None


def n64(b):
    return len(base64.b64decode(b))


def simulate(fn, args):
    env = invoke(fn, args)
    res = rpc('simulateTransaction', {'transaction': env})
    if 'error' in res or res['result'].get('error'):
        raise RuntimeError(str(res.get('error') or res['result']['error'])[-600:])
    r = res['result']
    td = json.loads(cli('xdr', 'decode', '--type', 'SorobanTransactionData', '--input', 'single-base64', '--output',
                        'json', stdin=r['transactionData']))
    res_ = find(td, 'resources')
    fp = res_['footprint']
    auth = sum(n64(a) for x in r.get('results', []) for a in x.get('auth', []))
    written = [n64(c['after']) for c in r.get('stateChanges', []) if c.get('after')]
    cost = r.get('cost') or {}
    return {
        'instructions': res_['instructions'],
        'mem': int(cost['memBytes']) if 'memBytes' in cost else None,
        'read_bytes': res_.get('disk_read_bytes', res_.get('read_bytes')),
        'write_bytes': res_['write_bytes'],
        'entries': len(fp['read_only']) + len(fp['read_write']),
        'writes': len(fp['read_write']),
        # envelope (op args, empty auth) + the SorobanTransactionData + the auth entries + one decorated signature
        'tx_size': n64(env) + n64(r['transactionData']) + auth + 72,
        'largest_entry': max(written, default=0),
        'events': sum(n64(e) for e in r.get('events', [])),  # diagnostic events included: an upper bound
        'fee': int(r['minResourceFee']),
    }


ZETHER_COUNT = """## zether_transfer_model: host operations counted from smartcontracts/evm/src/zether/ZetherVerifier.sol (auditor on)
#   points: 96 B on Soroban (128 B on EVM); every EVM G1MSM (0x0c) becomes one bls12_381_g1_msm (subgroup check inside)
#   transcript (ZetherTranscript.sol): absorb = 1 keccak, challenge = 3 keccak + a 512-bit reduction (2 Fr reductions, 1 mul, 1 add)
#   m = 1, verifyTransfer: ctx absorbs statement (512 + 9P) and sigma (10P), 1 challenge; 2 keccak (Y_f != Y_t);
#          Sigma MSMs E1..E8 = 3,3,4,4,6,4,4,4 points; 2 range proofs
#   m > 1, verifyTransferMulti: statement 512 + 6P + 32 + 4Pm, sigma (6 + 5m)P; 1 + 3m keccak (Y_f, Y_tj, C_aud/D_aud);
#          Sigma MSMs E1 E2 E4 E5 E8 = 3,3,4,6,4 + per leg E3_j E6_j E6'_j E7_j = 4,4,3,4; m + 1 range proofs
#   per range proof (verifyRange, n = 64, k = 6): 9 absorbs + 10 challenges; 7 Fr inversions (y, u_1..u_6);
#          about 540 Fr mul and 330 Fr add/sub (_bp1 sum y^i, _sVector, _bpVectorScalars, _bp2); MSMs of 5 and 144 points
#   not modelled: the token's ciphertext reads / writes and its g1_add updates (Z0 measures the real verifier and token)"""


def main():
    print(ZETHER_COUNT)
    lim = flat(json.load(open(sys.argv[1])), {})
    L = {
        'instructions': lim['tx_max_instructions'],
        'mem': lim['tx_memory_limit'],
        'read_bytes': lim['tx_max_disk_read_bytes'],
        'write_bytes': lim['tx_max_write_bytes'],
        'entries': lim['tx_max_footprint_entries'],
        'writes': lim['tx_max_write_ledger_entries'],
        'tx_size': lim['tx_max_size_bytes'],
        'largest_entry': lim['contract_data_entry_size_bytes'],
        'events': lim['tx_max_contract_events_size_bytes'],
    }
    print('## network limits (stellar network settings):', json.dumps(L))
    print('#   also: ledger_max_instructions=%s contract_max_size_bytes=%s' % (
        lim.get('ledger_max_instructions'), lim.get('contract_max_size_bytes')))

    portable = json.load(open(os.path.join(VEC, 'portable.json')))
    r65 = next(r for r in portable['registrations'] if r['name'] == 'mldsa65#1')
    r44 = next(r for r in portable['registrations'] if r['name'] == 'mldsa44')
    sigs = json.load(open(os.path.join(VEC, 'signatures.json')))
    wa = next(r for r in sigs['derived'] if r['kind'] == 256)
    mt = next(x for x in wa['sigs'] if x['purpose'] == 'metatx')
    h = lambda s: s[2:] if s.startswith('0x') else s
    sig = bytes.fromhex(h(mt['sig']))
    word = lambda o: int.from_bytes(sig[o:o + 32], 'big')
    o1, o2 = word(0), word(32)
    auth_data, cdj = sig[o1 + 32:o1 + 32 + word(o1)], sig[o2 + 32:o2 + 32 + word(o2)]
    kd = bytes.fromhex(h(wa['keyData']))

    # set-up (submitted): 16 mldsa65 member records, the passkey record and its UA balance
    ids = ['%064x' % (int('01' * 32, 16) * i) for i in range(1, 17)]
    for i in ids:
        invoke('seed', ['--id', i, '--kind', '305', '--key_data', h(r65['keyData']), '--pop', h(r65['pop'])], False)
    invoke('seed', ['--kind', '256', '--key_data', kd.hex(), '--pop', ''], False)
    print('## seeded 16 mldsa65 member records and the webauthn-p256 record')

    m65 = ['--pk', h(r65['keyData']), '--msg', h(r65['popMessage']), '--sig', h(r65['pop'])]
    calls = [
        ('GATE', 'register_model mldsa65', 'register_model', m65),
        ('GATE', 'msig_model n=3 mldsa65', 'msig_model', ['--n', '3', '--member_ids', json.dumps(ids[:3])] + m65),
        ('GATE', 'ua_pay_model webauthn-p256', 'ua_pay_model', [
            '--key', '04' + kd[:64].hex(), '--rp_id_hash', kd[64:96].hex(), '--authenticator_data', auth_data.hex(),
            '--client_data_json', cdj.hex(), '--sig', sig[64:128].hex(), '--digest', h(mt['digest'])]),
    ]
    data = [('data', 'msig_model n=%d mldsa65' % n, 'msig_model',
             ['--n', str(n), '--member_ids', json.dumps(ids[:n])] + m65) for n in range(1, 17)]
    data += [('data', 'verify_only %s' % name, 'verify_only',
              ['--kind', str(r['kind']), '--pk', h(r['keyData']), '--msg', h(r['popMessage']), '--sig', h(r['pop'])])
             for name, r in (('mldsa44', r44), ('mldsa65', r65))]
    data += [('data', 'bls_g1_msm n=%d' % n, 'bls_g1_msm', ['--n', str(n)]) for n in (64, 128, 256)]
    data += [('data', 'bls_g2_msm n=%d' % n, 'bls_g2_msm', ['--n', str(n)]) for n in (2, 8)]
    data += [('data', 'bls_pairing pairs=2', 'bls_pairing', ['--n_pairs', '2']),
             ('data', 'bls_add_mul n=1', 'bls_add_mul', ['--n', '1']),
             ('data', 'bls_fr_ops n=100', 'bls_fr_ops', ['--n', '100'])]
    data += [('data', 'zether_transfer_model m=%d' % m, 'zether_transfer_model', ['--m', str(m)]) for m in (1, 2, 4, 8, 16)]

    keys = list(L)
    print('| class | call | ' + ' | '.join(keys) + ' | resource fee (stroops) | verdict |')
    print('|---|---|' + '---|' * (len(keys) + 2))
    print('| limit | network | ' + ' | '.join(str(L[k]) for k in keys) + ' | — | — |')
    bad = 0
    for cls, label, fn, args in calls + data:
        try:
            f = simulate(fn, args)
        except Exception as e:  # noqa: BLE001 — a failed simulation is a figure
            print('| %s | %s | SIMULATION FAILED: %s |' % (cls, label, str(e).replace('\n', ' ')[:300]))
            bad += cls == 'GATE'
            continue
        over = [k for k in keys if f[k] is not None and f[k] > L[k]]
        bad += cls == 'GATE' and bool(over)
        cell = lambda k: 'n/a' if f[k] is None else '%s (%.1f%%)' % (f[k], 100.0 * f[k] / L[k])
        print('| %s | %s | %s | %d | %s |' % (cls, label, ' | '.join(cell(k) for k in keys), f['fee'],
                                            'OVER: ' + ','.join(over) if over else 'within'))
    print('## GATE: %s' % ('FAIL (%d gate call(s) failed or over a limit)' % bad if bad else 'PASS (every UA-Soroban figure within the limits)'))
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()
