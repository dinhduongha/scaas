#!/usr/bin/env python3
"""T0 spike network figures (plan UA-Soroban T0): per call `stellar contract invoke … --build-only`, RPC simulateTransaction,
`stellar xdr decode` of the SorobanTransactionData; prints the figures next to the limits read from the network.

usage: measure.py <settings.json>   (env: STELLAR_BIN, SPIKE_ID, SPIKE_TOKEN, SPIKE_RPC, SPIKE_PASSPHRASE, SPIKE_CFG; run.sh)
       measure.py fixture <out.json> (the msig n = 3 fixture of the unit tests)
Exit 1 when a GATE call (register_model, msig_model n=3, ua_pay_model) fails to simulate or is over a limit; the other
calls are data (the msig scan, the BLS12-381 primitives, the Zether model: the S13a estimate, Z0 decides).
B0 (plan ua8-soroban B0, C12): GATE = per parameter set the single-key mldsa65 `register` with PQZ + KEM split from its
proof and the `store_pqz_pop` that follows, and single-key `set_kem_key` / `set_pqz_key`; data = the full single-key
`register`, the msig rows (the largest n is published as the Soroban maximum, not a STOP) and the keccak256 cost.

Fixtures made here (portable.json holds one mldsa65 key): 16 ML-DSA-65 member keys from fixed seeds
keccak256("scaas.t0.member" ‖ i) and a P-256 passkey from a fixed scalar, signed with `cryptography` (OpenSSL ML-DSA,
pure FIPS 204, empty context; ECDSA low-s). Member and WebAuthn signatures are made per run (the passkey signs the op
digest, which binds the deployed token address)."""
import base64
import hashlib
import json
import os
import site
import subprocess
import sys
import urllib.request

# cryptography >= 48 (ML-DSA) and pycryptodome are user installs; -I drops the user site, so put it back first
sys.path.insert(0, site.getusersitepackages())
from Crypto.Hash import keccak  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, mldsa  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
VEC = os.path.join(HERE, '..', '..', 'vectors', 'ua')
ENV = os.environ
NET = []
if 'SPIKE_RPC' in ENV:
    STELLAR, RPC, CFG = ENV['STELLAR_BIN'], ENV['SPIKE_RPC'], ENV['SPIKE_CFG']
    NET = ['--rpc-url', RPC, '--network-passphrase', ENV['SPIKE_PASSPHRASE'], '--config-dir', CFG]

K_WEBAUTHN, K_MSIG, K_MLDSA65 = 0x0100, 0x0120, 0x0131
TAG = {K_WEBAUTHN: b'scaas.ua.webauthn-p256.v1', K_MSIG: b'scaas.ua.msig.v1', K_MLDSA65: b'scaas.ua.mldsa65.v1'}
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def k256(b):
    return keccak.new(digest_bits=256, data=b).digest()


def tagged(kind, x):
    return k256(k256(TAG[kind]) + x)


def ua_msg(kind, purpose, digest):
    return k256(k256(b'scaas.ua.msg.v1') + k256(TAG[kind]) + k256(purpose) + digest)


def w(v):
    return v.to_bytes(32, 'big')


def dyn(b):
    return w(len(b)) + b + bytes(-len(b) % 32)


def member_sigs(items):
    """abi.encode(MemberSig[]) of (index, keyData, sig) (UA8-D5)."""
    tuples = [w(i) + w(96) + w(96 + 32 + len(kd) + (-len(kd) % 32)) + dyn(kd) + dyn(sig) for i, kd, sig in items]
    offs, o = b'', 32 * len(items)
    for t in tuples:
        offs, o = offs + w(o), o + len(t)
    return w(32) + w(len(items)) + offs + b''.join(tuples)


def members():
    """16 ML-DSA-65 members sorted by their CTR-UA-04 id: (id, sk, pk, pop for the seeded record)."""
    out = []
    for i in range(16):
        sk = mldsa.MLDSA65PrivateKey.from_seed_bytes(k256(b'scaas.t0.member' + bytes([i])))
        pk = sk.public_key().public_bytes_raw()
        out.append((tagged(K_MLDSA65, pk), sk, pk, sk.sign(b'scaas.t0.member-pop')))
    return sorted(out, key=lambda m: m[0])


MSIG_MSG = k256(b'scaas.t0.msig-pop')  # stands for the msig's uaMessage(MSIG, PURPOSE_POP_V2, registrationDigest)


def msig(ms, with_keys=False):
    """(key_data, pop) of an msig over registered members `ms`, threshold = count, weight 1 each (CTR-UA-09, spec §3):
    every MemberSig keyData empty (owner ruling 2026-10-30); `with_keys` builds the refused pre-ruling form."""
    n = len(ms)
    kd = n.to_bytes(2, 'big') + n.to_bytes(2, 'big') + b''.join(
        K_MLDSA65.to_bytes(2, 'big') + mid + (1).to_bytes(2, 'big') for mid, *_ in ms)
    member_digest = k256(tagged(K_MSIG, kd) + MSIG_MSG)
    pq = tagged(K_MLDSA65, ua_msg(K_MLDSA65, b'scaas.ua.purpose.member.v1', member_digest))
    return kd, member_sigs([(i, pk if with_keys else b'', sk.sign(pq)) for i, (_, sk, pk, _) in enumerate(ms)])


# --- B0 (plan ua8-soroban B0): the full PQZ + KEM registration, the split, set_kem_key, set_pqz_key ---
SETS = ('n2048-kmax1024', 'n2304-kmax4096', 'n2560-kmax16384', 'n2816-kmax65536')
POP_V2, KEM, PQZ_KEY = b'scaas.ua.purpose.pop.v2', b'scaas.ua.purpose.kem.v1', b'scaas.ua.purpose.pqz-key.v1'
GROUP_PQZ = k256(b'scaas.ua.group.pqz-mlwe.v1')


def attrs_json(a):
    """`UaAttrs` as the CLI's JSON (hex bytes) from a portable.json `attrs` (or None = empty attributes)."""
    a = a or {'pqzKey': '0x', 'pqzPopHash': '0x' + '00' * 32, 'kemVersion': 0, 'kemPk': '0x'}
    return {'pqz_key': a['pqzKey'][2:], 'pqz_pop_hash': a['pqzPopHash'][2:], 'kem_version': a['kemVersion'],
            'kem_pk': a['kemPk'][2:]}


def kem_record_digest(ua, version, kem_pk):
    return k256(k256(b'scaas.ua.kem-record.v1') + ua + w(version) + k256(kem_pk))


def reg_digest(ua, a):
    """UA8-D1 registration digest of portable.json `attrs` `a` (None = none)."""
    if not a:
        return k256(k256(k256(POP_V2) + ua + bytes(64)) + bytes(32))
    pk = bytes.fromhex(a['pqzKey'][2:])
    pqz_key_hash = k256(GROUP_PQZ + pk) if pk else bytes(32)
    kem = kem_record_digest(ua, a['kemVersion'], bytes.fromhex(a['kemPk'][2:])) if a['kemVersion'] else bytes(32)
    return k256(k256(k256(POP_V2) + ua + pqz_key_hash + kem) + bytes.fromhex(a['pqzPopHash'][2:]))


def ua_sig(signers, ua, purpose, digest):
    """The stored signature of a UA over `ua_message(kind, purpose, digest)`: a single ML-DSA-65 signer (`signers` =
    (sk,)) or an msig whose every member signs (`signers` = members, threshold reached only by all: minimal)."""
    if len(signers) == 1:
        return signers[0].sign(tagged(K_MLDSA65, ua_msg(K_MLDSA65, purpose, digest)))
    md = k256(ua + ua_msg(K_MSIG, purpose, digest))
    pq = tagged(K_MLDSA65, ua_msg(K_MLDSA65, b'scaas.ua.purpose.member.v1', md))
    return member_sigs([(i, b'', sk.sign(pq)) for i, (_, sk, _, _) in enumerate(signers)])


def msig_kd(ms, weight=1):
    """CTR-UA-09 key data and id of an msig over `ms`, every member `weight`, threshold = the total (minimal)."""
    n = len(ms)
    kd = (n * weight).to_bytes(2, 'big') + n.to_bytes(2, 'big') + b''.join(
        K_MLDSA65.to_bytes(2, 'big') + mid + weight.to_bytes(2, 'big') for mid, *_ in ms)
    return kd, tagged(K_MSIG, kd)


PASSKEY = ec.derive_private_key(int.from_bytes(k256(b'scaas.t0.passkey'), 'big') % P256_N, ec.SECP256R1())
RP_HASH = hashlib.sha256(b'scaas.example').digest()


def passkey_kd():
    pn = PASSKEY.public_key().public_numbers()
    return pn.x.to_bytes(32, 'big') + pn.y.to_bytes(32, 'big') + RP_HASH


def webauthn_auth(m):
    """abi.encode(bytes authenticatorData, string clientDataJSON, uint256 r, uint256 s) over ua_msg `m`."""
    ch = base64.urlsafe_b64encode(m).rstrip(b'=').decode()
    cdj = ('{"type":"webauthn.get","challenge":"%s","origin":"https://scaas.example","crossOrigin":false}' % ch).encode()
    ad = RP_HASH + b'\x05' + (1).to_bytes(4, 'big')
    r, s = decode_dss_signature(PASSKEY.sign(ad + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256())))
    s = min(s, P256_N - s)
    return w(128) + w(128 + len(dyn(ad))) + w(r) + w(s) + dyn(ad) + dyn(cdj)


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


def cli(*args, stdin=None):
    r = subprocess.run([STELLAR, *args], input=stdin, capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(r.stderr.strip()[-600:])
    return r.stdout.strip()


def argv(args):
    """A `bytes` value goes through `--<name>-file-path` (raw bytes, empty allowed; an argument may not exceed 128 KiB),
    a `dict` (a contract struct, B0's `UaAttrs`) the same way as JSON."""
    out = []
    for a in args:
        if isinstance(a, (bytes, dict)):
            p = os.path.join(CFG, 'arg%d.bin' % len(out))
            with open(p, 'wb') as f:
                f.write(a if isinstance(a, bytes) else json.dumps(a).encode())
            out[-1] += '-file-path'
            out.append(p)
        else:
            out.append(a)
    return out


def invoke(cid, fn, args, mode='build'):
    flag = {'build': ['--build-only'], 'send': [], 'view': ['--send=no']}[mode]
    return cli('contract', 'invoke', '--id', cid, '--source-account', 'spike', *NET, *flag, '--', fn, *argv(args))


class SimError(Exception):
    """The network refused the simulation (a figure), as opposed to a bug in this script."""


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


def contract_event_size(b64):
    """XDR size of the ContractEvent inside a DiagnosticEvent when its type is CONTRACT (1), else 0."""
    raw = base64.b64decode(b64)
    off = 8  # bool inSuccessfulContractCall, ContractEvent.ext
    off += 4 + 32 * int.from_bytes(raw[off:off + 4], 'big')  # ContractID* contractID
    return len(raw) - 4 if int.from_bytes(raw[off:off + 4], 'big') == 1 else 0


def simulate(cid, fn, args):
    env = invoke(cid, fn, args)
    res = rpc('simulateTransaction', {'transaction': env})
    if 'error' in res or res['result'].get('error'):
        raise SimError(str(res.get('error') or res['result']['error'])[-600:])
    r = res['result']
    td = json.loads(cli('xdr', 'decode', '--type', 'SorobanTransactionData', '--input', 'single-base64', '--output',
                        'json', stdin=r['transactionData']))
    res_ = find(td, 'resources')
    fp = res_['footprint']
    auth = sum(n64(a) for x in r.get('results', []) for a in x.get('auth', []))
    written = [n64(c['after']) for c in r.get('stateChanges', []) if c.get('after')]
    cost = r.get('cost') or {}
    evs = r.get('events', [])
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
        # what tx_max_contract_events_size_bytes limits: the contract events plus the return value
        'events': sum(contract_event_size(e) for e in evs) + sum(n64(x['xdr']) for x in r.get('results', [])),
        'diag_events': sum(n64(e) for e in evs),  # every simulation event, diagnostic ones included (no limit)
        'fee': int(r['minResourceFee']),
    }


def fixture(path):
    ms = members()[:3]
    kd, pop = msig(ms)
    _, pop_keys = msig(ms, with_keys=True)
    with open(path, 'w') as f:
        json.dump({'note': 'measure.py fixture: msig n = 3 of ML-DSA-65 members (see measure.py docstring)',
                   'members': [{'pk': pk.hex(), 'pop': p.hex()} for _, _, pk, p in ms],
                   'key_data': kd.hex(), 'msg': MSIG_MSG.hex(), 'pop': pop.hex(),
                   'pop_with_key_data': pop_keys.hex()}, f, indent=1)
        f.write('\n')


def main():
    if sys.argv[1] == 'fixture':
        return fixture(sys.argv[2])
    reg, tok = ENV['SPIKE_ID'], ENV['SPIKE_TOKEN']
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
    print('#   also: ledger_max_instructions=%s contract_max_size_bytes=%s tx_max_disk_read_entries=%s' % (
        lim.get('ledger_max_instructions'), lim.get('contract_max_size_bytes'), lim.get('tx_max_disk_read_entries')))
    print('#   events = contract events + return value (the limited figure); diag_events = all simulation events, no limit')

    portable = json.load(open(os.path.join(VEC, 'portable.json')))
    r65 = next(r for r in portable['registrations'] if r['name'] == 'mldsa65#1')
    r44 = next(r for r in portable['registrations'] if r['name'] == 'mldsa44')
    h = lambda s: s[2:] if s.startswith('0x') else s

    # set-up (submitted): 16 mldsa65 member records, the passkey record, the payer's UA balance
    ms = members()
    for _, _, pk, pop in ms:
        invoke(reg, 'seed', ['--kind', str(K_MLDSA65), '--key_data', pk, '--pop', json.dumps(pop.hex())], 'send')
    kd = passkey_kd()
    frm, to = tagged(K_WEBAUTHN, kd), ms[0][0]
    invoke(reg, 'seed', ['--kind', str(K_WEBAUTHN), '--key_data', kd.hex()], 'send')
    invoke(tok, 'mint_ua', ['--ua', frm.hex(), '--amount', '1000000000'], 'send')
    print('## seeded 16 mldsa65 member records, the webauthn-p256 payer (receiver: an mldsa65 UA) and its balance')
    pay = ['--from', frm.hex(), '--to', json.dumps({'Ua': to.hex()}), '--amount', '1',
           '--pay_ref', k256(b'scaas.t0.pay-ref').hex(), '--valid_until', '4102444800']
    digest = bytes.fromhex(json.loads(invoke(tok, 'pay_digest', pay, 'view')))
    auth = webauthn_auth(ua_msg(K_WEBAUTHN, b'scaas.ua.purpose.metatx.v1', digest))

    m65 = ['--pk', h(r65['keyData']), '--msg', h(r65['popMessage']), '--sig', h(r65['pop'])]

    def msig_args(n):
        mkd, mpop = msig(ms[:n])
        return ['--key_data', mkd, '--msg', MSIG_MSG.hex(), '--pop', mpop]

    calls = [
        ('GATE', 'register_model mldsa65', reg, 'register_model', m65),
        ('GATE', 'msig_model n=3 mldsa65', reg, 'msig_model', msig_args(3)),
        ('GATE', 'ua_pay_model webauthn-p256 -> mldsa65 UA', tok, 'ua_pay_model', pay + ['--auth', auth.hex()]),
    ]
    data = [('data', 'msig_model n=%d mldsa65' % n, reg, 'msig_model', msig_args(n)) for n in range(1, 17)]
    data += [('data', 'verify_only %s' % name, reg, 'verify_only',
              ['--kind', str(r['kind']), '--pk', h(r['keyData']), '--msg', h(r['popMessage']), '--sig', h(r['pop'])])
             for name, r in (('mldsa44', r44), ('mldsa65', r65))]
    data += [('data', 'bls_g1_msm n=%d' % n, reg, 'bls_g1_msm', ['--n', str(n)]) for n in (64, 128, 256)]
    data += [('data', 'bls_g2_msm n=%d' % n, reg, 'bls_g2_msm', ['--n', str(n)]) for n in (2, 8)]
    data += [('data', 'bls_pairing pairs=2', reg, 'bls_pairing', ['--n_pairs', '2']),
             ('data', 'bls_add_mul n=1', reg, 'bls_add_mul', ['--n', '1']),
             ('data', 'bls_fr_ops n=100', reg, 'bls_fr_ops', ['--n', '100'])]
    data += [('data', 'zether_transfer_model m=%d' % m, reg, 'zether_transfer_model', ['--m', str(m)])
             for m in (1, 2, 4, 8)]

    # B0 targets (submitted): per set a fresh single ML-DSA-65 UA registered split (PQZ key + KEM v1, no proof) for
    # store_pqz_pop; an msig of 16 registered split at n2816-kmax65536 (weight 3); an msig of 16 without attributes
    # (weight 2, another id) and member 0's seeded record for set_kem_key / set_pqz_key
    rows = {x: next(r for r in portable['registrations'] if r['name'] == 'mldsa65/' + x) for x in SETS}
    b0, singles = [], {}
    for x in SETS:
        sk = mldsa.MLDSA65PrivateKey.from_seed_bytes(k256(b'scaas.b0.single' + x.encode()))
        pk = sk.public_key().public_bytes_raw()
        ua, a = tagged(K_MLDSA65, pk), rows[x]['attrs']
        invoke(reg, 'register_pqz_kem_model', ['--kind', str(K_MLDSA65), '--key_data', pk, '--attrs', attrs_json(a),
               '--pop', ua_sig((sk,), ua, POP_V2, reg_digest(ua, a)), '--pqz_pop', b''], 'send')
        singles[x] = ua
    a16 = rows[SETS[-1]]['attrs']
    kd16, ua16 = msig_kd(ms, 3)  # weight 3: not the weight-1 msig the register rows simulate
    invoke(reg, 'register_pqz_kem_model', ['--kind', str(K_MSIG), '--key_data', kd16, '--attrs', attrs_json(a16),
           '--pop', ua_sig(ms, ua16, POP_V2, reg_digest(ua16, a16)), '--pqz_pop', b''], 'send')
    kd16e, ua16e = msig_kd(ms, 2)
    invoke(reg, 'register_pqz_kem_model', ['--kind', str(K_MSIG), '--key_data', kd16e, '--attrs', attrs_json(None),
           '--pop', ua_sig(ms, ua16e, POP_V2, reg_digest(ua16e, None)), '--pqz_pop', b''], 'send')
    print('## B0: registered (split) 4 single mldsa65 UAs (one per set) and an msig of 16 at %s; an msig of 16 without '
          'attributes' % SETS[-1])

    def reg_args(x, n, split, kd=None):
        """`register_pqz_kem_model` of set `x`: n = 0 the portable.json mldsa65/<set> row, else an msig of n."""
        r = rows[x]
        pqz_pop = b'' if split else bytes.fromhex(r['pqzPop'][2:])
        if n == 0:
            return ['--kind', str(K_MLDSA65), '--key_data', h(r['keyData']), '--attrs', attrs_json(r['attrs']),
                    '--pop', bytes.fromhex(h(r['pop'])), '--pqz_pop', pqz_pop]
        mkd, ua = msig_kd(ms[:n])
        return ['--kind', str(K_MSIG), '--key_data', mkd, '--attrs', attrs_json(r['attrs']),
                '--pop', ua_sig(ms[:n], ua, POP_V2, reg_digest(ua, r['attrs'])), '--pqz_pop', pqz_pop]

    def reg_label(x, n, split):
        return 'B0 register %s %s %s' % ('mldsa65' if n == 0 else 'msig n=%d' % n, x, 'split' if split else 'full')

    for x in SETS:
        b0.append(('data', reg_label(x, 0, False), reg, 'register_pqz_kem_model', reg_args(x, 0, False)))
        b0.append(('GATE', reg_label(x, 0, True), reg, 'register_pqz_kem_model', reg_args(x, 0, True)))
        b0.append(('GATE', 'B0 store_pqz_pop mldsa65 %s' % x, reg, 'store_pqz_pop_model',
                   ['--ua', singles[x].hex(), '--pqz_pop', bytes.fromhex(rows[x]['pqzPop'][2:])]))
        for n in (2, 4, 8, 16):
            for split in (False, True):
                b0.append(('data', reg_label(x, n, split), reg, 'register_pqz_kem_model', reg_args(x, n, split)))
    b0.append(('data', 'B0 store_pqz_pop msig n=16 %s' % SETS[-1], reg, 'store_pqz_pop_model',
               ['--ua', ua16.hex(), '--pqz_pop', bytes.fromhex(rows[SETS[-1]]['pqzPop'][2:])]))
    kem_pk = bytes.fromhex(a16['kemPk'][2:])
    pqz_key, pqz_pop_hash = bytes.fromhex(a16['pqzKey'][2:]), bytes.fromhex(a16['pqzPopHash'][2:])
    for cls, who, ua, signers in (('GATE', 'mldsa65', ms[0][0], (ms[0][1],)), ('data', 'msig n=16', ua16e, ms)):
        b0.append((cls, 'B0 set_kem_key v1 %s' % who, reg, 'set_kem_key_model',
                   ['--ua', ua.hex(), '--version', '1', '--kem_pk', kem_pk,
                    '--sig', ua_sig(signers, ua, KEM, kem_record_digest(ua, 1, kem_pk))]))
        kdig = k256(k256(b'scaas.ua.pqz-key-record.v1') + ua + k256(GROUP_PQZ + pqz_key))
        b0.append((cls, 'B0 set_pqz_key %s %s' % (SETS[-1], who), reg, 'set_pqz_key_model',
                   ['--ua', ua.hex(), '--pqz_key', pqz_key, '--pqz_pop_hash', pqz_pop_hash.hex(),
                    '--sig', ua_sig(signers, ua, PQZ_KEY, k256(kdig + pqz_pop_hash))]))
    keccaks = [(1, 64), (100, 64), (100, 256), (1, 8192)]
    b0 += [('data', 'B0 keccak_model n=%d len=%d' % nl, reg, 'keccak_model', ['--n', str(nl[0]), '--len', str(nl[1])])
           for nl in keccaks]

    keys = list(L)
    print('| class | call | ' + ' | '.join(keys) + ' | diag_events | resource fee (stroops) | verdict |')
    print('|---|---|' + '---|' * (len(keys) + 3))
    print('| limit | network | ' + ' | '.join(str(L[k]) for k in keys) + ' | — | — | — |')
    bad, msig_fit, msig_stop, gate_over, res = 0, 0, None, [], {}
    for cls, label, cid, fn, args in calls + data + b0:
        scan = cls == 'data' and fn == 'msig_model'
        n = len(args[1]) // 36 if scan else 0  # key data 4 + 36n
        try:
            f = simulate(cid, fn, args)
        except SimError as e:  # the network refused it: a figure
            print('| %s | %s | SIMULATION FAILED: %s |' % (cls, label, str(e).replace('\n', ' ')[:300]))
            bad += cls == 'GATE'
            res[label] = (None, ['simulation failed'])
            if scan and msig_stop is None:
                msig_stop = (n, ['simulation failed'])
            continue
        except Exception as e:  # noqa: BLE001 — a bug in building or reading the call, not a figure
            print('| %s | %s | MEASURE ERROR (script): %s |' % (cls, label, str(e).replace('\n', ' ')[:300]))
            bad += cls == 'GATE'
            continue
        over = [k for k in keys if f[k] is not None and f[k] > L[k]]
        res[label] = (f, over)
        bad += cls == 'GATE' and bool(over)
        if cls == 'GATE' and over:
            gate_over.append((label, cid, fn, args))
        if scan and msig_stop is None:
            if over:
                msig_stop = (n, over)
            else:
                msig_fit = n
        cell = lambda k: 'n/a' if f[k] is None else '%s (%.1f%%)' % (f[k], 100.0 * f[k] / L[k])
        print('| %s | %s | %s | %d | %d | %s |' % (cls, label, ' | '.join(cell(k) for k in keys), f['diag_events'],
                                                 f['fee'], 'OVER: ' + ','.join(over) if over else 'within'))
    print('## msig_model scan (data): largest n in 1..16 that fits every limit: %d; first over: %s' % (
        msig_fit, 'n=%d (%s)' % (msig_stop[0], ','.join(msig_stop[1])) if msig_stop else 'none up to 16'))
    print('## B0 (UA8-D21 case per set; GATE = the single-key split register + store_pqz_pop, C12):')
    fits = lambda label: label in res and res[label][0] is not None and not res[label][1]
    for x in SETS:
        single = 'full in one register' if fits(reg_label(x, 0, False)) else (
            'split (store_pqz_pop separately)' if fits(reg_label(x, 0, True)) else 'STOP: over even after the split')
        largest = {}
        for split in (False, True):
            ok = [n for n in (2, 4, 8, 16) if fits(reg_label(x, n, split))]
            n = max(ok, default=0)
            if n in (2, 4, 8):  # the next measured n is over: scan the n between (data)
                for m in range(n + 1, 2 * n):
                    label = reg_label(x, m, split)
                    try:
                        f = simulate(reg, 'register_pqz_kem_model', reg_args(x, m, split))
                    except Exception as e:  # noqa: BLE001
                        print('| data | %s | SIMULATION FAILED: %s |' % (label, str(e).replace('\n', ' ')[:300]))
                        break
                    over = [k for k in keys if f[k] is not None and f[k] > L[k]]
                    print('| data | %s | %s |' % (label, 'OVER: ' + ','.join(over) if over else 'within'))
                    if over:
                        break
                    n = m
            largest[split] = n
        print('##   %s: single mldsa65 %s; largest msig n (ML-DSA-65 members) with PQZ + KEM: %d in one register, %d with '
              'the split' % (x, single, largest[False], largest[True]))
    k = {nl: res.get('B0 keccak_model n=%d len=%d' % nl, (None,))[0] for nl in keccaks}
    if all(k.values()):
        top = max((f['instructions'], label) for label, (f, _) in res.items() if f and label.startswith('B0 register'))
        per = {ln: (k[(100, ln)]['instructions'] - k[(1, 64)]['instructions']) / 99 for ln in (64, 256)}
        print('##   keccak256 on the network: ~%d instructions per 64 B hash, ~%d per 256 B hash; the costliest B0 register '
              '(%s) uses %d of %d instructions: headroom ~%d hashes of 256 B' % (
                  per[64], per[256], top[1], top[0], L['instructions'], (L['instructions'] - top[0]) // per[256]))
    for label, cid, fn, args in gate_over:  # simulation does not refuse every limit: submit the call to show the outcome
        try:
            invoke(cid, fn, args, 'send')
            print('## submitted %s: the network ACCEPTED it' % label)
        except RuntimeError as e:
            print('## submitted %s: the network refused it: %s' % (label, str(e).replace('\n', ' ')[-300:]))
    print('## GATE: %s' % ('FAIL (%d gate call(s) failed or over a limit)' % bad if bad else 'PASS (every UA-Soroban and B0 gate figure within the limits)'))
    sys.exit(1 if bad else 0)


if __name__ == '__main__':
    main()
