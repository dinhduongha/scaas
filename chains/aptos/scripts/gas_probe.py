#!/usr/bin/env python3
"""Đo gas của `meta::relay_pay` trên localnet: chủ ed25519 (ví) và chủ passkey (WebAuthn P-256 kiểm bằng
`bamboo::p256` — UNAUDITED). Ghi file `--json-file` cho `aptos move run` rồi chạy nó bằng profile deployer.

    gas_probe.py <localnet dir>     (sau devnet.sh up && publish; tạo FA BUSD của testfa nếu chưa có)

In ra FeeStatement (execution/io gas units, storage fee octa) của lần chi đầu (mở Account lười) và lần thứ hai.
"""
import hashlib
import importlib
import json
import os
import subprocess
import sys
import time
import types
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
_pkg = types.ModuleType('aptlib')
_pkg.__path__ = [os.path.join(HERE, '..', '..', '..', 'dms_blockchain', 'lib')]
sys.modules['aptlib'] = _pkg
F = importlib.import_module('aptlib.fam_aptos')

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils  # noqa: E402

D = sys.argv[1]
PKG = open(os.path.join(D, 'package.txt')).read().strip()
DEPLOYER = open(os.path.join(D, 'deployer.txt')).read().strip()
BUSD = F.object_address(DEPLOYER, b'BUSD')
ROOT = F.root_of(PKG)
N = F.P256_N


def run(args):
    out = subprocess.run(['aptos', 'move', 'run', '--profile', 'deployer', '--assume-yes'] + args,
                         cwd=os.path.join(D, 'cli'), capture_output=True, text=True)
    if out.returncode:
        sys.exit(out.stdout + out.stderr)
    return json.loads(out.stdout)['Result']


def mint(to, amount):
    run(['--function-id', DEPLOYER + '::coin::mint', '--args', 'hex:42555344', 'address:' + to, 'u64:%d' % amount])


def fee(tx_hash):
    tx = json.load(urllib.request.urlopen('http://127.0.0.1:32010/v1/transactions/by_hash/' + tx_hash))
    [ev] = [e for e in tx['events'] if e['type'] == '0x1::transaction_fee::FeeStatement']
    d = ev['data']
    return {'gas_used': int(tx['gas_used']), 'execution': int(d['execution_gas_units']), 'io': int(d['io_gas_units']),
            'storage_octa': int(d['storage_fee_octas'])}


def pay(owner, pk, sign, ref):
    account = F.account_of(ROOT, owner)
    mint(account, 1000)
    pay_ref, lane = bytes([ref]) * 32, bytes([ref ^ 0xff]) * 32
    vu = int(time.time()) + 300
    payload = F.metaop_bytes(4, account, BUSD, F.OP_PAY, owner, '0xbeef', 10, pay_ref, lane, 0, vu)
    sig, env = sign(F.digest(payload), lane)
    spec = {'function_id': PKG + '::meta::relay_pay', 'type_args': [], 'args': [
        {'type': 'address', 'value': owner}, {'type': 'address', 'value': BUSD}, {'type': 'address', 'value': '0xbeef'},
        {'type': 'u128', 'value': '10'}, {'type': 'hex', 'value': '0x' + pay_ref.hex()},
        {'type': 'hex', 'value': '0x' + lane.hex()}, {'type': 'u64', 'value': '0'}, {'type': 'u64', 'value': str(vu)},
        {'type': 'address', 'value': '0x0'}, {'type': 'hex', 'value': '0x' + bytes(32).hex()},
        {'type': 'hex', 'value': '0x' + pk.hex()}, {'type': 'hex', 'value': '0x' + sig.hex()},
        {'type': 'hex', 'value': '0x' + env.hex()}]}
    path = os.path.join(D, 'gas-%02x.json' % ref)
    json.dump(spec, open(path, 'w'))
    r = run(['--json-file', path, '--max-gas', '2000000'])
    assert r['success'], r
    return fee(r['transaction_hash'])


ed = ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b'gas-ed').digest())
ed_pk = ed.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def ed_sign(dg, lane):
    env = F.minimal_envelope(F.expected_message(dg), lane.hex()).encode()
    return ed.sign(env), env


p = ec.derive_private_key(int.from_bytes(hashlib.sha256(b'gas-passkey').digest(), 'big') % N, ec.SECP256R1())
p_pk = p.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)


def passkey_sign(dg, _lane):
    ad = hashlib.sha256(b'pay.bamboo.test').digest() + b'\x05' + bytes(4)
    cd = json.dumps({'type': 'webauthn.get', 'challenge': F._b64url(dg).decode(), 'origin': 'https://pay.bamboo.test'},
                    separators=(',', ':')).encode()
    r, s = utils.decode_dss_signature(p.sign(ad + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, 'big') + min(s, N - s).to_bytes(32, 'big'), F.webauthn_envelope(ad, cd)


subprocess.run(['aptos', 'account', 'fund-with-faucet', '--profile', 'deployer', '--amount', '1000000000'],
               cwd=os.path.join(D, 'cli'), capture_output=True, check=True)
subprocess.run(['aptos', 'move', 'run', '--profile', 'deployer', '--assume-yes', '--function-id',
                DEPLOYER + '::coin::create', '--args', 'hex:42555344'], cwd=os.path.join(D, 'cli'), capture_output=True)
out = {}
for name, pk, sign, refs in (('ed25519', ed_pk, ed_sign, (0x31, 0x33)), ('passkey', p_pk, passkey_sign, (0x32, 0x34))):
    owner = F.auth_keys(pk)[0]
    out[name] = {'first_pay_opens_account': pay(owner, pk, sign, refs[0]), 'next_pay': pay(owner, pk, sign, refs[1])}
print(json.dumps(out))
