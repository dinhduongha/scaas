#!/usr/bin/env python3
"""Đo gas của `meta::relay_pay` trên localnet: chủ ed25519 (ví) và chủ passkey (WebAuthn P-256 kiểm bằng
`scaas::p256` — UNAUDITED). Ghi file `--json-file` cho `aptos move run` rồi chạy nó bằng profile deployer.

    gas_probe.py <localnet dir>     (sau devnet.sh up && publish; tạo FA BUSD của testfa nếu chưa có)

In ra FeeStatement (execution/io gas units, storage fee octa) của lần chi đầu (mở Account lười) và lần thứ hai, và
của một `dex::settle` khớp HAI lệnh ký bằng passkey (trường hợp nặng nhất: hai lần kiểm P-256 trong một tx).

Chặn (review L4): thoát mã 1 nếu execution gas vượt `GUARD` — trần một tx là 9 200; `settle` hai passkey đã dùng ~88 %,
thêm logic hay Aptos đổi bảng gas là lệnh khớp passkey sẽ `EXECUTION_LIMIT_REACHED` (job `Reverted`, không thử lại).
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
_pkg.__path__ = [os.path.join(HERE, '..', '..', '..', '..', '..', 'dms_blockchain', 'lib')]
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


def pay(owner, pk, sign, ref, profile=False):
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
    if profile:   # mô phỏng cục bộ có profiler gas (báo cáo HTML ở cli/gas-profiling/)
        return run(['--json-file', path, '--max-gas', '2000000', '--profile-gas'])
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


def passkey_sign(dg, _lane, key=None):
    key = key or p
    ad = hashlib.sha256(b'pay.scaas.test').digest() + b'\x05' + bytes(4)
    cd = json.dumps({'type': 'webauthn.get', 'challenge': F._b64url(dg).decode(), 'origin': 'https://pay.scaas.test'},
                    separators=(',', ':')).encode()
    r, s = utils.decode_dss_signature(key.sign(ad + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, 'big') + min(s, N - s).to_bytes(32, 'big'), F.webauthn_envelope(ad, cd)


subprocess.run(['aptos', 'account', 'fund-with-faucet', '--profile', 'deployer', '--amount', '1000000000'],
               cwd=os.path.join(D, 'cli'), capture_output=True, check=True)
subprocess.run(['aptos', 'move', 'run', '--profile', 'deployer', '--assume-yes', '--function-id',
                DEPLOYER + '::coin::create', '--args', 'hex:42555344'], cwd=os.path.join(D, 'cli'), capture_output=True)
out = {}
for name, pk, sign, refs in (('ed25519', ed_pk, ed_sign, (0x31, 0x33)), ('passkey', p_pk, passkey_sign, (0x32, 0x34))):
    owner = F.auth_keys(pk)[0]
    out[name] = {'first_pay_opens_account': pay(owner, pk, sign, refs[0]), 'next_pay': pay(owner, pk, sign, refs[1])}
# DEX: hai chủ passkey (A đã mở ở trên; B mở bằng một pay), market BUSD/BEUR, settle hai lệnh passkey.
p2 = ec.derive_private_key(int.from_bytes(hashlib.sha256(b'gas-passkey-2').digest(), 'big') % N, ec.SECP256R1())
p2_pk = p2.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
a_owner, b_owner = F.auth_keys(p_pk)[0], F.auth_keys(p2_pk)[0]
pay(b_owner, p2_pk, lambda dg, lane: passkey_sign(dg, lane, p2), 0x36)
run(['--function-id', DEPLOYER + '::coin::create', '--args', 'hex:42455552'])
BEUR = F.object_address(DEPLOYER, b'BEUR')
run(['--function-id', DEPLOYER + '::coin::mint', '--args', 'hex:42455552', 'address:' + F.account_of(ROOT, b_owner), 'u64:1000'])
mint(F.account_of(ROOT, a_owner), 1000)
DEX = F.dex_of(ROOT)
MARKET = F.market_of(DEX, BUSD, BEUR)
run(['--function-id', PKG + '::dex::create_dex'])
run(['--function-id', PKG + '::dex::list_market', '--args', 'address:' + BUSD, 'address:' + BEUR, 'bool:true',
     'bool:false', 'u32:0', 'u32:0', 'address:0x0'])
expiry = int(time.time()) + 300


def order(maker, sell, buy, sell_amount, buy_amount, nonce):
    return (F.vec(b'scaas.order.v1') + bytes([4]) + F.addr(MARKET) + F.addr(maker) + F.addr('0x0') + F.addr(sell)
            + F.addr(buy) + sell_amount.to_bytes(8, 'little') + buy_amount.to_bytes(8, 'little')
            + nonce.to_bytes(16, 'little') + expiry.to_bytes(8, 'little') + (10000).to_bytes(4, 'little') + b'\x00'
            + F.addr('0x0'))


mo, to_ = order(a_owner, BUSD, BEUR, 100, 100, 1), order(b_owner, BEUR, BUSD, 100, 100, 1)
msig, menv = passkey_sign(F.sha3(mo), None, p)
tsig, tenv = passkey_sign(F.sha3(to_), None, p2)
hx = lambda b: {'type': 'hex', 'value': '0x' + b.hex()}  # noqa: E731
spec = {'function_id': PKG + '::dex::settle', 'type_args': [], 'args': [
    {'type': 'address', 'value': MARKET}, hx(mo), hx(p_pk), hx(msig), hx(menv), hx(to_), hx(p2_pk), hx(tsig), hx(tenv),
    {'type': 'u64', 'value': '100'}, {'type': 'u64', 'value': '100'}, hx(b'gas-probe')]}
path = os.path.join(D, 'gas-settle.json')
json.dump(spec, open(path, 'w'))
r = run(['--json-file', path, '--max-gas', '2000000'])
assert r['success'], r
out['dex_settle_two_passkeys'] = fee(r['transaction_hash'])
if os.environ.get('PROFILE'):
    out['profile'] = pay(F.auth_keys(p_pk)[0], p_pk, passkey_sign, 0x35, profile=True)
print(json.dumps(out))
# execution gas units; trần một tx 9 200 (`txn.max_execution_gas`). Nâng ngưỡng phải ghi lý do vào spec §17.
GUARD = {('dex_settle_two_passkeys',): 8_600, ('passkey', 'next_pay'): 4_300, ('passkey', 'first_pay_opens_account'): 5_200}
over = []
for path, limit in GUARD.items():
    v = out
    for k in path:
        v = v[k]
    if v['execution'] > limit:
        over.append('%s: execution %d > %d' % ('.'.join(path), v['execution'], limit))
if over:
    sys.exit('gas guard: ' + '; '.join(over))
print('gas guard ok')
