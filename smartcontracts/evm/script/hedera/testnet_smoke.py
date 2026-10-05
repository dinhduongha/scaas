#!/usr/bin/env python3
"""Chạy `HederaSmoke` (initcode) qua `eth_call` trên Hedera testnet relay — không cần tài khoản, không cần HBAR.

python3 script/hedera/testnet_smoke.py [relay-url]   (từ smartcontracts/, sau `forge build`; cần `cast`)

Bước 1 lấy địa chỉ token + digest (địa chỉ CREATE tất định nhờ `from` cố định), ký digest bằng khoá ECDSA cố định,
bước 2 chạy: thanh toán ECDSA, chữ ký ED25519 sai cho tài khoản ED25519 có thật (0x16a thật), tài khoản không tồn tại.
"""
import json
import subprocess
import sys
import urllib.error
import urllib.request

RELAY = sys.argv[1] if len(sys.argv) > 1 else 'https://testnet.hashio.io/api'
CALLER = '0x00000000000000000000000000000000000b0b0b'
PK = '0x' + '11' * 32
ED_ACCOUNT = '0x00000000000000000000000000000000005b8d93'   # 0.0.6000019 — khoá ED25519 đơn trên testnet
BAD_SIG = '0x' + '22' * 64
BAD_SIGNATURE = '0x0bdf5a6b'                                # MetaTxBadSignature()


def rpc(method, params):
    req = urllib.request.Request(RELAY, json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': method, 'params': params}).encode(),
                                 {'content-type': 'application/json', 'user-agent': 'bamboo-smoke'})
    try:
        out = json.load(urllib.request.urlopen(req, timeout=60))
    except urllib.error.HTTPError as exc:
        sys.exit(f'{method}: HTTP {exc.code} {exc.read()[:500]!r}')
    if 'error' in out:
        sys.exit(f'{method}: {out["error"]}')
    return out['result']


def sh(*args):
    return subprocess.check_output(args, text=True).strip()


code = json.load(open('out/HederaSmoke.sol/HederaSmoke.json'))['bytecode']['object']
eoa = sh('cast', 'wallet', 'address', PK)


def run(sig):
    args = sh('cast', 'abi-encode', 'f(address,bytes,address,bytes)', eoa, sig, ED_ACCOUNT, BAD_SIG)
    return rpc('eth_call', [{'from': CALLER, 'data': code + args[2:], 'gas': '0xe4e1c0'}, 'latest'])


token, digest, chain = sh('cast', 'abi-decode', 'f()(address,bytes32,uint256)', run('0x')).split('\n')
sig = sh('cast', 'wallet', 'sign', '--no-hash', '--private-key', PK, digest)
ecdsa, shop, ed, unknown, code_len, call_ok, static_ok = sh(
    'cast', 'abi-decode', 'f()(bytes,uint256,bytes,bytes,uint256,bool,bool)', run(sig)).split('\n')
print(json.dumps({'chain': chain, 'token': token, 'ecdsa_payment': ecdsa, 'shop_balance': shop,
                  'ed25519_bad_signature': ed, 'unknown_account': unknown, 'eoa_code_length': code_len,
                  'has_answers_call': call_ok, 'has_answers_staticcall': static_ok}, indent=1))
assert (ecdsa, shop, ed, unknown, code_len, call_ok, static_ok) == (
    '0x6f6b', '100', BAD_SIGNATURE, BAD_SIGNATURE, '0', 'true', 'false'), 'unexpected'
print('OK')
