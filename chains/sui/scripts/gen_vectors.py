#!/usr/bin/env python3
"""Sinh `tests/vectors.move`: khoá cố định, chữ ký thật (ed25519, secp256k1, secp256r1, passkey WebAuthn
phần mềm) trên payload do `dms_blockchain/lib/fam_sui.py` dựng — vector chéo Python ↔ Move.

    python3 chains/sui/scripts/gen_vectors.py > chains/sui/tests/vectors.move

Id object lấy từ `fixtures::print_ids` (cùng chuỗi tx ⇒ cùng id). ECDSA ngẫu nhiên ⇒ mỗi lần sinh khác
chữ ký nhưng vẫn đúng.
"""
import base64
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', '..', '..', 'dms_blockchain'))
from lib import fam_sui as F  # noqa: E402

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils  # noqa: E402

ROOT = '0xa4137e2ed945e7f4e8c307001c32e97472fb3eebb8f7b4ab7534b447d22da89b'
REG_SUI = '0x7c9575082976f063e7bfa16aa86ca20e1675b50efa7d5a64d1fa66ce127f5fdf'
REG_EUR = '0x168544589e67ec4f3a15a388d1a4ed44eca52abd8ff1c04a1057d2d4f53e3960'
DEX = '0xd726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d3'
MANDATE = '0xbfd1d3ac3d6c37f03afe4d7c244e677f9b01fcbff79dae3394640a7944e5f5ab'
NET = 'localnet'
SUI_T = b'0000000000000000000000000000000000000000000000000000000000000002::sui::SUI'
EUR_T = b'0000000000000000000000000000000000000000000000000000000000000000::fixtures::EUR'
ORIGIN = 'https://pay.bamboo.test'
RP_ID_HASH = hashlib.sha256(b'pay.bamboo.test').digest()
N = {ec.SECP256K1: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
     ec.SECP256R1: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551}


def seed(name):
    return hashlib.sha256(name.encode()).digest()


class Key:
    def __init__(self, name, flag):
        self.flag = flag
        if flag == F.ED25519:
            self.sk = ed25519.Ed25519PrivateKey.from_private_bytes(seed(name))
            self.pk = self.sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        else:
            self.curve = ec.SECP256K1 if flag == F.SECP256K1 else ec.SECP256R1
            self.sk = ec.derive_private_key(int.from_bytes(seed(name), 'big') % N[self.curve], self.curve())
            self.pk = self.sk.public_key().public_bytes(serialization.Encoding.X962,
                                                         serialization.PublicFormat.CompressedPoint)
        self.address = F.address_of(flag, self.pk)

    def raw(self, msg):
        """64 byte r‖s low-s; ECDSA băm SHA-256 như Sui."""
        if self.flag == F.ED25519:
            return self.sk.sign(msg)
        r, s = utils.decode_dss_signature(self.sk.sign(msg, ec.ECDSA(hashes.SHA256())))
        n = N[self.curve]
        s = min(s, n - s)
        return r.to_bytes(32, 'big') + s.to_bytes(32, 'big')

    def assertion(self, digest, origin=ORIGIN, flags=5):
        ad = RP_ID_HASH + bytes([flags]) + bytes(4)
        cd = json.dumps({'type': 'webauthn.get', 'challenge': base64.urlsafe_b64encode(digest).rstrip(b'=').decode(),
                         'origin': origin, 'crossOrigin': False}, separators=(',', ':')).encode()
        return self.raw(ad + hashlib.sha256(cd).digest()), ad, cd

    def auth(self, digest, **kw):
        """(sig, authenticator_data, client_data_json, serialized-base64)."""
        if self.flag != F.PASSKEY:
            sig = self.raw(digest)
            return sig, b'', b'', base64.b64encode(bytes([self.flag]) + sig + self.pk).decode()
        sig, ad, cd = self.assertion(digest, **kw)
        user = bytes([F.SECP256R1]) + sig + self.pk
        ser = bytes([F.PASSKEY]) + F._vec(ad) + F._vec(cd) + F._vec(user)
        return sig, ad, cd, base64.b64encode(ser).decode()


alice = Key('alice', F.ED25519)
bob = Key('bob', F.SECP256K1)
carol = Key('carol', F.SECP256R1)
dave = Key('dave', F.SECP256R1)
dave.flag, dave.address = F.PASSKEY, F.address_of(F.PASSKEY, dave.pk)
delegate = Key('delegate', F.ED25519)
BEEF = '0xbeef'
out = []


def h(b):
    return 'x"%s"' % b.hex()


def const(name, value):
    out.append('public fun %s(): vector<u8> { %s }' % (name, h(value)))


def addr_const(name, a):
    out.append('public fun %s(): address { @%s }' % (name, a))


def auth_const(name, key, digest, **kw):
    sig, ad, cd, ser = key.auth(digest, **kw)
    out.append('public fun %s(): Auth { auth::new(%s, %s, %s) }' % (name, h(sig), h(ad), h(cd)))
    # Odoo kiểm được mọi thứ trừ origin/rpIdHash đã đăng ký (chain giữ) — vector thiếu UV phải trượt ở cả hai.
    assert F.verify_digest(key.flag, key.pk, digest, sig, ad, cd) == (kw.get('flags', 5) == 5)
    return ser


def pay(name, key, registry, amount, ref, lane, nonce, valid_until=1000, relayer='0x0', to=BEEF, **kw):
    account = F.derive_account(registry, key.address)
    payload = F.metaop_bytes(NET, account, F.OP_PAY, key.address, to, amount, bytes([ref]) * 32,
                             bytes([lane]) * 32, nonce, valid_until, relayer)
    digest = F.personal_digest(payload)
    ser = auth_const(name, key, digest, **kw)
    return account, payload, digest, ser


for n, k in (('alice', alice), ('bob', bob), ('carol', carol), ('dave', dave), ('delegate', delegate)):
    const(n + '_pk', k.pk)
    addr_const(n, k.address)

x_account, x_payload, x_digest, x_ser = pay('a_pay_sui_0', alice, REG_SUI, 100, 1, 0xa1, 0)
const('a_pay_sui_0_digest', x_digest)
addr_const('a_sui_account', x_account)
pay('a_pay_sui_1', alice, REG_SUI, 50, 2, 0xa1, 1)
pay('a_pay_eur_0', alice, REG_EUR, 70, 3, 0xa2, 0)
pay('a_pay_sui_relayer', alice, REG_SUI, 10, 4, 0xa3, 0, relayer='0x7e1')
pay('b_pay_sui', bob, REG_SUI, 100, 5, 0xb1, 0)
pay('c_pay_sui', carol, REG_SUI, 100, 6, 0xc1, 0)
pay('d_pay_sui', dave, REG_SUI, 100, 7, 0xd1, 0)
pay('d_pay_sui_evil_origin', dave, REG_SUI, 100, 7, 0xd1, 0, origin='https://evil.test')
pay('d_pay_sui_no_uv', dave, REG_SUI, 100, 7, 0xd1, 0, flags=1)
open_ch = F.blake2b256(b'bamboo.open.v1' + F.addr(REG_SUI) + dave.pk)
auth_const('d_open', dave, open_ch)

# Mandate (delegate ký; from = alice, contract = mandate).
for name, amount, ref in (('m_pay_1', 40, 0x61), ('m_pay_2', 40, 0x62), ('m_pay_3', 30, 0x63)):
    p = F.metaop_bytes(NET, MANDATE, F.OP_MANDATE_PAY, alice.address, BEEF, amount, bytes([ref]) * 32,
                       bytes([ref]) * 32, 0, 1000)
    auth_const(name, delegate, F.personal_digest(p))
p = F.metaop_bytes(NET, MANDATE, F.OP_REVOKE, alice.address, '0x0', 0, bytes(32), bytes(32), 0, 1000)
auth_const('m_revoke', delegate, F.personal_digest(p))


def order(maker, sell_t, buy_t, sell, buy, nonce, flags=0, max_fee=3000, expiry=1000, taker='0x0'):
    b = (F._vec(b'bamboo.order.v1') + F._vec(NET.encode()) + F.addr(DEX) + F.addr(maker.address) + F.addr(taker)
         + F._vec(sell_t) + F._vec(buy_t) + sell.to_bytes(8, 'little') + buy.to_bytes(8, 'little')
         + nonce.to_bytes(16, 'little') + expiry.to_bytes(8, 'little') + max_fee.to_bytes(4, 'little')
         + bytes([flags]) + F.addr('0x0'))
    return F.personal_digest(b)


orders = {
    'o_a': (alice, SUI_T, EUR_T, 1000, 2000, 1, 0),
    'o_b': (bob, EUR_T, SUI_T, 1000, 500, 1, 0),
    'o_b_fok': (bob, EUR_T, SUI_T, 1000, 500, 2, 1),
    'o_b_ioc': (bob, EUR_T, SUI_T, 1000, 500, 3, 2),
    'o_b_greedy': (bob, EUR_T, SUI_T, 1000, 600, 4, 0),
    'o_b_lowfee': (bob, EUR_T, SUI_T, 1000, 500, 5, 0, 100),
}
for name, args in orders.items():
    d = order(*args)
    const(name + '_hash', d)
    auth_const(name, args[0], d)
cancel = F._vec(b'bamboo.cancel.v1') + F._vec(NET.encode()) + F.addr(DEX) + F._vec(order(*orders['o_a']))
auth_const('cancel_o_a', alice, F.personal_digest(cancel))
nonces = (F._vec(b'bamboo.nonces.v1') + F._vec(NET.encode()) + F.addr(DEX) + F.addr(alice.address)
          + (2).to_bytes(16, 'little'))
auth_const('nonces_a_2', alice, F.personal_digest(nonces))

print('// GENERATED by chains/sui/scripts/gen_vectors.py — do not edit.')
print('// Cross-implementation vector (also pinned in Rust and Odoo tests):')
print('//   a_pay_sui_0 payload = %s' % x_payload.hex())
print('//   a_pay_sui_0 digest  = %s' % x_digest.hex())
print('//   a_pay_sui_0 signature (Sui serialized) = %s' % x_ser)
print('#[test_only]\nmodule bamboo::vectors;\n\nuse bamboo::auth::{Self, Auth};\n')
print('\n'.join(out))
