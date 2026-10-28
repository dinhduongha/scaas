#!/usr/bin/env python3
"""Sinh `tests/vectors.move`: khoá cố định, chữ ký thật (ed25519, secp256k1, secp256r1, passkey WebAuthn
phần mềm) trên payload do `dms_blockchain/lib/fam_sui.py` dựng — vector chéo Python ↔ Move.

    python3 smartcontracts/move/sui/scripts/gen_vectors.py > smartcontracts/move/sui/tests/vectors.move

Id object lấy từ `fixtures::print_ids` (cùng chuỗi tx ⇒ cùng id). ECDSA ngẫu nhiên ⇒ mỗi lần sinh khác
chữ ký nhưng vẫn đúng.
"""
import base64
import hashlib
import importlib
import json
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
_pkg = types.ModuleType('dmslib')  # nạp lib mà không chạy lib/__init__ (kéo Odoo)
# `DMS_LIB` = thư mục `dms_blockchain/lib` (mặc định: repo anh em cạnh scaas).
_pkg.__path__ = [os.environ.get('DMS_LIB') or os.path.join(HERE, '..', '..', '..', '..', '..', 'dms_blockchain', 'lib')]
sys.modules['dmslib'] = _pkg
F = importlib.import_module('dmslib.fam_sui')

from Crypto.Hash import keccak as _keccak  # noqa: E402  (pycryptodome)
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils  # noqa: E402

ROOT = '0xa4137e2ed945e7f4e8c307001c32e97472fb3eebb8f7b4ab7534b447d22da89b'
REG_SUI = '0x7c9575082976f063e7bfa16aa86ca20e1675b50efa7d5a64d1fa66ce127f5fdf'
REG_EUR = '0x168544589e67ec4f3a15a388d1a4ed44eca52abd8ff1c04a1057d2d4f53e3960'
DEX = '0xd726ecf6f7036ee3557cd6c7b93a49b231070e8eecada9cfa157e40e3f02e5d3'
# `dex::market_address<EUR, SUI>` / `<USD, SUI>` (derived từ DEX — `fixtures::print_ids`).
MARKET = '0x4c5e7c0aa01e77f7c83bc1bd0c19fc6fdfd44f12920176c52c005f5f6b90326b'
MARKET_USD = '0xefe418838a1646cb7f0a12168dfddaa6353e52e80313e45150fec5539c8431d'
# `relayfee::RelayFee` (the router marker, tx1 — `fixtures::print_ids`); the package's id in `sui move test`.
RELAY_FEE = '0x5ef2fcf809fb9535ea0aeaea421f683026f06c34569aafc42bcde652ef6dd270'
PACKAGE = '0x0'
PAYMETA = os.path.join(HERE, '..', '..', '..', 'vectors', 'metatx', 'paymeta.json')
MANDATE = '0xbfd1d3ac3d6c37f03afe4d7c244e677f9b01fcbff79dae3394640a7944e5f5ab'
NET = 'localnet'
SUI_T = b'0000000000000000000000000000000000000000000000000000000000000002::sui::SUI'
EUR_T = b'0000000000000000000000000000000000000000000000000000000000000000::fixtures::EUR'
ORIGIN = 'https://pay.scaas.test'
ANDROID = 'android:apk-key-hash:Kq4X0bWx4mSs2N3uTjRL8tqxHH4m-sPGxBtcIu7b3QM'
GUARDIAN = '0x9a'
ADD_KEY, REMOVE_KEY, ADD_ORIGIN, REMOVE_ORIGIN, SET_GUARDIAN, CANCEL_RECOVERY = range(6)
RP_ID_HASH = hashlib.sha256(b'pay.scaas.test').digest()
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
alice2 = Key('alice2', F.ED25519)
alice3 = Key('alice3', F.SECP256K1)
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


def pay(name, key, registry, amount, ref, lane, nonce, valid_until=1000, relayer='0x0', to=BEEF, owner=None, extra=bytes(32),
        **kw):
    """`ref` / `lane`: one byte (repeated ×32) or the 32 bytes themselves."""
    owner = owner or key.address
    account = F.derive_account(registry, owner)
    b32 = lambda x: x if isinstance(x, bytes) else bytes([x]) * 32  # noqa: E731
    payload = F.metaop_bytes(NET, account, F.OP_PAY, owner, to, amount, b32(ref), b32(lane), nonce, valid_until,
                             relayer, extra)
    digest = F.personal_digest(payload)
    ser = auth_const(name, key, digest, **kw)
    return account, payload, digest, ser


for n, k in (('alice', alice), ('alice2', alice2), ('alice3', alice3), ('bob', bob), ('carol', carol), ('dave', dave),
             ('delegate', delegate)):
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
open_ch = F.blake2b256(b'scaas.open.v1' + F.addr(REG_SUI) + dave.pk)
auth_const('d_open', dave, open_ch)


# Vòng đời khoá (review M1): `meta::KeyOp`, ký bởi một khoá hiện có của account.
keyops = {}


def keyop(name, signer, owner, action, nonce, scheme=0, pk=b'', rp=b'', origin='', guardian='0x0', **kw):
    account = F.derive_account(REG_SUI, owner.address)
    b = (F._vec(b'scaas.keyop.v1') + F._vec(NET.encode()) + F.addr(account) + bytes([action, scheme]) + F._vec(pk)
         + F._vec(rp) + F._vec(origin.encode()) + F.addr(guardian) + nonce.to_bytes(8, 'little')
         + (1000).to_bytes(8, 'little'))
    keyops[name] = auth_const(name, signer, F.personal_digest(b), **kw)


keyop('k_a_add_a2', alice, alice, ADD_KEY, 0, 0, alice2.pk)
keyop('k_a2_rm_a', alice2, alice, REMOVE_KEY, 1, 0, alice.pk)
keyop('k_a_rm_a', alice, alice, REMOVE_KEY, 0, 0, alice.pk)
keyop('k_a_guardian', alice, alice, SET_GUARDIAN, 0, guardian=GUARDIAN)
keyop('k_a_cancel', alice, alice, CANCEL_RECOVERY, 1)
keyop('k_d_add_android', dave, dave, ADD_ORIGIN, 0, origin=ANDROID)
keyop('k_d_rm_origin', dave, dave, REMOVE_ORIGIN, 0, origin=ORIGIN)
# Cùng payload với a_pay_sui_0 / d_pay_sui, ký bằng khoá mới / từ app Android.
pay('a2_pay_sui', alice2, REG_SUI, 100, 1, 0xa1, 0, owner=alice.address)
pay('a3_pay_sui', alice3, REG_SUI, 100, 1, 0xa1, 0, owner=alice.address)
pay('d_pay_sui_android', dave, REG_SUI, 100, 7, 0xd1, 0, origin=ANDROID)

# Mandate (delegate ký; from = alice, contract = mandate).
for name, amount, ref in (('m_pay_1', 40, 0x61), ('m_pay_2', 40, 0x62), ('m_pay_3', 30, 0x63)):
    p = F.metaop_bytes(NET, MANDATE, F.OP_MANDATE_PAY, alice.address, BEEF, amount, bytes([ref]) * 32,
                       bytes([ref]) * 32, 0, 1000)
    auth_const(name, delegate, F.personal_digest(p))
p = F.metaop_bytes(NET, MANDATE, F.OP_REVOKE, alice.address, '0x0', 0, bytes(32), bytes(32), 0, 1000)
m_revoke_ser = auth_const('m_revoke', delegate, F.personal_digest(p))


def order_bytes(maker, sell_t, buy_t, sell, buy, nonce, flags=0, max_fee=3000, expiry=1000, taker='0x0'):
    return (F._vec(b'scaas.order.v1') + F._vec(NET.encode()) + F.addr(MARKET) + F.addr(maker.address) + F.addr(taker)
         + F._vec(sell_t) + F._vec(buy_t) + sell.to_bytes(8, 'little') + buy.to_bytes(8, 'little')
         + nonce.to_bytes(16, 'little') + expiry.to_bytes(8, 'little') + max_fee.to_bytes(4, 'little')
         + bytes([flags]) + F.addr('0x0'))


def order(*args, **kw):
    return F.personal_digest(order_bytes(*args, **kw))


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
cancel = F._vec(b'scaas.cancel.v1') + F._vec(NET.encode()) + F.addr(MARKET) + F._vec(order(*orders['o_a']))
cancel_ser = auth_const('cancel_o_a', alice, F.personal_digest(cancel))
sigs = {'m_revoke': m_revoke_ser, 'cancel_o_a': cancel_ser}
for name, market in (('nonces_a_2', MARKET), ('nonces_a_2_usd', MARKET_USD)):
    nonces = (F._vec(b'scaas.nonces.v1') + F._vec(NET.encode()) + F.addr(market) + F.addr(alice.address)
              + (2).to_bytes(16, 'little'))
    sigs[name] = auth_const(name, alice, F.personal_digest(nonces))


def keccak(b):
    return _keccak.new(digest_bits=256, data=b).digest()


# ------------------------------------------------------------------ CTR-MTX-26 pay-meta (spec §6.2)
def meta_pay_id(salt, meta):
    return keccak(b'scaas.pay.meta' + salt + keccak(meta))


def pay_lane(p):
    return keccak(b'scaas.pay.lane' + p)


# Every row of the shared vectors (`long_body_4096` is a hash vector only, never submitted).
rows = json.load(open(PAYMETA))
quads = []
for r in rows:
    salt, meta = bytes.fromhex(r['salt'][2:]), bytes.fromhex(r['meta'][2:])
    pid = meta_pay_id(salt, meta)
    assert pid.hex() == r['payId'][2:] and pay_lane(pid).hex() == r['payLane'][2:], r['name']
    quads.append('vector[%s]' % ', '.join(h(x) for x in (salt, meta, bytes.fromhex(r['payId'][2:]),
                                                           bytes.fromhex(r['payLane'][2:]))))
    if r['name'] == 'note_utf8':
        const('pm_note_salt', salt)
        const('pm_note_meta', meta)
        const('pm_note_id', pid)
# `[salt, meta, payId, payLane]` of every row, as in the file (`payId` / `payLane` copied, not recomputed).
out.append('public fun pm_rows(): vector<vector<vector<u8>>> { vector[%s] }' % ', '.join(quads))
NOTE = next(r for r in rows if r['name'] == 'note_utf8')
note_id = bytes.fromhex(NOTE['payId'][2:])
# Alice pays 0xbeef 100 SUI with payId(note_utf8): the same signed MetaOp as a plain pay of that pay_ref.
pay('pm_a_note', alice, REG_SUI, 100, note_id, pay_lane(note_id), 0)
# Bob (another payer) signs his own pay of 1 with Alice's payId: his lane, never hers (rule 6).
pay('pm_b_note', bob, REG_SUI, 1, note_id, pay_lane(note_id), 0)


# ------------------------------------------------------------------ CTR-MTX-27 relayfee (spec §7.2)
def bcs_auth(ser):
    """BCS of `auth::Auth` from the serialized signature `auth_const` returned."""
    raw = base64.b64decode(ser)
    if raw[0] != F.PASSKEY:
        return F._vec(raw[1:65]) + F._vec(b'') + F._vec(b'')
    _, sig, _, ad, cd = F.parse_signature(ser)
    return F._vec(sig) + F._vec(ad) + F._vec(cd)


def relay_ref(call, salt):
    """`keccak256("scaas.relayfee" ‖ network ‖ package ‖ keccak256(call) ‖ salt)`."""
    return keccak(b'scaas.relayfee' + NET.encode() + F.addr(PACKAGE) + keccak(call) + salt)


A_SUI = F.derive_account(REG_SUI, alice.address)
PAY_UNTIL = 2000  # the payments outlive the inner calls (valid until 1000) so a call's own expiry is testable
calls = {
    # name: (call bytes, payee, salt byte)
    'manage': (F._vec(b'meta::manage') + F.addr(A_SUI) + bytes([SET_GUARDIAN, 0]) + F._vec(b'') + F._vec(b'')
               + F._vec(b'') + F.addr(GUARDIAN) + (1000).to_bytes(8, 'little') + bcs_auth(keyops['k_a_guardian']),
               RELAY_FEE, 0x51),
    'revoke': (F._vec(b'mandate::revoke_with_sig') + F.addr(MANDATE) + (1000).to_bytes(8, 'little')
               + bcs_auth(sigs['m_revoke']), BEEF, 0x52),
    'cancel': (F._vec(b'dex::cancel') + F.addr(MARKET) + F.addr(A_SUI) + order_bytes(*orders['o_a'])
               + bcs_auth(sigs['cancel_o_a']), RELAY_FEE, 0x53),
    'nonces': (F._vec(b'dex::invalidate_nonces') + F.addr(MARKET) + F.addr(A_SUI) + (2).to_bytes(16, 'little')
               + bcs_auth(sigs['nonces_a_2']), RELAY_FEE, 0x54),
}
for name, (call, to, salt_b) in calls.items():
    salt = bytes([salt_b]) * 32
    r = relay_ref(call, salt)
    const('rf_%s_call' % name, call)
    const('rf_%s_ref' % name, r)
    # Alice pays 10 SUI for the call: pay_ref = ref, lane = payLane(ref), nonce 0, relayer = the marker.
    pay('rf_%s_pay' % name, alice, REG_SUI, 10, r, pay_lane(r), 0, valid_until=PAY_UNTIL, relayer=RELAY_FEE, to=to,
        extra=salt)
addr_const('relay_fee_marker', RELAY_FEE)

print('// GENERATED by smartcontracts/move/sui/scripts/gen_vectors.py — do not edit.')
print('// Cross-implementation vector (also pinned in Rust and Odoo tests):')
print('//   a_pay_sui_0 payload = %s' % x_payload.hex())
print('//   a_pay_sui_0 digest  = %s' % x_digest.hex())
print('//   a_pay_sui_0 signature (Sui serialized) = %s' % x_ser)
print('#[test_only]\nmodule scaas::vectors;\n\nuse scaas::auth::{Self, Auth};\n')
print('\n'.join(out))
