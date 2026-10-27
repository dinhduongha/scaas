#!/usr/bin/env python3
"""Sinh `tests/vectors.move`: khoá cố định, chữ ký THẬT (ed25519 qua phong bì signMessage, passkey WebAuthn P-256
phần mềm) trên payload do `dms_blockchain/lib/fam_aptos.py` dựng — vector chéo Python ↔ Move ↔ Rust.

    python3 smartcontracts/move/aptos/scripts/gen_vectors.py [--check]

Mỗi vector là một hàm test-only gọi đúng entry function với đối số đã ký; test chỉ chọn lane, tài sản và thời điểm.
ECDSA P-256 ngẫu nhiên ⇒ `--check` so mọi thứ trừ các dòng chữ ký P-256 (đánh dấu `// p256`).
"""
import hashlib
import importlib
import json
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
# `DMS_LIB` = thư mục `dms_blockchain/lib` (mặc định: repo anh em cạnh scaas).
LIB = os.environ.get('DMS_LIB') or os.path.join(HERE, '..', '..', '..', '..', '..', 'dms_blockchain', 'lib')
PAYMETA = os.path.join(HERE, '..', '..', '..', 'vectors', 'metatx', 'paymeta.json')
OUT = os.path.join(HERE, '..', 'tests', 'vectors.move')
_pkg = types.ModuleType('aptlib')
_pkg.__path__ = [LIB]            # nạp lib mà không chạy lib/__init__ (kéo Odoo)
sys.modules['aptlib'] = _pkg
F = importlib.import_module('aptlib.fam_aptos')

from Crypto.Hash import keccak as _keccak  # noqa: E402  (pycryptodome)
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils  # noqa: E402

SCAAS = '0xb0b'
CHAIN = 4
ROOT = F.root_of(SCAAS)
DEX = F.dex_of(ROOT)
EUR = F.object_address('0xcafe', b'EUR')
USD = F.object_address('0xcafe', b'USD')
GBP = F.object_address('0xcafe', b'GBP')
HOOK = F.object_address('0xcafe', b'HOOK')    # FA có hook withdraw (dispatchable, AIP-73)
APT = '0xa'                                    # FA cặp của coin APT (AIP-63)
BEEF = '0xbeef'
RELAYER = '0x7e1'
VU = 1000
ORIGIN = 'https://pay.scaas.test'
RP_ID_HASH = hashlib.sha256(b'pay.scaas.test').digest()
APP = 'https://pay.scaas.test'
ZERO32 = bytes(32)
N = F.P256_N
# CTR-MTX-27 router marker: `object::create_object_address(&@scaas, b"scaas.relayfee")` (no one can sign for it).
MARKER = F.object_address(SCAAS, b'scaas.relayfee')
out = []
# vector name ⇒ (Move argument text, BCS of the same arguments): the relay-fee wrappers' `call` (spec §7.2 Aptos)
CALLS = {}


def seed(name):
    return hashlib.sha256(name.encode()).digest()


class Key:
    def __init__(self, name, kind='ed25519', single=False):
        self.kind = kind
        if kind == 'ed25519':
            self.sk = ed25519.Ed25519PrivateKey.from_private_bytes(seed(name))
            self.pk = self.sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        else:
            self.sk = ec.derive_private_key(int.from_bytes(seed(name), 'big') % N, ec.SECP256R1())
            self.pk = self.sk.public_key().public_bytes(serialization.Encoding.X962,
                                                         serialization.PublicFormat.UncompressedPoint)
        # địa chỉ của chủ = auth key chưa xoay: legacy ed25519, hoặc SingleKey (ed25519 / WebAuthn)
        keys = F.auth_keys(self.pk)
        self.address = keys[-1] if single else keys[0]

    def sign(self, label, digest, lane=None, style='minimal'):
        """(sig64, envelope) — ed25519: phong bì signMessage; WebAuthn: assertion trên challenge = digest."""
        if self.kind == 'ed25519':
            msg = F.expected_message(digest, label)
            nonce = (lane or ZERO32).hex()
            env = {
                'minimal': F.minimal_envelope(msg, nonce),
                'app': F.minimal_envelope(msg, nonce, APP),
                'evil_app': F.minimal_envelope(msg, nonce, 'https://evil.test'),
                'reordered': 'APTOS\nnonce: %s\nchainId: %d\napplication: %s\nmessage: %s\naddress: %s' % (
                    nonce, CHAIN, APP, msg, self.address),
                'phish': 'APTOS\nmessage: hello\nmessage: %s\nnonce: %s' % (msg, nonce),
                'chain1': 'APTOS\nchainId: 1\nmessage: %s\nnonce: %s' % (msg, nonce),
                'unknown_key': 'APTOS\nmessage: %s\nfullMessage: x' % msg,
            }[style].encode()
            sig = self.sk.sign(env)
            ok = F.parse_envelope(env, msg, CHAIN) is not None
            assert F.verify_signature(self.pk, digest, sig, env, CHAIN, label=label) == ok
            return sig, env
        origin, flags, more = {'minimal': (ORIGIN, 5, {}), 'evil': ('https://evil.test', 5, {}), 'no_uv': (ORIGIN, 1, {}),
                               'cross': (ORIGIN, 5, {'crossOrigin': True}),
                               'top': (ORIGIN, 5, {'topOrigin': 'https://evil.test'})}[style]
        ad = RP_ID_HASH + bytes([flags]) + bytes(4)
        cd = json.dumps({'type': 'webauthn.get', 'challenge': F._b64url(digest).decode(), 'origin': origin,
                         'crossOrigin': False, **more}, separators=(',', ':')).encode()
        r, s = utils.decode_dss_signature(self.sk.sign(ad + hashlib.sha256(cd).digest(), ec.ECDSA(hashes.SHA256())))
        sig = r.to_bytes(32, 'big') + min(s, N - s).to_bytes(32, 'big')
        env = F.webauthn_envelope(ad, cd)
        assert F.verify_signature(self.pk, digest, sig, env, CHAIN) == (flags == 5 and not more)
        return sig, env


alice = Key('alice')
alice2 = Key('alice2')
bob = Key('bob', single=True)
carol = Key('carol')
dave = Key('dave', 'webauthn', single=True)
delegate = Key('delegate')
mallory = Key('mallory')
guardian = '0x9a'


def h(b):
    return 'x"%s"' % b.hex()


def a(x):
    return '@' + x


def vecaddr(xs):
    return 'vector[%s]' % ', '.join(a(x) for x in xs)


def fn(name, params, body, p256=False):
    out.append('public fun %s(%s) { %s }%s' % (name, params, body, '  // p256' if p256 else ''))


def const(name, value):
    out.append('public fun %s(): vector<u8> { %s }' % (name, h(value)))


def addr_const(name, value):
    out.append('public fun %s(): address { @%s }' % (name, value))


def b32(x):
    return x if isinstance(x, bytes) else bytes([x]) * 32


def pay(name, key, asset, amount, ref, lane, nonce, valid_until=VU, relayer='0x0', to=BEEF, owner=None, style='minimal',
        signer=None, extra=ZERO32):
    """`meta::relay_pay` đã ký. `signer` ≠ `key` = khoá khác ký thay chủ `owner`. `ref` / `lane`: byte lặp 32 lần hoặc
    32 byte."""
    owner = owner or key.address
    signer = signer or key
    account = F.account_of(ROOT, owner)
    pay_ref, lane_b = b32(ref), b32(lane)
    payload = F.metaop_bytes(CHAIN, account, asset, F.OP_PAY, owner, to, amount, pay_ref, lane_b, nonce, valid_until,
                             relayer, extra)
    dg = F.digest(payload)
    sig, env = signer.sign(F.LABEL, dg, lane_b, style)
    tail = '%s, asset, %s, %d, %s, %s, %d, %d, %s, %s, %s, %s, %s)' % (
        a(owner), a(to), amount, h(pay_ref), h(lane_b), nonce, valid_until, a(relayer), h(extra), h(signer.pk), h(sig),
        h(env))
    fn(name, 'lane: &signer, asset: Object<Metadata>', 'meta::relay_pay(lane, ' + tail, p256=signer.kind != 'ed25519')
    out.append('public fun %s_check(lane: address, asset: Object<Metadata>): vector<u8> { meta::pay_check(lane, %s }%s'
               % (name, tail, '  // p256' if signer.kind != 'ed25519' else ''))
    return payload, dg, sig, env


# ---------------------------------------------------------------- khoá, địa chỉ
for n, k in (('alice', alice), ('alice2', alice2), ('bob', bob), ('carol', carol), ('dave', dave),
             ('delegate', delegate), ('mallory', mallory)):
    const(n + '_pk', k.pk)
    addr_const(n, k.address)
addr_const('root', ROOT)
addr_const('dex', DEX)
addr_const('eur', EUR)
addr_const('usd', USD)
addr_const('hook', HOOK)
addr_const('gbp', GBP)
addr_const('a_account', F.account_of(ROOT, alice.address))
addr_const('b_account', F.account_of(ROOT, bob.address))
addr_const('c_account', F.account_of(ROOT, carol.address))
addr_const('d_account', F.account_of(ROOT, dave.address))
const('rp_id_hash', RP_ID_HASH)
const('origin', ORIGIN.encode())

# ---------------------------------------------------------------- pay
x_payload, x_digest, x_sig, x_env = pay('a_pay_eur_0', alice, EUR, 100, 1, 0xa1, 0)
const('a_pay_eur_0_digest', x_digest)
pay('a_pay_eur_1', alice, EUR, 50, 2, 0xa1, 1)
# M2: Odoo phát lại điều khoản CÙNG request (cùng pay_ref, lane, nonce 0) với hạn mới — hai op đã ký cho một request
pay('a_pay_eur_0_reissued', alice, EUR, 100, 1, 0xa1, 0, valid_until=1300)
pay('a_pay_usd_0', alice, USD, 70, 3, 0xa2, 0)
pay('a_pay_eur_relayer', alice, EUR, 10, 4, 0xa3, 0, relayer=RELAYER)
pay('a_pay_eur_reordered', alice, EUR, 10, 5, 0xa4, 0, style='reordered')
pay('a_pay_eur_phish', alice, EUR, 10, 6, 0xa5, 0, style='phish')
pay('a_pay_eur_chain1', alice, EUR, 10, 7, 0xa6, 0, style='chain1')
pay('a_pay_eur_unknown_key', alice, EUR, 10, 8, 0xa7, 0, style='unknown_key')
pay('a_pay_eur_short', alice, EUR, 10, 9, 0xa8, 0, valid_until=150)
pay('a_pay_eur_by_mallory', alice, EUR, 10, 10, 0xa9, 0, signer=mallory)
pay('a2_pay_eur', alice, EUR, 20, 11, 0xaa, 0, signer=alice2)
pay('a_pay_apt', alice, APT, 30, 12, 0xab, 0)
pay('a_pay_hook', alice, HOOK, 40, 13, 0xac, 0)
pay('b_pay_eur', bob, EUR, 100, 0x21, 0xb1, 0)
pay('d_pay_eur', dave, EUR, 100, 0x41, 0xd1, 0)
pay('d_pay_eur_1', dave, EUR, 10, 0x42, 0xd1, 1)
pay('d_pay_eur_evil_origin', dave, EUR, 100, 0x41, 0xd1, 0, style='evil')
pay('d_pay_eur_no_uv', dave, EUR, 100, 0x41, 0xd1, 0, style='no_uv')
pay('d_pay_eur_cross_origin', dave, EUR, 100, 0x41, 0xd1, 0, style='cross')
pay('d_pay_eur_top_origin', dave, EUR, 100, 0x41, 0xd1, 0, style='top')
# M1: `application:` của ví phải ∈ origins của Account khi Account có origin
pay('a_pay_eur_app', alice, EUR, 10, 15, 0xae, 0, style='app')
pay('a_pay_eur_evil_app', alice, EUR, 10, 16, 0xaf, 0, style='evil_app')


# ---------------------------------------------------------------- vòng đời khoá
def keyop_digest(owner, action, nonce, scheme=0, pk=b'', rp=b'', origin=b'', guardian_='0x0', valid_until=VU):
    account = F.account_of(ROOT, owner)
    return F.sha3(F.vec(b'scaas.keyop.v1') + bytes([CHAIN]) + F.addr(account) + bytes([action, scheme]) + F.vec(pk)
                  + F.vec(rp) + F.vec(origin) + F.addr(guardian_) + nonce.to_bytes(8, 'little')
                  + valid_until.to_bytes(8, 'little'))


def keyop(name, signer, owner, action, nonce, scheme=0, pk=b'', rp=b'', origin=b'', guardian_='0x0'):
    dg = keyop_digest(owner, action, nonce, scheme, pk, rp, origin, guardian_)
    sig, env = signer.sign('scaas.keyop.v1', dg)
    args = '%s, %d, %d, %s, %s, %s, %s, %d, %s, %s, %s' % (
        a(owner), action, scheme, h(pk), h(rp), h(origin), a(guardian_), VU, h(signer.pk), h(sig), h(env))
    fn(name, '', 'meta::manage_signed(%s)' % args, p256=signer.kind != 'ed25519')
    CALLS[name] = (args, F.addr(owner) + bytes([action, scheme]) + F.vec(pk) + F.vec(rp) + F.vec(origin)
                   + F.addr(guardian_) + VU.to_bytes(8, 'little') + F.vec(signer.pk) + F.vec(sig) + F.vec(env))
    return dg


ADD_KEY, REMOVE_KEY, ADD_ORIGIN, REMOVE_ORIGIN, SET_GUARDIAN, CANCEL_RECOVERY = range(6)
const('a_keyop_0_digest', keyop('a_add_alice2', alice, alice.address, ADD_KEY, 0, pk=alice2.pk))
keyop('a2_remove_alice', alice2, alice.address, REMOVE_KEY, 1, pk=alice.pk)
keyop('a_set_guardian', alice, alice.address, SET_GUARDIAN, 1, guardian_=guardian)
keyop('a_cancel_recovery', alice, alice.address, CANCEL_RECOVERY, 2)
keyop('a_remove_alice_last', alice, alice.address, REMOVE_KEY, 0, pk=alice.pk)
keyop('a_add_dave_key', alice, alice.address, ADD_KEY, 0, scheme=2, pk=dave.pk, rp=RP_ID_HASH, origin=ORIGIN.encode())


# ---------------------------------------------------------------- mandate
M_SEED = b'm1'
MANDATE = F.mandate_of(ROOT, alice.address, M_SEED)
addr_const('mandate', MANDATE)


def mandate_open(name, signer, max_pay=100, max_period=150, period=600, expiry=5000, payees=(BEEF,)):
    dg = F.sha3(F.vec(b'scaas.mandate.v1') + bytes([CHAIN]) + F.addr(F.account_of(ROOT, alice.address))
                + F.addr(MANDATE) + F.vec(M_SEED) + F.vec(delegate.pk) + max_pay.to_bytes(8, 'little')
                + max_period.to_bytes(8, 'little') + period.to_bytes(8, 'little') + expiry.to_bytes(8, 'little')
                + F.uleb128(len(payees)) + b''.join(F.addr(p) for p in payees) + VU.to_bytes(8, 'little'))
    sig, env = signer.sign('scaas.mandate.v1', dg)
    args = '%s, %s, %s, %d, %d, %d, %d, %s, %d, %s, %s, %s' % (
        a(alice.address), h(M_SEED), h(delegate.pk), max_pay, max_period, period, expiry, vecaddr(payees), VU,
        h(signer.pk), h(sig), h(env))
    fn(name, '', 'mandate::open(%s)' % args)
    CALLS[name] = (args, F.addr(alice.address) + F.vec(M_SEED) + F.vec(delegate.pk) + b''.join(
        x.to_bytes(8, 'little') for x in (max_pay, max_period, period, expiry)) + F.uleb128(len(payees))
        + b''.join(F.addr(p) for p in payees) + VU.to_bytes(8, 'little') + F.vec(signer.pk) + F.vec(sig) + F.vec(env))


def mandate_pay(name, asset, amount, ref, to=BEEF, signer=delegate, valid_until=VU):
    pay_ref = bytes([ref]) * 32
    payload = F.metaop_bytes(CHAIN, MANDATE, asset, F.OP_MANDATE_PAY, alice.address, to, amount, pay_ref, pay_ref, 0,
                             valid_until)
    sig, env = signer.sign(F.LABEL, F.digest(payload), pay_ref)
    fn(name, 'lane: &signer, asset: Object<Metadata>', 'mandate::pay(lane, %s, asset, %s, %d, %s, %d, @0x0, %s, %s, %s)' % (
        a(MANDATE), a(to), amount, h(pay_ref), valid_until, h(signer.pk), h(sig), h(env)))


def mandate_revoke(name, signer):
    payload = F.metaop_bytes(CHAIN, MANDATE, '0x0', F.OP_REVOKE, alice.address, '0x0', 0, ZERO32, ZERO32, 0, VU)
    sig, env = signer.sign(F.LABEL, F.digest(payload))
    args = '%s, %d, %s, %s, %s' % (a(MANDATE), VU, h(signer.pk), h(sig), h(env))
    fn(name, 'lane: &signer', 'mandate::revoke_signed(lane, %s)' % args)
    # the lane is not part of `call` (no sender in `ref`): the wrapper's own lane submits
    CALLS[name] = (args, F.addr(MANDATE) + VU.to_bytes(8, 'little') + F.vec(signer.pk) + F.vec(sig) + F.vec(env))


pay('a_pay_eur_to_mandate', alice, EUR, 200, 14, 0xad, 0, to=MANDATE)
mandate_open('m_open', alice)
mandate_open('m_open_by_mallory', mallory)
mandate_pay('m_pay_60_r1', EUR, 60, 0x61)
mandate_pay('m_pay_60_r1_reissued', EUR, 60, 0x61, valid_until=1300)
mandate_pay('m_pay_60_r2', EUR, 60, 0x62)
mandate_pay('m_pay_60_r3', EUR, 60, 0x63)
mandate_pay('m_pay_101', EUR, 101, 0x64)
mandate_pay('m_pay_to_mallory', EUR, 10, 0x65, to=mallory.address)
mandate_pay('m_pay_by_mallory', EUR, 10, 0x66, signer=mallory)
# Chữ ký `pay` của Account (op 0, contract = Account) đem nộp vào mandate (op 2, contract = Mandate): sai miền.
_ref = bytes([0x67]) * 32
_dg = F.digest(F.metaop_bytes(CHAIN, F.account_of(ROOT, alice.address), EUR, F.OP_PAY, alice.address, BEEF, 10, _ref,
                              _ref, 0, VU))
_sig, _env = delegate.sign(F.LABEL, _dg, _ref)
fn('m_pay_with_account_op_sig', 'lane: &signer, asset: Object<Metadata>',
   'mandate::pay(lane, %s, asset, %s, 10, %s, %d, @0x0, %s, %s, %s)' % (
       a(MANDATE), a(BEEF), h(_ref), VU, h(delegate.pk), h(_sig), h(_env)))
mandate_revoke('m_revoke_by_delegate', delegate)
mandate_revoke('m_revoke_by_owner', alice)


# ---------------------------------------------------------------- DEX
MARKET = F.market_of(DEX, EUR, USD)
addr_const('market', MARKET)
FOK, IOC = 1, 2


def order_bytes(maker, sell, buy, sell_amount, buy_amount, nonce, expiry=VU, max_fee=10_000, flags=0, taker='0x0',
                relayer='0x0', market=MARKET):
    return (F.vec(b'scaas.order.v1') + bytes([CHAIN]) + F.addr(market) + F.addr(maker.address) + F.addr(taker)
            + F.addr(sell) + F.addr(buy) + sell_amount.to_bytes(8, 'little') + buy_amount.to_bytes(8, 'little')
            + nonce.to_bytes(16, 'little') + expiry.to_bytes(8, 'little') + max_fee.to_bytes(4, 'little')
            + bytes([flags]) + F.addr(relayer))


def order(name, maker, *args, signer=None, **kw):
    """[order bytes, pk, sig, env]."""
    b = order_bytes(maker, *args, **kw)
    sig, env = (signer or maker).sign('scaas.order.v1', F.sha3(b))
    out.append('public fun %s(): vector<vector<u8>> { vector[%s, %s, %s, %s] }%s' % (
        name, h(b), h((signer or maker).pk), h(sig), h(env), '  // p256' if (signer or maker).kind != 'ed25519' else ''))
    return b


# alice bán 100 EUR lấy 200 USD; carol bán 200 USD lấy 100 EUR (giá khớp đúng)
o_a = order('o_alice_sell_eur', alice, EUR, USD, 100, 200, 1)
const('o_alice_sell_eur_hash', F.sha3(o_a))
order('o_carol_sell_usd', carol, USD, EUR, 200, 100, 1)
order('o_carol_sell_usd_cheap', carol, USD, EUR, 100, 100, 2)      # đòi 1 EUR / USD — phạm giá của alice
order('o_alice_fok', alice, EUR, USD, 100, 200, 3, flags=FOK)
order('o_alice_ioc', alice, EUR, USD, 100, 200, 4, flags=IOC)
order('o_alice_nofee', alice, EUR, USD, 100, 200, 5, max_fee=0)
order('o_carol_big', carol, USD, EUR, 400, 200, 6)
order('o_dave_sell_usd', dave, USD, EUR, 200, 100, 7)              # passkey ký lệnh
order('o_alice_by_mallory', alice, EUR, USD, 100, 200, 8, signer=mallory)


def cancel(name, maker, ob):
    dg = F.sha3(F.vec(b'scaas.cancel.v1') + bytes([CHAIN]) + F.addr(MARKET) + F.vec(F.sha3(ob)))
    sig, env = maker.sign('scaas.cancel.v1', dg)
    args = '%s, %s, %s, %s, %s' % (a(MARKET), h(ob), h(maker.pk), h(sig), h(env))
    fn(name, '', 'dex::cancel_signed(%s)' % args)
    CALLS[name] = (args, F.addr(MARKET) + F.vec(ob) + F.vec(maker.pk) + F.vec(sig) + F.vec(env))


def invalidate(name, maker, min_nonce, market=MARKET):
    dg = F.sha3(F.vec(b'scaas.nonces.v1') + bytes([CHAIN]) + F.addr(market) + F.addr(maker.address)
                + min_nonce.to_bytes(16, 'little'))
    sig, env = maker.sign('scaas.nonces.v1', dg)
    args = '%s, %s, %d, %s, %s, %s' % (a(market), a(maker.address), min_nonce, h(maker.pk), h(sig), h(env))
    fn(name, '', 'dex::invalidate_nonces_signed(%s)' % args)
    CALLS[name] = (args, F.addr(market) + F.addr(maker.address) + min_nonce.to_bytes(16, 'little') + F.vec(maker.pk)
                   + F.vec(sig) + F.vec(env))


# Market thứ hai (EUR/GBP): min_nonce/filled/huỷ của market này không đụng market kia.
MARKET2 = F.market_of(DEX, EUR, GBP)
addr_const('market2', MARKET2)
order('o2_alice_sell_eur', alice, EUR, GBP, 100, 200, 1, market=MARKET2)
order('o2_carol_sell_gbp', carol, GBP, EUR, 200, 100, 1, market=MARKET2)
cancel('cancel_o_alice_sell_eur', alice, o_a)
invalidate('alice_min_nonce_2', alice, 2)


# ---------------------------------------------------------------- CTR-MTX-26 pay-meta (spec §6.2)
def keccak(b):
    return _keccak.new(digest_bits=256, data=b).digest()


def meta_pay_id(salt, meta):
    return keccak(b'scaas.pay.meta' + salt + keccak(meta))


def pay_lane(p):
    return keccak(b'scaas.pay.lane' + p)


def pay_meta(name, key, asset, amount, salt, meta, relayer='0x0', to=BEEF):
    """`meta::relay_pay_meta` / `pay_meta_check` of a signed plain pay with `pay_ref = metaPayId(salt, meta)`,
    `lane = payLane(pay_ref)`, nonce 0. `salt` / `meta` are parameters, so a test can pass others."""
    pid = meta_pay_id(salt, meta)
    payload = F.metaop_bytes(CHAIN, F.account_of(ROOT, key.address), asset, F.OP_PAY, key.address, to, amount, pid,
                             pay_lane(pid), 0, VU, relayer)
    sig, env = key.sign(F.LABEL, F.digest(payload), pay_lane(pid))
    tail = '%s, asset, %s, %d, s, m, %d, %s, %s, %s, %s, %s)' % (
        a(key.address), a(to), amount, VU, a(relayer), h(ZERO32), h(key.pk), h(sig), h(env))
    fn(name, 'lane: &signer, asset: Object<Metadata>, s: vector<u8>, m: vector<u8>', 'meta::relay_pay_meta(lane, ' + tail)
    out.append('public fun %s_check(lane: address, asset: Object<Metadata>, s: vector<u8>, m: vector<u8>): vector<u8> '
               '{ meta::pay_meta_check(lane, %s }' % (name, tail))
    return F.digest(payload)


# Every row of the shared vectors (`long_body_4096` is a hash vector only, never submitted).
rows = json.load(open(PAYMETA))
quads = []
for r in rows:
    salt, meta = bytes.fromhex(r['salt'][2:]), bytes.fromhex(r['meta'][2:])
    pid = meta_pay_id(salt, meta)
    assert pid.hex() == r['payId'][2:] and pay_lane(pid).hex() == r['payLane'][2:], r['name']
    # `[salt, meta, payId, payLane]` as in the file (`payId` / `payLane` copied, not recomputed)
    quads.append('vector[%s]' % ', '.join(h(bytes.fromhex(r[k][2:])) for k in ('salt', 'meta', 'payId', 'payLane')))
out.append('public fun pm_rows(): vector<vector<vector<u8>>> { vector[%s] }' % ', '.join(quads))
NOTE = next(r for r in rows if r['name'] == 'note_utf8')
PM_SALT, PM_META, PM_ID = (bytes.fromhex(NOTE[k][2:]) for k in ('salt', 'meta', 'payId'))
const('pm_note_salt', PM_SALT)
const('pm_note_meta', PM_META)
const('pm_note_id', PM_ID)
const('pm_note_lane', pay_lane(PM_ID))
# Alice pays 0xbeef 100 EUR with payId(note_utf8): the same signed MetaOp as a plain pay of that pay_ref.
const('pm_a_note_digest', pay_meta('pm_a_note', alice, EUR, 100, PM_SALT, PM_META))
pay('pm_a_note_plain', alice, EUR, 100, PM_ID, pay_lane(PM_ID), 0)
# Bob (another payer) pays 1 with Alice's payId from his own Account (an attacker's pre-burn; rule 6).
pay('pm_b_note', bob, EUR, 1, PM_ID, pay_lane(PM_ID), 0)
# A pay-meta signed for the router marker as relayer: only the router may spend it.
pay_meta('pm_a_marker', alice, EUR, 100, PM_SALT, PM_META, relayer=MARKER)


# ---------------------------------------------------------------- CTR-MTX-27 relayfee (spec §7.2 Aptos)
def relay_ref(call, salt):
    """`keccak256("scaas.relayfee" ‖ chain_id (1 byte) ‖ @scaas (32) ‖ keccak256(call) ‖ salt (32))`."""
    return keccak(b'scaas.relayfee' + bytes([CHAIN]) + F.addr(SCAAS) + keccak(call) + salt)


PAY_UNTIL = 2000  # the payments outlive the inner calls (valid until 1000), so a call's own expiry is testable
keyop('rf_k_guardian', alice, alice.address, SET_GUARDIAN, 0, guardian_=guardian)
addr_const('relay_fee_marker', MARKER)
PAYS = {}


def relay(name, wrapper, entry, inner, to, salt_b, payer=alice, amount=10, pay_name=None):
    """`relayfee::<wrapper>(lane, <inner call's arguments>, <payer's payment>)`. `call = bcs(entry name) ‖ bcs(each
    argument)`; the payment: `pay_ref = ref`, `lane = payLane(ref)`, nonce 0, `relayer = marker`, `extra = salt`.
    `pay_name`: reuse that vector's payment (signed for another call)."""
    args, bcs_args = CALLS[inner]
    call = F.vec(entry) + bcs_args
    salt = bytes([salt_b]) * 32
    r = relay_ref(call, salt)
    if pay_name is None:
        const('rf_%s_call' % name, call)
        const('rf_%s_ref' % name, r)
        payload = F.metaop_bytes(CHAIN, F.account_of(ROOT, payer.address), EUR, F.OP_PAY, payer.address, to, amount, r,
                                 pay_lane(r), 0, PAY_UNTIL, MARKER, salt)
        sig, env = payer.sign(F.LABEL, F.digest(payload), pay_lane(r))
        PAYS[name] = '%s, asset, %s, %d, %d, %s, %s, %s, %s' % (
            a(payer.address), a(to), amount, PAY_UNTIL, h(salt), h(payer.pk), h(sig), h(env))
    fn('rf_%s' % name, 'lane: &signer, asset: Object<Metadata>',
       'relayfee::%s(lane, %s, %s)' % (wrapper, args, PAYS[pay_name or name]))
    return r


r_manage = relay('manage', 'relay_manage_signed', b'meta::manage_signed', 'rf_k_guardian', MARKER, 0x51)
relay('open', 'relay_mandate_open', b'mandate::open', 'm_open', MARKER, 0x52)
relay('revoke', 'relay_revoke_signed', b'mandate::revoke_signed', 'm_revoke_by_owner', BEEF, 0x53)
relay('cancel', 'relay_cancel_signed', b'dex::cancel_signed', 'cancel_o_alice_sell_eur', MARKER, 0x54)
relay('nonces', 'relay_invalidate_nonces_signed', b'dex::invalidate_nonces_signed', 'alice_min_nonce_2', MARKER, 0x55)
# Bob pays for Alice's call (any payer: no `&mut` object ties the payment to the call's account on Aptos).
relay('nonces_by_bob', 'relay_invalidate_nonces_signed', b'dex::invalidate_nonces_signed', 'alice_min_nonce_2', MARKER,
      0x56, payer=bob)
# The revoke's payment sent through another wrapper: signed for another `ref`.
relay('nonces_with_revoke_pay', 'relay_invalidate_nonces_signed', b'dex::invalidate_nonces_signed',
      'alice_min_nonce_2', MARKER, 0x53, pay_name='revoke')
# The nonces payment through the same wrapper with another instance of the call (Alice's invalidate on market2).
invalidate('alice_min_nonce_2_m2', alice, 2, market=MARKET2)
relay('nonces_m2_with_nonces_pay', 'relay_invalidate_nonces_signed', b'dex::invalidate_nonces_signed',
      'alice_min_nonce_2_m2', MARKER, 0x55, pay_name='nonces')
# The manage payment (router-bound) sent to the plain `relay_pay`.
pay('rf_manage_direct', alice, EUR, 10, r_manage, pay_lane(r_manage), 0, valid_until=PAY_UNTIL, relayer=MARKER,
    to=MARKER, extra=bytes([0x51]) * 32)
# Bob pre-burns Alice's manage `ref` with a plain pay of 1 from his own Account (rule 6).
pay('rf_manage_preburn_by_bob', bob, EUR, 1, r_manage, pay_lane(r_manage), 0)


def main():
    head = [
        '// GENERATED by smartcontracts/move/aptos/scripts/gen_vectors.py — do not edit.',
        '// Cross-implementation vector (also pinned in Rust and Odoo tests):',
        '//   a_pay_eur_0 payload = %s' % x_payload.hex(),
        '//   a_pay_eur_0 digest  = %s' % x_digest.hex(),
        '//   a_pay_eur_0 signature blob = %s' % (x_sig + x_env).hex(),
        '//   root = %s, a_account = %s' % (ROOT, F.account_of(ROOT, alice.address)),
        '#[test_only]',
        'module scaas::vectors {',
        '    use aptos_framework::fungible_asset::Metadata;',
        '    use aptos_framework::object::Object;',
        '    use scaas::dex;',
        '    use scaas::mandate;',
        '    use scaas::meta;',
        '    use scaas::relayfee;',
        '',
    ]
    text = '\n'.join(head + ['    ' + line for line in out] + ['}']) + '\n'
    if '--check' in sys.argv:
        strip = lambda t: [ln for ln in t.splitlines() if not ln.endswith('// p256')]  # noqa: E731
        if strip(open(OUT).read()) != strip(text):
            sys.exit('tests/vectors.move is stale: re-run gen_vectors.py')
        print('ok')
        return
    open(OUT, 'w').write(text)
    print('wrote', OUT)


if __name__ == '__main__':
    main()
