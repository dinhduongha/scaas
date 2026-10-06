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
LIB = os.path.join(HERE, '..', '..', '..', '..', '..', 'dms_blockchain', 'lib')
OUT = os.path.join(HERE, '..', 'tests', 'vectors.move')
_pkg = types.ModuleType('aptlib')
_pkg.__path__ = [LIB]            # nạp lib mà không chạy lib/__init__ (kéo Odoo)
sys.modules['aptlib'] = _pkg
F = importlib.import_module('aptlib.fam_aptos')

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils  # noqa: E402

BAMBOO = '0xb0b'
CHAIN = 4
ROOT = F.root_of(BAMBOO)
DEX = F.dex_of(ROOT)
EUR = F.object_address('0xcafe', b'EUR')
USD = F.object_address('0xcafe', b'USD')
GBP = F.object_address('0xcafe', b'GBP')
HOOK = F.object_address('0xcafe', b'HOOK')    # FA có hook withdraw (dispatchable, AIP-73)
APT = '0xa'                                    # FA cặp của coin APT (AIP-63)
BEEF = '0xbeef'
RELAYER = '0x7e1'
VU = 1000
ORIGIN = 'https://pay.bamboo.test'
RP_ID_HASH = hashlib.sha256(b'pay.bamboo.test').digest()
APP = 'https://pay.bamboo.test'
ZERO32 = bytes(32)
N = F.P256_N
out = []


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


def pay(name, key, asset, amount, ref, lane, nonce, valid_until=VU, relayer='0x0', to=BEEF, owner=None, style='minimal',
        signer=None):
    """`meta::relay_pay` đã ký. `signer` ≠ `key` = khoá khác ký thay chủ `owner`."""
    owner = owner or key.address
    signer = signer or key
    account = F.account_of(ROOT, owner)
    pay_ref, lane_b = bytes([ref]) * 32, bytes([lane]) * 32
    payload = F.metaop_bytes(CHAIN, account, asset, F.OP_PAY, owner, to, amount, pay_ref, lane_b, nonce, valid_until,
                             relayer)
    dg = F.digest(payload)
    sig, env = signer.sign(F.LABEL, dg, lane_b, style)
    tail = '%s, asset, %s, %d, %s, %s, %d, %d, %s, %s, %s, %s, %s)' % (
        a(owner), a(to), amount, h(pay_ref), h(lane_b), nonce, valid_until, a(relayer), h(ZERO32), h(signer.pk), h(sig),
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
    return F.sha3(F.vec(b'bamboo.keyop.v1') + bytes([CHAIN]) + F.addr(account) + bytes([action, scheme]) + F.vec(pk)
                  + F.vec(rp) + F.vec(origin) + F.addr(guardian_) + nonce.to_bytes(8, 'little')
                  + valid_until.to_bytes(8, 'little'))


def keyop(name, signer, owner, action, nonce, scheme=0, pk=b'', rp=b'', origin=b'', guardian_='0x0'):
    dg = keyop_digest(owner, action, nonce, scheme, pk, rp, origin, guardian_)
    sig, env = signer.sign('bamboo.keyop.v1', dg)
    fn(name, '', 'meta::manage_signed(%s, %d, %d, %s, %s, %s, %s, %d, %s, %s, %s)' % (
        a(owner), action, scheme, h(pk), h(rp), h(origin), a(guardian_), VU, h(signer.pk), h(sig), h(env)),
       p256=signer.kind != 'ed25519')
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
    dg = F.sha3(F.vec(b'bamboo.mandate.v1') + bytes([CHAIN]) + F.addr(F.account_of(ROOT, alice.address))
                + F.addr(MANDATE) + F.vec(M_SEED) + F.vec(delegate.pk) + max_pay.to_bytes(8, 'little')
                + max_period.to_bytes(8, 'little') + period.to_bytes(8, 'little') + expiry.to_bytes(8, 'little')
                + F.uleb128(len(payees)) + b''.join(F.addr(p) for p in payees) + VU.to_bytes(8, 'little'))
    sig, env = signer.sign('bamboo.mandate.v1', dg)
    fn(name, '', 'mandate::open(%s, %s, %s, %d, %d, %d, %d, %s, %d, %s, %s, %s)' % (
        a(alice.address), h(M_SEED), h(delegate.pk), max_pay, max_period, period, expiry, vecaddr(payees), VU,
        h(signer.pk), h(sig), h(env)))


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
    fn(name, 'lane: &signer', 'mandate::revoke_signed(lane, %s, %d, %s, %s, %s)' % (
        a(MANDATE), VU, h(signer.pk), h(sig), h(env)))


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
    return (F.vec(b'bamboo.order.v1') + bytes([CHAIN]) + F.addr(market) + F.addr(maker.address) + F.addr(taker)
            + F.addr(sell) + F.addr(buy) + sell_amount.to_bytes(8, 'little') + buy_amount.to_bytes(8, 'little')
            + nonce.to_bytes(16, 'little') + expiry.to_bytes(8, 'little') + max_fee.to_bytes(4, 'little')
            + bytes([flags]) + F.addr(relayer))


def order(name, maker, *args, signer=None, **kw):
    """[order bytes, pk, sig, env]."""
    b = order_bytes(maker, *args, **kw)
    sig, env = (signer or maker).sign('bamboo.order.v1', F.sha3(b))
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
    dg = F.sha3(F.vec(b'bamboo.cancel.v1') + bytes([CHAIN]) + F.addr(MARKET) + F.vec(F.sha3(ob)))
    sig, env = maker.sign('bamboo.cancel.v1', dg)
    fn(name, '', 'dex::cancel_signed(%s, %s, %s, %s, %s)' % (a(MARKET), h(ob), h(maker.pk), h(sig), h(env)))


def invalidate(name, maker, min_nonce):
    dg = F.sha3(F.vec(b'bamboo.nonces.v1') + bytes([CHAIN]) + F.addr(MARKET) + F.addr(maker.address)
                + min_nonce.to_bytes(16, 'little'))
    sig, env = maker.sign('bamboo.nonces.v1', dg)
    fn(name, '', 'dex::invalidate_nonces_signed(%s, %s, %d, %s, %s, %s)' % (
        a(MARKET), a(maker.address), min_nonce, h(maker.pk), h(sig), h(env)))


# Market thứ hai (EUR/GBP): min_nonce/filled/huỷ của market này không đụng market kia.
MARKET2 = F.market_of(DEX, EUR, GBP)
addr_const('market2', MARKET2)
order('o2_alice_sell_eur', alice, EUR, GBP, 100, 200, 1, market=MARKET2)
order('o2_carol_sell_gbp', carol, GBP, EUR, 200, 100, 1, market=MARKET2)
cancel('cancel_o_alice_sell_eur', alice, o_a)
invalidate('alice_min_nonce_2', alice, 2)


def main():
    head = [
        '// GENERATED by smartcontracts/move/aptos/scripts/gen_vectors.py — do not edit.',
        '// Cross-implementation vector (also pinned in Rust and Odoo tests):',
        '//   a_pay_eur_0 payload = %s' % x_payload.hex(),
        '//   a_pay_eur_0 digest  = %s' % x_digest.hex(),
        '//   a_pay_eur_0 signature blob = %s' % (x_sig + x_env).hex(),
        '//   root = %s, a_account = %s' % (ROOT, F.account_of(ROOT, alice.address)),
        '#[test_only]',
        'module bamboo::vectors {',
        '    use aptos_framework::fungible_asset::Metadata;',
        '    use aptos_framework::object::Object;',
        '    use bamboo::dex;',
        '    use bamboo::mandate;',
        '    use bamboo::meta;',
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
