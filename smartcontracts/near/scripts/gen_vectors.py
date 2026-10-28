#!/usr/bin/env python3
"""NEAR family vectors (near-algorand plan Task 3; spec §2 rows 1, 3, 8, §3.5, §3.8, §8) → `vectors/near-vectors.json`.

    python3 -I smartcontracts/near/scripts/gen_vectors.py [--check]

Fixed seeds (key = seed sha256(name)), deterministic signatures (ed25519; ECDSA by RFC 6979), so `--check` compares
the whole file and fails on drift or when it is missing. A self-test runs first: every `paymeta.json` row's
`payId` / `payLane`, every `relayRefs` row recomputed from its own bytes, every signature verified.

Encoding (pinned here; spec §11 builder detail): `encode = b"scaas.metaop.v1" ‖ borsh(MetaOp)`, field order
network [u8;32], contract AccountId, op u8, from Holder, to Holder, relayer Option<AccountId>, amount u128,
pay_ref [u8;32], lane [u8;32], nonce u64, valid_until u64 (s), extra [u8;32]; `Holder` = Borsh enum 0 `Near(AccountId)`
/ 1 `Ua([u8;32])`; AccountId / String = u32 LE length ‖ UTF-8; `digest = sha256(encode)`.

Extension points (ruling R5): the ops whose parameter structs later tasks define add their vectors in the function
named for their family below (`transfer_vectors`, `key_op_vectors`, `recovery_vectors`, `mandate_vectors`,
`dex_vectors`), and Task 4 onwards adds a `storage` section (measured record sizes).
"""
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'vectors', 'metatx'))
import famvec as V  # noqa: E402

OUT = os.path.join(V.REPO, 'smartcontracts', 'near', 'vectors', 'near-vectors.json')
NETWORK = V.seed('scaas.near.test-genesis')         # stands in for the genesis hash (RPC `status`)
TOKEN = 'token.test.near'
TOKEN_B = 'tokenb.test.near'                        # the second token of the DEX pair (Task 8)
ROUTER = 'relayfee.test.near'
EXECUTOR = 'relayexec.test.near'
DEX = 'dex.test.near'
ALICE = 'alice.test.near'
BOB = 'bob.test.near'
RELAYER = 'relayer.test.near'
VU = 4_102_444_800                                  # 2100-01-01 in seconds: valid on a sandbox too
NEP413_TAG = 2**31 + 413                            # 2147484061

alice = V.Ed('alice')                               # a SCaaS key of alice.test.near (never an access key, §3.3)
erin = V.Ed('erin')                                 # ed25519 UA
carol = V.Ecdsa('carol', V.SECP256K1)               # secp256k1 UA (kind 0x0108, raw digest)
dave = V.Ecdsa('dave', V.P256)                      # webauthn-p256 UA (kind 0x0100)
UA_ERIN = V.ua_of(V.KIND_ED25519, erin.pk)
UA_CAROL = V.ua_of(V.KIND_SECP256K1, carol.key)
UA_DAVE = V.ua_of(V.KIND_WEBAUTHN_P256, dave.key + V.sha256(V.RP_ID.encode()))
KIND_MSIG = 0x0120


class Msig:
    """`msig` (kind 0x0120) key data: u16 threshold ‖ u16 count ‖ count × (u16 kind ‖ id 32 ‖ u16 weight), big-endian,
    ids strictly increasing; `signers` = (member index, signer) of the derived members that sign."""

    def __init__(self, threshold, members, signers):
        members = sorted(members, key=lambda m: m[1])
        self.key_data = struct.pack('>HH', threshold, len(members)) + b''.join(
            struct.pack('>H', k) + i + struct.pack('>H', w) for k, i, w in members)
        self.members = members
        self.signers = [(next(n for n, m in enumerate(members) if m[1] == i), s) for i, s in signers]
        self.ua = V.ua_of(KIND_MSIG, self.key_data)


# ---------------------------------------------------------------- Borsh
def u32(n):
    return struct.pack('<I', n)


def string(s):
    b = s.encode()
    return u32(len(b)) + b


def option(s):
    return b'\x00' if s is None else b'\x01' + string(s)


def near(a):
    return ('near', a)


def ua(i):
    return ('ua', i)


def holder(h):
    return b'\x00' + string(h[1]) if h[0] == 'near' else b'\x01' + h[1]


def holder_json(h):
    return {'Near': h[1]} if h[0] == 'near' else {'Ua': V.hx(h[1])}


def encode(op):
    return (V.LABEL + NETWORK + string(op['contract']) + bytes([op['op']]) + holder(op['from']) + holder(op['to'])
            + option(op['relayer']) + op['amount'].to_bytes(16, 'little') + op['pay_ref'] + op['lane']
            + struct.pack('<QQ', op['nonce'], op['valid_until']) + op['extra'])


def nep413(digest, recipient):
    """NEP-413: payload = Borsh {message, nonce = op digest, recipient = token, callback_url None};
    hash = sha256(u32 LE 2^31+413 ‖ payload); ed25519 signs the hash."""
    payload = string(V.text(digest).decode()) + digest + string(recipient) + option(None)
    return payload, V.sha256(u32(NEP413_TAG), payload)


def auth(signer, digest, recipient):
    if isinstance(signer, Msig):
        return {'kind': 'msig', 'keyData': V.hx(signer.key_data),
                'sigs': [{'index': i, 'auth': auth(s, digest, recipient)} for i, s in signer.signers]}
    if isinstance(signer, V.Ed):
        payload, h = nep413(digest, recipient)
        return {'kind': 'ed25519', 'key': V.hx(signer.pk), 'message': V.text(digest).decode(), 'nonce': V.hx(digest),
                'recipient': recipient, 'nep413Payload': V.hx(payload), 'nep413Hash': V.hx(h),
                'sig': V.hx(signer.sign(h))}
    if signer.c is V.SECP256K1:
        sig, v = signer.sign(digest)
        return {'kind': 'secp256k1', 'key': V.hx(signer.key), 'sig': V.hx(sig), 'v': v}
    return V.passkey(signer, digest)


METAOPS = []


def metaop(name, signer, frm, to, amount, pay_ref, lane, nonce=0, relayer=None, extra=V.ZERO32, valid_until=VU,
           note=None, code=V.OP['pay'], out=None, contract=TOKEN):
    op = {'contract': contract, 'op': code, 'from': frm, 'to': to, 'relayer': relayer, 'amount': amount,
          'pay_ref': pay_ref, 'lane': lane, 'nonce': nonce, 'valid_until': valid_until, 'extra': extra}
    enc = encode(op)
    dg = V.sha256(enc)
    row = {'name': name, 'fields': {
        'network': V.hx(NETWORK), 'contract': contract, 'op': op['op'], 'from': holder_json(frm), 'to': holder_json(to),
        'relayer': relayer, 'amount': str(amount), 'pay_ref': V.hx(pay_ref), 'lane': V.hx(lane), 'nonce': nonce,
        'valid_until': valid_until, 'extra': V.hx(extra)},
        'encoding': V.hx(enc), 'digest': V.hx(dg), 'text': V.text(dg).decode(), 'auth': auth(signer, dg, contract)}
    if note:
        row['note'] = note
    (METAOPS if out is None else out).append(row)
    return row


def b32(x):
    return bytes([x]) * 32


# ---------------------------------------------------------------- pay ops (op 0)
metaop('pay', alice, near(ALICE), near(BOB), 100, b32(0x01), b32(0xa1))
metaop('pay_ua_ed25519_u128_max', erin, ua(UA_ERIN), near(ALICE), V.U128_MAX, b32(0x02), b32(0xa2),
       note='amount 2^128 - 1 (Review Focus 5)')
metaop('pay_ua_secp256k1', carol, ua(UA_CAROL), ua(UA_ERIN), 2**64 + 1, b32(0x03), b32(0xa3), nonce=7)
metaop('pay_ua_passkey', dave, ua(UA_DAVE), near(BOB), 7, b32(0x04), b32(0xa4))
metaop('relay_pay', alice, near(ALICE), near(BOB), 25, b32(0x05), b32(0xa5), nonce=1, relayer=RELAYER,
       note='relayer bound: only RELAYER (the predecessor) may submit (§2 row 7)')
for r in V.paymeta_rows():
    pid = V.unhx(r['payId'])
    row = metaop('pay_meta_' + r['name'], alice, near(ALICE), near(BOB), 100, pid, V.pay_lane(pid),
                 note='mtx_pay_meta(op, auth, salt, meta) of paymeta.json row %s: pay_ref = payId, lane = payLane, '
                      'nonce 0' % r['name'])
    row['paymetaRow'] = r['name']


# ---------------------------------------------------------------- relay fee (§3.8)
def target_bytes(account):
    return bytes([len(account)]) + account.encode()


def filler(tag, n):
    out = b''
    while len(out) < n:
        out += V.sha256(tag.encode(), len(out).to_bytes(4, 'big'))
    return out[:n]


RELAY_REFS = []


def relay(name, kind, call, target, salt, to, relayer, call_parts):
    r = V.relay_ref(NETWORK, target_bytes(target), call, salt)
    pay = metaop('relay_fee_pay_' + name, alice, near(ALICE), near(to), 10, r, V.pay_lane(r), relayer=relayer,
                 extra=salt, note='payment of relayRefs %s: pay_ref = ref, lane = payLane(ref), nonce 0, '
                                  'extra = salt (ruling R11)' % name)
    RELAY_REFS.append({'name': name, 'kind': kind, **call_parts, 'target': target,
                       'targetBytes': V.hx(target_bytes(target)), 'call': V.hx(call), 'callLength': len(call),
                       'callHash': V.hx(V.keccak256(call)), 'salt': V.hx(salt), 'ref': V.hx(r),
                       'lane': V.hx(V.pay_lane(r)), 'payment': pay['name']})


def wrapper(name, entry, args, salt):
    """`relay_fee_<entry>`: target = u8 len ‖ token id, call = u8 len ‖ entry name ‖ Borsh(entry arguments); the
    payment is bound to the token (open mode: to = relayer = token)."""
    call = bytes([len(entry)]) + entry.encode() + args
    relay(name, 'wrapper', call, TOKEN, salt, TOKEN, TOKEN, {'entry': entry, 'args': V.hx(args)})


def router(name, target, method, args, salt):
    """escrow router `relay`: call = u8 len ‖ target ‖ u8 len ‖ method ‖ args; ref target = u8 len ‖ target id; the
    payment is bound to the router (open mode: to = relayer = router)."""
    call = target_bytes(target) + bytes([len(method)]) + method.encode() + args
    relay(name, 'router', call, target, salt, ROUTER, ROUTER, {'method': method, 'args': V.hx(args)})


# `args` are opaque filler here: the entries' argument structs belong to Tasks 5–8, which add real-argument rows.
wrapper('wrapper_short', 'mtx_invalidate_nonces', filler('wrapper_short', 48), b32(0x51))
_long_entry = 'mtx_add_key'
wrapper('wrapper_4096', _long_entry, filler('wrapper_4096', 4096 - 1 - len(_long_entry)), b32(0x52))
router('router_short', DEX, 'settle', filler('router_short', 40), b32(0x53))
router('router_4096', DEX, 'settle', filler('router_4096', 4096 - 2 - len(DEX) - len('settle')), b32(0x54))


# ---------------------------------------------------------------- extension points (ruling R5)
TRANSFERS = []
metaop('transfer', erin, ua(UA_ERIN), near(BOB), 50, V.ZERO32, b32(0xa6), nonce=3, code=V.OP['transfer'], out=TRANSFERS,
       note='mtx_transfer(op, auth): pay_ref zero (else refused), a client-chosen lane at its next nonce; no '
            'payment_settled')
metaop('execute_transfer_ref', carol, ua(UA_CAROL), near(ALICE), 9, b32(0x06), b32(0xa7), relayer=RELAYER,
       extra=b32(0x99), code=V.OP['execute_transfer'], out=TRANSFERS,
       note='mtx_execute_transfer(op, auth): any lane and pay_ref; pay_ref != 0 emits payment_settled; extra '
            'payer-chosen')


def transfer_vectors():
    """Ops 4 transfer, 5 execute_transfer (`mtx_transfer`, `mtx_execute_transfer`), Task 6."""
    return TRANSFERS


# Key ops (Task 5, spec §3.3): amount 0, pay_ref / lane zero, nonce = the signer's key nonce, to = from (start_recovery:
# to = the subject recovered), extra = sha256(Borsh(entry parameters)) — Borsh of the parameter tuple after (op, auth).
def u16(n):
    return struct.pack('<H', n)


def key_record(kind, data):
    """`KeyRecord { kind u16, key_data Vec<u8> }`: the subject key as its UA kind and canonical key data."""
    return u16(kind) + u32(len(data)) + data


def opt(b):
    return b'\x00' if b is None else b'\x01' + b


KIND_NEAR_ACCOUNT = 0x0017
SEC_KEY = key_record(V.KIND_SECP256K1, carol.key)
DAVE_KEY = key_record(V.KIND_WEBAUTHN_P256, dave.key + V.sha256(V.RP_ID.encode()))
frank = V.Ed('frank')
FRANK_KEY = key_record(V.KIND_ED25519, frank.pk)
APP_ORIGIN = 'https://app.scaas.test'
MSIG = Msig(2, [(KIND_NEAR_ACCOUNT, V.sha256(ALICE.encode()), 1), (V.KIND_ED25519, UA_ERIN, 1)],
            [(UA_ERIN, erin)])
KEY_OPS = []


def key_op(name, code, signer, frm, params, nonce, to=None, note=None):
    row = metaop(name, signer, frm, to or frm, 0, V.ZERO32, V.ZERO32, nonce=nonce, extra=V.sha256(params),
                 note=note, code=V.OP[code], out=KEY_OPS)
    row['params'] = V.hx(params)
    return row


key_op('add_key_secp256k1', 'add_key', erin, ua(UA_ERIN), SEC_KEY + opt(None), 0,
       note='mtx_add_key(op, auth, key, origin None); opens UA erin lazily (key nonce 0)')
key_op('add_key_passkey_with_origin', 'add_key', carol, ua(UA_CAROL), DAVE_KEY + opt(string(V.ORIGIN)), 0,
       note='mtx_add_key(op, auth, key = webauthn-p256 x ‖ y ‖ rpIdHash, origin Some)')
key_op('remove_key', 'remove_key', erin, ua(UA_ERIN), SEC_KEY, 1, note='mtx_remove_key(op, auth, key)')
key_op('add_origin_passkey', 'add_origin', dave, ua(UA_DAVE), string(APP_ORIGIN), 0,
       note='mtx_add_origin(op, auth, origin); passkey UA opened lazily with its assertion origin')
key_op('remove_origin', 'remove_origin', dave, ua(UA_DAVE), string(APP_ORIGIN), 1,
       note='mtx_remove_origin(op, auth, origin)')
key_op('set_guardian', 'set_guardian', erin, ua(UA_ERIN), opt(holder(near(ALICE))), 2,
       note='mtx_set_guardian(op, auth, guardian Some(Near(alice))); alice signs with its SCaaS key')
key_op('set_policy', 'set_guardian', erin, ua(UA_ERIN), bytes([6, 1]), 3,
       note='mtx_set_policy(op, auth, policy u8): the set_policy key-op action under op code 10, signed params '
            '[KEYOP_SET_POLICY 6, policy] (POLICY_PASSKEY_FOR_VALUE = 1, NET-ALL-23 item 3); a wallet key may sign')
key_op('set_guardian_msig', 'set_guardian', MSIG, ua(MSIG.ua), opt(None), 0,
       note='msig UA: the near-account member alice.test.near counts only as the predecessor; erin signs')


def key_op_vectors():
    """Ops 6–10 (`mtx_add_key` … `mtx_set_guardian`), `extra = sha256(Borsh(params))`."""
    return [r for r in KEY_OPS if r['fields']['op'] <= V.OP['set_guardian']]


key_op('start_recovery', 'start_recovery', alice, near(ALICE), FRANK_KEY + opt(None), 0, to=ua(UA_ERIN),
       note='mtx_start_recovery(op, auth, key, origin): from = the guardian, to = the subject; the guardian\'s '
            'mtx_finish_recovery after 172,800 s adds the key (CTR-ACC-03)')
key_op('finish_recovery', 'start_recovery', alice, near(ALICE), bytes([7]), 1, to=ua(UA_ERIN),
       note='mtx_finish_recovery(op, auth): the finish_recovery key-op action under op code 11, signed params '
            '[KEYOP_FINISH_RECOVERY 7], from = the guardian, to = the subject; adds the recovery key, removes none')
key_op('cancel_recovery', 'cancel_recovery', erin, ua(UA_ERIN), b'', 4, note='mtx_cancel_recovery(op, auth): no params')


def recovery_vectors():
    """Ops 11 start_recovery, 12 cancel_recovery, `extra = sha256(Borsh(params))`."""
    return [r for r in KEY_OPS if r['fields']['op'] >= V.OP['start_recovery']]


# Task 9 (ruling R6, T9 pre-flight (d)): `relay_fee_add_key` with real entry arguments, `call = u8 len ‖ "mtx_add_key" ‖
# Borsh(op, auth, key, origin)` of the key op row `add_key_secp256k1` (Auth::Ed25519 = variant 0 ‖ key 32 ‖ sig 64).
_ka = next(r for r in KEY_OPS if r['name'] == 'add_key_secp256k1')
wrapper('wrapper_add_key_real', 'mtx_add_key',
        V.unhx(_ka['encoding'])[len(V.LABEL):] + b'\x00' + V.unhx(_ka['auth']['key']) + V.unhx(_ka['auth']['sig'])
        + V.unhx(_ka['params']), b32(0x55))
RELAY_REFS[-1]['entryOp'] = _ka['name']


# Mandate (Task 7, spec §3.6): `MandateTerms` Borsh = delegate Holder ‖ payee Holder ‖ per_payment u128 ‖ per_period u128 ‖
# period_s u64 ‖ expiry u64 ‖ funding u128. Open (op 13, owner-signed value op on its lane): id = sha256(Borsh(from,
# terms, lane, nonce)), to = Ua(id), amount = funding (ruling R9), extra = sha256(id ‖ terms) (params). Pay (op 2,
# delegate-signed): from = Ua(id), lane = payLane(pay_ref), nonce 0, extra = sha256([]). Revoke (op 3, owner or delegate):
# to = Ua(id), amount / pay_ref / lane / nonce zero, extra = sha256([]).
MANDATES = []


def mandate_terms(delegate, payee, per_payment, per_period, period_s, expiry, funding):
    return (holder(delegate) + holder(payee) + per_payment.to_bytes(16, 'little') + per_period.to_bytes(16, 'little')
            + struct.pack('<QQ', period_s, expiry) + funding.to_bytes(16, 'little'))


_terms = mandate_terms(ua(UA_CAROL), near(BOB), 100, 250, 86_400, VU, 1_000)
_lane, _nonce = b32(0xb0), 0
MANDATE_ID = V.sha256(holder(ua(UA_ERIN)) + _terms + _lane + struct.pack('<Q', _nonce))
_row = metaop('mandate_open', erin, ua(UA_ERIN), ua(MANDATE_ID), 1_000, V.ZERO32, _lane, nonce=_nonce,
              extra=V.sha256(MANDATE_ID + _terms), code=V.OP['mandate_open'], out=MANDATES,
              note='mtx_mandate_open(op, auth, terms): owner erin on its lane at its next nonce; delegate carol (UA), payee '
                   'bob, per payment 100, per period 250 per 86,400 s, funding 1,000 = amount')
_row.update(params=V.hx(MANDATE_ID + _terms), terms=V.hx(_terms), mandateId=V.hx(MANDATE_ID))
_pr = b32(0x07)
metaop('mandate_pay', carol, ua(MANDATE_ID), near(BOB), 100, _pr, V.pay_lane(_pr), extra=V.sha256(b''),
       code=V.OP['mandate_pay'], out=MANDATES,
       note='mtx_mandate_pay(op, auth): from = the mandate id, signed by the delegate carol; the mandate\'s lane '
            'payLane(pay_ref) at nonce 0 (each pay_ref once per mandate)')['params'] = V.hx(b'')
metaop('mandate_revoke', carol, ua(UA_CAROL), ua(MANDATE_ID), 0, V.ZERO32, V.ZERO32, extra=V.sha256(b''),
       code=V.OP['revoke'], out=MANDATES,
       note='mtx_revoke(op, auth): the delegate\'s kill switch (the owner may sign it too); the balance goes back to '
            'the owner')['params'] = V.hx(b'')


def mandate_vectors():
    """Ops 2 mandate_pay, 3 revoke, 13 mandate_open (`MandateTerms`)."""
    return MANDATES


# DEX (Task 8, spec §3.6): `Order` Borsh = sell_token AccountId ‖ buy_token AccountId ‖ sell_amount u128 ‖ min_buy u128 ‖
# relayer Option<AccountId> ‖ expiry u64 (s). Leg (op 1, `mtx_trade(op, auth, order, receiver)`): contract = the sell
# token, to = Near(dex), relayer = dex, amount = sell_amount, pay_ref zero, the maker's order lane at any nonce >=
# min_nonce, extra = sha256(Borsh(Order)). Cancel (op 14, `mtx_cancel(op, auth, target_lane, target_nonce)`) and
# invalidate (op 15, `mtx_invalidate_nonces(op, auth, lane, min_nonce)`, min_nonce < 2^63): to = from, amount / pay_ref /
# lane / nonce zero, extra = sha256(Borsh(params)). settle_id = sha256(digest(op_a) ‖ digest(op_b)).
DEX_OPS = []


def order(sell, buy, sell_amount, min_buy, relayer, expiry):
    return (string(sell) + string(buy) + sell_amount.to_bytes(16, 'little') + min_buy.to_bytes(16, 'little')
            + option(relayer) + struct.pack('<Q', expiry))


_oa = order(TOKEN, TOKEN_B, 100, 50, RELAYER, VU)
_ob = order(TOKEN_B, TOKEN, 60, 100, None, VU)
_ta = metaop('trade_a', erin, ua(UA_ERIN), near(DEX), 100, V.ZERO32, b32(0xc0), relayer=DEX, extra=V.sha256(_oa),
             code=V.OP['trade'], out=DEX_OPS,
             note='mtx_trade leg of order A (erin sells 100 token for >= 50 tokenb, order relayer bound to RELAYER): '
                  'to = relayer = dex, amount = sell_amount, extra = sha256(Borsh(Order))')
_ta['order'] = V.hx(_oa)
_tb = metaop('trade_b', carol, ua(UA_CAROL), near(DEX), 60, V.ZERO32, b32(0xc1), nonce=3, relayer=DEX, extra=V.sha256(_ob),
             code=V.OP['trade'], out=DEX_OPS, contract=TOKEN_B,
             note='mtx_trade leg of order B (carol sells 60 tokenb for >= 100 token, open relayer) on tokenb, order lane '
                  'nonce 3')
_tb['order'] = V.hx(_ob)
SETTLE = {'legs': ['trade_a', 'trade_b'],
          'settleId': V.hx(V.sha256(V.unhx(_ta['digest']), V.unhx(_tb['digest']))),
          'derivation': 'sha256(digest(op_a) ‖ digest(op_b)), the two leg ops in settle-argument order',
          'note': 'fill-or-kill: 100 >= 100 (B min_buy) and 60 >= 50 (A min_buy); erin receives 60 tokenb, carol 100 token'}
_p = b32(0xc0) + struct.pack('<Q', 5)
metaop('cancel', erin, ua(UA_ERIN), ua(UA_ERIN), 0, V.ZERO32, V.ZERO32, extra=V.sha256(_p), code=V.OP['cancel'],
       out=DEX_OPS, note='mtx_cancel(op, auth, target_lane, target_nonce): closes erin\'s open order (lane c0, nonce 5); a '
                         'filled order is refused')['params'] = V.hx(_p)
_p = b32(0xc0) + struct.pack('<Q', 10)
metaop('invalidate_nonces', erin, ua(UA_ERIN), ua(UA_ERIN), 0, V.ZERO32, V.ZERO32, extra=V.sha256(_p),
       code=V.OP['invalidate_nonces'], out=DEX_OPS,
       note='mtx_invalidate_nonces(op, auth, lane, min_nonce): voids erin\'s orders below nonce 10 on lane c0; '
            'min_nonce < 2^63, only increasing (CTR-DEX-10)')['params'] = V.hx(_p)


def dex_vectors():
    """Ops 1 trade (`Order`, `extra = sha256(Borsh(Order))`), 14 cancel, 15 invalidate_nonces."""
    return DEX_OPS


# ---------------------------------------------------------------- native ids (kind 0x0017 near-account, §3.3)
def native_id(account):
    """64 lower-case hex = an implicit account: its raw 32 bytes; any other id (named, ETH-implicit) sha256(id)."""
    if len(account) == 64 and all(ch in '0123456789abcdef' for ch in account):
        return bytes.fromhex(account), 'implicit'
    assert account == account.lower(), 'not a NEAR account id'
    return V.sha256(account.encode()), 'sha256'


def eth_implicit(key):
    return '0x' + V.keccak256(key)[-20:].hex()


NATIVE = []
for acc in (alice.pk.hex(), ALICE, eth_implicit(carol.key), TOKEN):
    i, form = native_id(acc)
    NATIVE.append({'accountId': acc, 'form': form, 'id': V.hx(i)})
NATIVE_INVALID = [{'accountId': alice.pk.hex().upper(), 'reason': 'upper-case hex is not a NEAR account id: refused'},
                  {'accountId': 'Alice.test.near', 'reason': 'upper case is not a NEAR account id: refused'}]


# ---------------------------------------------------------------- storage (Task 4 onwards; spec §2 row 15)
# Bytes per record kind, measured on near-sandbox (`runs/2026-10-28-near-storage.txt`, test
# `storage_bounds_min_equals_max_equals_measured`); the contract constants equal them. Tasks 5–10 add their kinds.
MEASURED_STORAGE_BYTES = {
    'account': (125, 'NEP-145 registration of a 64-char account id: key b"f" ‖ Borsh(AccountId) 69 B, value u128 '
                     '16 B, record overhead 40 B (token ACCOUNT_STORAGE_BYTES; the fixed min == max of every holder)'),
    'uaBalance': (89, 'UA ledger record: key b"u" ‖ id 33 B, value u128 16 B, record overhead 40 B '
                      '(token UA_STORAGE_BYTES)'),
    'subjectEd25519Ua': (131, 'subject account of a UA with one ed25519 key, no origin / guardian / recovery: key '
                              'b"a" ‖ Borsh(Holder::Ua) 34 B, value Borsh(Subject) 57 B (keys 4 + 38, origins 4, '
                              'guardian 1, recovery 1, key_nonce 8, policy 1), record overhead 40 B; any subject '
                              'record = 41 + Borsh(holder) + Borsh(subject) (token SUBJECT_RECORD_OVERHEAD, measured in '
                              '`new`); a second ed25519 key +38 B (169 B, test ua_opened_lazily_relayer_pays_storage)'),
}
MEASURED_STORAGE_BYTES['lane'] = (
    114, 'lane record of a UA payer: key b"l" ‖ Borsh((Holder::Ua, lane)) 66 B, value u64 (next nonce) 8 B, record '
         'overhead 40 B; any lane = 81 + Borsh(holder) (token LANE_RECORD_OVERHEAD, measured in `new`); a first '
         'UA → UA pay of a new UA = subject 131 + lane 114 + UA record 89 = 334 B (test near_check_storage_needed_is_exact)')
MEASURED_STORAGE_BYTES['mandate'] = (
    261, 'mandate record with a UA owner, delegate and payee: key b"m" ‖ id 33 B, value Borsh(Mandate) 188 B (owner 33, '
         'terms: delegate 33, payee 33, per_payment 16, per_period 16, period_s 8, expiry 8, funding 16; period_start 8, '
         'spent 16, revoked 1), record overhead 40 B; any mandate = 73 + Borsh(Mandate) (token MANDATE_RECORD_OVERHEAD, '
         'measured in `new` with this record); an open also pays the UA record of the mandate id (89 B) and, first time, '
         'the owner\'s lane; each mandate pay a lane of the mandate id (114 B) (test mandate_pay_within_limits)')
MEASURED_STORAGE_BYTES['orderFilledUa'] = (
    147, 'order record of a UA maker, filled: key b"o" ‖ Borsh((Holder::Ua, lane, nonce)) 74 B, value OrderClose::Filled(leg '
         'op digest) 33 B, record overhead 40 B; any order record = 81 + Borsh(holder) + Borsh(OrderClose) (token '
         'TRADE_RECORD_OVERHEAD, measured in `new`); a native maker with a 43-char id: 162 B (test settle_pays_both_legs)')
MEASURED_STORAGE_BYTES['orderCancelledUa'] = (
    115, 'order record of a UA maker, cancelled: as orderFilledUa with value OrderClose::Cancelled 1 B '
         '(test cancel_filled_order_refused)')
MEASURED_STORAGE_BYTES['minNonceUa'] = (
    114, 'min_nonce record of a UA maker: key b"n" ‖ Borsh((Holder::Ua, lane)) 66 B, value u64 8 B, record overhead 40 B; '
         'any = 81 + Borsh(holder) (test min_nonce_cap_refused)')
MEASURED_STORAGE_BYTES['dexEntry'] = (
    706, 'DEX escrow entry of a settle: key b"s" ‖ settle_id 33 B + Borsh(Settle) (legs: token, seller, lane, nonce, '
         'digest, amount; relayer, deposit, expiry, done) + 40 B, and two leg-index records (key b"l" ‖ digest 33 B, '
         'value settle_id 32 B, + 40 B = 105 B each); = 283 + Borsh(Settle); 706 B for a UA seller and a native seller with '
         '43-char token / seller / relayer ids (test settle_pays_both_legs); pruned after both expiries, the deposit back '
         'to the submitting relayer')
SANDBOX_BYTE_COST = 10**19                          # near-sandbox protocol config storage_amount_per_byte (yocto)


def storage_section():
    return {'note': 'deposit = bytes × env::storage_byte_cost() read at run time; depositSandbox at the sandbox '
                    'protocol config (%d yocto per byte)' % SANDBOX_BYTE_COST,
            'records': {k: {'bytes': b, 'layout': lay, 'depositSandbox': str(b * SANDBOX_BYTE_COST)}
                        for k, (b, lay) in MEASURED_STORAGE_BYTES.items()}}


def selftest(doc):
    V.selftest_primitives()
    net = V.unhx(doc['network'])
    for r in doc['relayRefs']:                       # independent recompute from the row's own bytes
        call = V.unhx(r['call'])
        assert len(call) == r['callLength']
        assert V.unhx(r['targetBytes']) == bytes([len(r['target'])]) + r['target'].encode()
        ref = V.keccak256(b'scaas.relayfee' + net + V.unhx(r['targetBytes']) + V.keccak256(call) + V.unhx(r['salt']))
        assert V.hx(ref) == r['ref'] and V.hx(V.keccak256(b'scaas.pay.lane' + ref)) == r['lane'], r['name']
        pay = next(m for m in doc['metaops']['vectors'] if m['name'] == r['payment'])
        f = pay['fields']
        assert f['extra'] == r['salt'] and f['pay_ref'] == r['ref'] and f['lane'] == r['lane'] and f['nonce'] == 0
    rows = {r['name']: r for r in V.paymeta_rows()}
    for m in doc['metaops']['vectors']:
        assert V.hx(V.sha256(V.unhx(m['encoding']))) == m['digest']
        if 'params' in m:                            # key ops and mandate ops bind their parameters
            assert m['fields']['extra'] == V.hx(V.sha256(V.unhx(m['params'])))
            assert m['fields']['amount'] == '0' or m['fields']['op'] in (V.OP['mandate_open'], V.OP['mandate_pay'])
        if 'paymetaRow' in m:
            r = rows[m['paymetaRow']]
            assert m['fields']['pay_ref'] == r['payId'] and m['fields']['lane'] == r['payLane']
    assert len(rows) == sum('paymetaRow' in m for m in doc['metaops']['vectors'])
    legs = {m['name']: m for m in doc['metaops']['vectors'] if 'order' in m}
    for m in legs.values():                          # leg extra = sha256(Borsh(Order)), amount = sell_amount
        o = V.unhx(m['order'])
        assert m['fields']['extra'] == V.hx(V.sha256(o)) and m['fields']['op'] == V.OP['trade']
        n = struct.unpack('<I', o[:4])[0]
        assert m['fields']['contract'] == o[4:4 + n].decode()
        m2 = 4 + n + 4 + struct.unpack('<I', o[4 + n:8 + n])[0]
        assert int.from_bytes(o[m2:m2 + 16], 'little') == int(m['fields']['amount'])
    d = doc['dexSettle']
    a, b = (V.unhx(legs[n]['digest']) for n in d['legs'])
    assert d['settleId'] == V.hx(V.sha256(a, b))
    k23 = [r for r in V._KINDS['natives'] if r['kind'] == 0x17]
    assert k23 and all(r['id'] == r['raw'] for r in k23)    # kind 0x0017 ids are the 32 bytes themselves


def build():
    first = METAOPS[0]
    payload, h = nep413(V.unhx(first['digest']), TOKEN)
    k1 = next(m for m in METAOPS if m['auth']['kind'] == 'secp256k1')
    hs, hv = V.high_s(V.unhx(k1['auth']['sig']), k1['auth']['v'], V.SECP256K1)
    pk = next(m for m in METAOPS if m['auth']['kind'] == 'passkey')
    doc = {
        'note': 'Generated by smartcontracts/near/scripts/gen_vectors.py (python3 -I, --check); never edit by hand. '
                'Read by the NEAR contracts, the scaas-node NEAR adapter and the clients.',
        'network': V.hx(NETWORK),
        'accounts': {'note': 'placeholders: the *.test.near names stand in for the deployed accounts; the tasks '
                             'that deploy those contracts replace them',
                     'token': TOKEN, 'tokenB': TOKEN_B, 'router': ROUTER, 'executor': EXECUTOR, 'dex': DEX, 'alice': ALICE, 'bob': BOB,
                     'relayer': RELAYER},
        'keys': {'alice': {'ed25519': V.hx(alice.pk)}, 'erin': {'ed25519': V.hx(erin.pk), 'ua': V.hx(UA_ERIN)},
                 'carol': {'secp256k1': V.hx(carol.key), 'ua': V.hx(UA_CAROL)},
                 'dave': {'p256': V.hx(dave.key), 'ua': V.hx(UA_DAVE)}},
        'metaops': {
            'encoding': 'b"scaas.metaop.v1" ‖ borsh(MetaOp {network [u8;32], contract AccountId, op u8, from Holder, '
                        'to Holder, relayer Option<AccountId>, amount u128, pay_ref [u8;32], lane [u8;32], nonce u64, '
                        'valid_until u64 (s), extra [u8;32]}); Holder = 0 Near(AccountId) | 1 Ua([u8;32])',
            'digest': 'sha256(encoding)',
            'codes': V.op_codes('Borsh'),
            'vectors': METAOPS + transfer_vectors() + key_op_vectors() + recovery_vectors() + mandate_vectors()
                       + dex_vectors()},
        'signing': {'form': 'NEP-413', 'tag': NEP413_TAG, 'tagBytes': V.hx(u32(NEP413_TAG)), 'metaop': first['name'],
                    'message': first['text'], 'nonce': first['digest'], 'recipient': TOKEN, 'callbackUrl': None,
                    'payload': V.hx(payload), 'hash': V.hx(h), 'key': first['auth']['key'],
                    'sig': first['auth']['sig']},
        'secp256k1': {'form': 'env::ecrecover over the op digest (kind 0x0108 raw digest), v = recovery id 0 / 1, low s',
                      'metaop': k1['name'], 'digest': k1['digest'], 'key': k1['auth']['key'], 'sig': k1['auth']['sig'],
                      'v': k1['auth']['v'], 'highS': {'sig': V.hx(hs), 'v': hv, 'expect': 'refused'}},
        'passkey': {'metaop': pk['name'], 'challenge': V.b64url(V.unhx(pk['digest'])), **pk['auth'],
                    'webauthnSoft': V.webauthn_soft()},
        'nativeIds': {'kind': 0x17, 'rows': NATIVE, 'invalid': NATIVE_INVALID,
                      'note': 'a 64-lower-case-hex id is always implicit, so a named id collides with it only through '
                              'a sha256 preimage'},
        'keyRecord': {'encoding': 'Borsh KeyRecord { kind u16, key_data Vec<u8> }; id = UA(kind, key_data)',
                      'kinds': {'ed25519': V.KIND_ED25519, 'secp256k1': V.KIND_SECP256K1,
                                'webauthn-p256': V.KIND_WEBAUTHN_P256, 'msig': KIND_MSIG},
                      'msigMaxMembers': 12},
        'msig': {'keyData': V.hx(MSIG.key_data), 'ua': V.hx(MSIG.ua), 'threshold': 2,
                 'members': [{'kind': k, 'id': V.hx(i), 'weight': w} for k, i, w in MSIG.members],
                 'predecessor': ALICE,
                 'note': 'near-account member alice.test.near (id sha256 of the id) counts only as the predecessor'},
        'relayRefs': RELAY_REFS,
        'dexSettle': SETTLE,
        'storage': storage_section(),
    }
    selftest(doc)
    return doc


if __name__ == '__main__':
    V.emit(OUT, build(), sys.argv)
