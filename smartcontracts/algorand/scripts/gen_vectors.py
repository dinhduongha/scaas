#!/usr/bin/env python3
"""Algorand family vectors (near-algorand plan Task 3; spec §2 rows 1, 3, 8, §4.1, §4.6, §4.8, §8)
→ `vectors/algorand-vectors.json`.

    python3 -I smartcontracts/algorand/scripts/gen_vectors.py [--check]

Fixed seeds (key = seed sha256(name)), deterministic signatures (ed25519; ECDSA by RFC 6979), so `--check` compares
the whole file and fails on drift or when it is missing. A self-test runs first: every `paymeta.json` row's
`payId` / `payLane`, every `relayRefs` row recomputed from its own bytes, every signature verified.

Encoding (pinned here; spec §11 builder detail): `encode = b"scaas.metaop.v1" ‖ ARC-4 static tuple` (big-endian),
field order network byte[32], contract byte[32] (the token app address), op uint8, from (uint8 kind, byte[32]),
to (uint8 kind, byte[32]), relayer byte[32] (zero = any), amount uint128, pay_ref byte[32], lane byte[32],
nonce uint64, valid_until uint64 (s), extra byte[32]; holder kind 0 = address (its 32-byte key), 1 = UA id;
306 bytes in all; `digest = sha256(encode)`.

Extension points (ruling R5): the ops whose parameter structs later tasks define add their vectors in the function
named for their family below (`transfer_vectors`, `key_op_vectors`, `recovery_vectors`, `mandate_vectors`,
`dex_vectors`), and their box kinds to `MBR_BOXES`.
"""
import base64
import hashlib
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', 'vectors', 'metatx'))
import famvec as V  # noqa: E402

OUT = os.path.join(V.REPO, 'smartcontracts', 'algorand', 'vectors', 'algorand-vectors.json')
NETWORK = V.seed('scaas.algorand.test-genesis')     # stands in for `global GenesisHash`
TOKEN_APP, ROUTER_APP, TARGET_APP, ACCOUNT_APP, MANDATE_APP, DEX_APP, TOKEN_B_APP = 1001, 1002, 1003, 1004, 1005, 1006, 1007
VU = 4_102_444_800                                  # 2100-01-01 in seconds
SIGN_PREFIX = b'MX'
ENCODING_LEN = 306


def sha512_256(b):
    return hashlib.new('sha512_256', b).digest()


def address(key):
    return base64.b32encode(key + sha512_256(key)[-4:]).decode().rstrip('=')


def address_key(addr):
    raw = base64.b32decode(addr + '=' * (-len(addr) % 8))
    assert len(raw) == 36 and sha512_256(raw[:32])[-4:] == raw[32:], 'bad checksum'
    return raw[:32]


def app_address(app_id):
    return sha512_256(b'appID' + app_id.to_bytes(8, 'big'))


def selector(signature):
    return sha512_256(signature.encode())[:4]


TOKEN = app_address(TOKEN_APP)
ROUTER = app_address(ROUTER_APP)
ACCOUNT = app_address(ACCOUNT_APP)
MANDATE = app_address(MANDATE_APP)
DEX = app_address(DEX_APP)
TOKEN_B = app_address(TOKEN_B_APP)
alice = V.Ed('alice')                               # a native address (signs with its own key: not rekeyed)
bob = V.Ed('bob')
relayer = V.Ed('relayer')
erin = V.Ed('erin')                                 # ed25519 UA
carol = V.Ecdsa('carol', V.SECP256K1)               # secp256k1 UA (kind 0x0108)
dave = V.Ecdsa('dave', V.P256)                      # webauthn-p256 UA (kind 0x0100)
UA_ERIN = V.ua_of(V.KIND_ED25519, erin.pk)
UA_CAROL = V.ua_of(V.KIND_SECP256K1, carol.key)
UA_DAVE = V.ua_of(V.KIND_WEBAUTHN_P256, dave.key + V.sha256(V.RP_ID.encode()))


def addr(key):
    return (0, key)


def ua(i):
    return (1, i)


def holder_json(h):
    j = {'kind': h[0], 'id': V.hx(h[1])}
    if h[0] == 0:
        j['address'] = address(h[1])
    return j


def encode(op):
    return (V.LABEL + NETWORK + op['contract'] + bytes([op['op']]) + bytes([op['from'][0]]) + op['from'][1]
            + bytes([op['to'][0]]) + op['to'][1] + op['relayer'] + op['amount'].to_bytes(16, 'big') + op['pay_ref']
            + op['lane'] + struct.pack('>QQ', op['nonce'], op['valid_until']) + op['extra'])


def auth(signer, digest):
    if isinstance(signer, V.Ed):
        sb = SIGN_PREFIX + V.text(digest)
        return {'kind': 'ed25519', 'key': V.hx(signer.pk), 'signBytes': V.hx(sb), 'sig': V.hx(signer.sign(sb))}
    if signer.c is V.SECP256K1:
        sig, v = signer.sign(digest)
        return {'kind': 'secp256k1', 'key': V.hx(signer.key), 'sig': V.hx(sig), 'v': v}
    return V.passkey(signer, digest)


METAOPS = []


def metaop(name, signer, frm, to, amount, pay_ref, lane, nonce=0, relayer_=V.ZERO32, extra=V.ZERO32, note=None,
           code=V.OP['pay'], keep=True, contract=TOKEN):
    op = {'contract': contract, 'op': code, 'from': frm, 'to': to, 'relayer': relayer_, 'amount': amount,
          'pay_ref': pay_ref, 'lane': lane, 'nonce': nonce, 'valid_until': VU, 'extra': extra}
    enc = encode(op)
    assert len(enc) == ENCODING_LEN
    dg = V.sha256(enc)
    row = {'name': name, 'fields': {
        'network': V.hx(NETWORK), 'contract': V.hx(contract),
        'contractApp': {ACCOUNT: ACCOUNT_APP, MANDATE: MANDATE_APP, TOKEN_B: TOKEN_B_APP}.get(contract, TOKEN_APP), 'op': op['op'],
        'from': holder_json(frm), 'to': holder_json(to), 'relayer': V.hx(relayer_), 'amount': str(amount),
        'pay_ref': V.hx(pay_ref), 'lane': V.hx(lane), 'nonce': nonce, 'valid_until': VU, 'extra': V.hx(extra)},
        'encoding': V.hx(enc), 'digest': V.hx(dg), 'text': V.text(dg).decode(), 'auth': auth(signer, dg)}
    if note:
        row['note'] = note
    if keep:
        METAOPS.append(row)
    return row


def b32(x):
    return bytes([x]) * 32


# ---------------------------------------------------------------- pay ops (op 0)
metaop('pay', alice, addr(alice.pk), addr(bob.pk), 100, b32(0x01), b32(0xa1))
metaop('pay_ua_ed25519_u128_max', erin, ua(UA_ERIN), addr(alice.pk), V.U128_MAX, b32(0x02), b32(0xa2),
       note='amount 2^128 - 1 (Review Focus 5)')
metaop('pay_ua_secp256k1', carol, ua(UA_CAROL), ua(UA_ERIN), 2**64 + 1, b32(0x03), b32(0xa3), nonce=7)
metaop('pay_ua_passkey', dave, ua(UA_DAVE), addr(bob.pk), 7, b32(0x04), b32(0xa4))
metaop('relay_pay', alice, addr(alice.pk), addr(bob.pk), 25, b32(0x05), b32(0xa5), nonce=1, relayer_=relayer.pk,
       note='relayer bound: only that Txn.Sender may submit (§2 row 7)')
for r in V.paymeta_rows():
    pid = V.unhx(r['payId'])
    row = metaop('pay_meta_' + r['name'], alice, addr(alice.pk), addr(bob.pk), 100, pid, V.pay_lane(pid),
                 note='mtx_pay_meta(op, auth, salt, meta) of paymeta.json row %s: pay_ref = payId, lane = payLane, '
                      'nonce 0' % r['name'])
    row['paymetaRow'] = r['name']


# ---------------------------------------------------------------- relay fee (§4.8): router `call` and `ref`
def router_call(app_id, args):
    """`call = target app id (u64 BE) ‖ u8 n ‖ (u16 BE len ‖ arg)×n` (the target's application arguments)."""
    return app_id.to_bytes(8, 'big') + bytes([len(args)]) + b''.join(len(a).to_bytes(2, 'big') + a for a in args)


def filler(tag, n):
    out = b''
    while len(out) < n:
        out += V.sha256(tag.encode(), len(out).to_bytes(4, 'big'))
    return out[:n]


# The method signature is a placeholder (Task 12 defines the account app's ABI); the vector pins the `call` layout.
METHOD = 'mtx_add_key(byte[])void'
RELAY_REFS = []


def relay(name, args, salt, note=None):
    call = router_call(TARGET_APP, args)
    target = app_address(TARGET_APP)
    r = V.relay_ref(NETWORK, target, call, salt)
    pay = metaop('relay_fee_pay_' + name, alice, addr(alice.pk), addr(ROUTER), 10, r, V.pay_lane(r), relayer_=ROUTER,
                 extra=salt, note='payment of relayRefs %s: pay_ref = ref, lane = payLane(ref), nonce 0, extra = '
                                  'salt (ruling R11); open mode to = relayer = router address' % name)
    row = {'name': name, 'kind': 'router', 'targetApp': TARGET_APP, 'target': V.hx(target),
           'targetAddress': address(target), 'args': [V.hx(a) for a in args], 'call': V.hx(call),
           'callLength': len(call), 'callHash': V.hx(V.keccak256(call)), 'salt': V.hx(salt), 'ref': V.hx(r),
           'lane': V.hx(V.pay_lane(r)), 'payment': pay['name']}
    if note:
        row['note'] = note
    RELAY_REFS.append(row)


relay('router_short', [selector(METHOD), filler('router_short', 60)], b32(0x61))
relay('router_4096', [selector(METHOD), filler('router_4096', 4096 - 8 - 1 - 2 - 4 - 2)], b32(0x62),
      note='hash vector only: above the 2,048 B app-call argument limit, never submitted')


# ---------------------------------------------------------------- MBR (§2 row 15): 2500 + 400·(name + value) µALGO
def mbr(name_len, value_len):
    return 2500 + 400 * (name_len + value_len)


def lane_box(kind, h, lane):
    return b'l' + V.sha256(bytes([kind]), h, lane)


# (box kind, example name, value length); later tasks add theirs (account records, mandates, orders, allowances)
MBR_BOXES = [
    ('balance', b'b' + alice.pk, 32, '"b" ‖ address → uint256'),
    ('ua_balance', b'u' + UA_ERIN, 32, '"u" ‖ UA id → uint256'),
    ('lane', lane_box(0, alice.pk, b32(0xa1)), 8, '"l" ‖ sha256(kind ‖ holder ‖ lane) → uint64 nonce'),
    ('allowance', b'a' + V.sha256(alice.pk, ROUTER), 32, '"a" ‖ sha256(owner ‖ spender) → uint256 (app-to-app only)'),
    ('account_record', b's' + bytes([1]) + UA_ERIN, 118 + 32, 'account app: "s" ‖ kind ‖ id → record (118 B header + '
                                                             '32 per key and origin); here one key'),
]
# Mandate app (T13): the mandate (owner 33 ‖ terms 130 ‖ period_start 8 ‖ spent 16 ‖ remaining 16 ‖ revoked 1) and a
# paid pay_ref's lane; ids from the mandate rows below (appended there)


# ---------------------------------------------------------------- extension points (ruling R5)
def transfer_vectors():
    """Ops 4 transfer (`mtx_transfer`, no pay_ref), 5 execute_transfer (`mtx_execute_transfer`, any pay_ref)."""
    return [metaop('transfer', alice, addr(alice.pk), ua(UA_ERIN), 42, V.ZERO32, b32(0xa6), code=V.OP['transfer'],
                   keep=False, note='mtx_transfer: op 4, pay_ref zero, extra payer-chosen'),
            metaop('execute_transfer', alice, addr(alice.pk), addr(bob.pk), 43, b32(0x07), b32(0xa7), nonce=2,
                   code=V.OP['execute_transfer'], keep=False, extra=b32(0x5e),
                   note='mtx_execute_transfer: op 5, any pay_ref (payment_settled when non-zero)')]


# Key ops (Task 12, spec §4.3; account app, contract = its address): amount 0, pay_ref / lane zero, nonce = the
# signer's key nonce, to = from (start / finish recovery: from = the guardian, to = the subject), extra =
# sha256(ARC-4 tuple of the entry parameters after (op, auth)); set_policy / finish_recovery are actions under codes
# 10 / 11 with signed parameters [6, policy] / [7]. `authBytes` = the account app's auth encoding (account.py).
KIND_ALGORAND_ADDRESS, KIND_MSIG = 0x0018, 0x0120


def u16(n):
    return n.to_bytes(2, 'big')


def arc4_bytes(b):
    return u16(len(b)) + b


def key_record(kind, data):
    """ARC-4 `KeyRecord (uint16 kind, byte[] key_data)`: kind ‖ offset 4 ‖ len ‖ data."""
    return u16(kind) + u16(4) + arc4_bytes(data)


def tup(*dyn):
    """An ARC-4 tuple of dynamic elements: the u16 offsets, then the elements."""
    head, off, tail = b'', 2 * len(dyn), b''
    for e in dyn:
        head, off, tail = head + u16(off), off + len(e), tail + e
    return head + tail


def account_auth(signer, digest):
    """The account app's `auth`: a native address's 64-byte wallet signature, else tag ‖ body."""
    if isinstance(signer, Msig):
        return signer.auth(digest)
    if isinstance(signer, V.Ed):
        return bytes([1]) + signer.pk + signer.sign(SIGN_PREFIX + V.text(digest))
    if signer.c is V.SECP256K1:
        return bytes([2]) + signer.key + signer.sign(digest)[0]
    p = V.passkey(signer, digest)
    ad = V.unhx(p['authenticatorData'])
    return bytes([3]) + signer.key + V.unhx(p['sig']) + u16(len(ad)) + ad + p['clientDataJSON'].encode()


class Msig:
    """`msig` (kind 288) key data and its auth (member index ‖ u16 len ‖ member auth; an algorand-address member signs
    with its wallet key)."""

    def __init__(self, threshold, members):
        self.rows = sorted(members, key=lambda m: m[1])
        self.key_data = u16(threshold) + u16(len(members)) + b''.join(u16(k) + i + u16(w) for k, i, w, _ in self.rows)
        self.ua = V.ua_of(KIND_MSIG, self.key_data)

    def auth(self, digest):
        sigs = b''
        for i, (k, _, _, s) in enumerate(self.rows):
            a = s.sign(SIGN_PREFIX + V.text(digest)) if k == KIND_ALGORAND_ADDRESS else account_auth(s, digest)
            sigs += bytes([i]) + u16(len(a)) + a
        return bytes([4]) + u16(len(self.key_data)) + self.key_data + sigs


frank = V.Ed('frank')
SEC_KEY = key_record(V.KIND_SECP256K1, carol.key)
DAVE_KEY = key_record(V.KIND_WEBAUTHN_P256, dave.key + V.sha256(V.RP_ID.encode()))
FRANK_KEY = key_record(V.KIND_ED25519, frank.pk)
APP_ORIGIN = b'https://app.scaas.test'
MSIG = Msig(2, [(KIND_ALGORAND_ADDRESS, alice.pk, 1, alice), (V.KIND_ED25519, UA_ERIN, 1, erin)])
KEY_OPS = []


def key_op(name, code, signer, frm, params, ptype, nonce, to=None, note=None):
    row = metaop(name, alice, frm, to or frm, 0, V.ZERO32, V.ZERO32, nonce=nonce, extra=V.sha256(params), note=note,
                 code=V.OP[code], keep=False, contract=ACCOUNT)
    dg = V.unhx(row['digest'])
    native = frm[0] == 0 and signer is alice
    a = alice.sign(SIGN_PREFIX + V.text(dg)) if native else account_auth(signer, dg)
    row['auth'] = {'kind': 'native' if native else 'account'}
    row['authBytes'] = V.hx(a)
    row['params'], row['paramsType'] = V.hx(params), ptype
    KEY_OPS.append(row)
    return row


KR = '(uint16,byte[])'
key_op('add_key_secp256k1', 'add_key', erin, ua(UA_ERIN), tup(SEC_KEY, arc4_bytes(b'')), '(%s,byte[])' % KR, 0,
       note='mtx_add_key(op, auth, key, origin empty = none); opens UA erin lazily (key nonce 0)')
key_op('add_key_passkey_with_origin', 'add_key', carol, ua(UA_CAROL), tup(DAVE_KEY, arc4_bytes(V.ORIGIN.encode())),
       '(%s,byte[])' % KR, 0, note='mtx_add_key(op, auth, key = webauthn-p256 x ‖ y ‖ rpIdHash, origin)')
key_op('remove_key', 'remove_key', erin, ua(UA_ERIN), tup(SEC_KEY), '(%s)' % KR, 1,
       note='mtx_remove_key(op, auth, key)')
key_op('add_origin_passkey', 'add_origin', dave, ua(UA_DAVE), tup(arc4_bytes(APP_ORIGIN)), '(byte[])', 0,
       note='mtx_add_origin(op, auth, origin); passkey UA opened lazily with its assertion origin')
key_op('remove_origin', 'remove_origin', dave, ua(UA_DAVE), tup(arc4_bytes(APP_ORIGIN)), '(byte[])', 1,
       note='mtx_remove_origin(op, auth, origin)')
key_op('set_guardian', 'set_guardian', erin, ua(UA_ERIN), bytes([0]) + alice.pk, '((uint8,byte[32]))', 2,
       note='mtx_set_guardian(op, auth, guardian Holder (0, alice)); zero holder = none')
key_op('set_policy', 'set_guardian', erin, ua(UA_ERIN), bytes([6, 1]), 'action', 3,
       note='mtx_set_policy(op, auth, policy uint8): the set_policy action under op code 10, signed params '
            '[KEYOP_SET_POLICY 6, policy] (POLICY_PASSKEY_FOR_VALUE = 1); a wallet-kind key may sign')
key_op('set_guardian_msig', 'set_guardian', MSIG, ua(MSIG.ua), bytes(33), '((uint8,byte[32]))', 0,
       note='msig UA (algorand-address alice, wallet signature by her current authority + ed25519 erin), guardian none')


def key_op_vectors():
    """Ops 6–10 (`mtx_add_key` … `mtx_set_guardian`), `extra = sha256(ARC-4(params))`."""
    return [r for r in KEY_OPS if r['fields']['op'] <= V.OP['set_guardian']]


key_op('start_recovery', 'start_recovery', alice, addr(alice.pk), tup(FRANK_KEY, arc4_bytes(b'')), '(%s,byte[])' % KR,
       0, to=ua(UA_ERIN), note='mtx_start_recovery(op, auth, key, origin): from = the guardian (alice, wallet '
                               'signature), to = the subject; finish after 172,800 s adds the key (CTR-ACC-03)')
key_op('finish_recovery', 'start_recovery', alice, addr(alice.pk), bytes([7]), 'action', 1, to=ua(UA_ERIN),
       note='mtx_finish_recovery(op, auth): the finish_recovery action under op code 11, signed params '
            '[KEYOP_FINISH_RECOVERY 7]; adds the recovery key, removes none')
key_op('cancel_recovery', 'cancel_recovery', erin, ua(UA_ERIN), b'', '()', 4,
       note='mtx_cancel_recovery(op, auth): no params')


def recovery_vectors():
    """Ops 11 start_recovery, 12 cancel_recovery, `extra = sha256(ARC-4(params))`."""
    return [r for r in KEY_OPS if r['fields']['op'] >= V.OP['start_recovery']]


# Mandate (Task 13, spec §4.7 → §3.6; the mandate app, contract = its address; state keyed by (token app id, id)).
# `MandateTerms` ARC-4 = delegate (uint8,byte[32]) ‖ payee (uint8,byte[32]) ‖ per_payment uint128 ‖ per_period uint128
# ‖ period_s uint64 ‖ expiry uint64 ‖ funding uint128 (130 B, big-endian). Open (Ruling T13-open, fix 1 C1): the
# owner's one signed op is the funding, a token mtx_pay (op 0, contract = the token) with relayer = to = the mandate app
# address, amount = funding (R9), pay_ref = id = sha256(ARC-4(from, terms, lane, nonce)) from its own lane / nonce,
# extra = sha256(token app id u64 ‖ id ‖ terms); only mtx_mandate_open(token, op, auth, terms, fund_mbr) executes it
# (inner call; the token's rule 7 refuses it elsewhere). No op 13 on Algorand. Pay (op 2, delegate-signed): from = Ua(id), lane = payLane(pay_ref) (the NEAR vector's
# bytes), nonce 0, extra = sha256(token app id u64). Revoke (op 3, owner or delegate): to = Ua(id), amount / pay_ref /
# lane / nonce zero, extra = sha256(token app id u64). `authBytes` = the account app's auth encoding.
MANDATES = []


def mandate_terms(delegate, payee, per_payment, per_period, period_s, expiry, funding):
    return (bytes([delegate[0]]) + delegate[1] + bytes([payee[0]]) + payee[1] + per_payment.to_bytes(16, 'big')
            + per_period.to_bytes(16, 'big') + struct.pack('>QQ', period_s, expiry) + funding.to_bytes(16, 'big'))


def mandate_row(name, signer, frm, to, amount, pay_ref, lane, code, extra, note, contract=MANDATE, relayer_=V.ZERO32):
    row = metaop(name, signer, frm, to, amount, pay_ref, lane, code=code, extra=extra, note=note, keep=False,
                 contract=contract, relayer_=relayer_)
    row['authBytes'] = V.hx(account_auth(signer, V.unhx(row['digest'])))
    MANDATES.append(row)
    return row


_tok = TOKEN_APP.to_bytes(8, 'big')
_terms = mandate_terms(ua(UA_CAROL), addr(bob.pk), 100, 250, 86_400, VU, 1_000)
_lane, _nonce = b32(0xb0), 0
MANDATE_ID = V.sha256(bytes([1]) + UA_ERIN + _terms + _lane + struct.pack('>Q', _nonce))
assert len(_terms) == 130
_row = mandate_row('mandate_open', erin, ua(UA_ERIN), addr(MANDATE), 1_000, MANDATE_ID, _lane, V.OP['pay'],
                   V.sha256(_tok + MANDATE_ID + _terms),
                   'mtx_mandate_open(token 1001, op, auth, terms, fund_mbr): owner erin signs the funding token.mtx_pay '
                   '(relayer = to = the mandate app, pay_ref = the mandate id, extra = sha256(token id ‖ id ‖ terms)); '
                   'delegate carol (UA), payee bob, per payment 100, per period 250 per 86,400 s, funding 1,000 = '
                   'amount', contract=TOKEN, relayer_=MANDATE)
_row.update(params=V.hx(_tok + MANDATE_ID + _terms), terms=V.hx(_terms), mandateId=V.hx(MANDATE_ID))
_pr = b32(0x07)
mandate_row('mandate_pay', carol, ua(MANDATE_ID), addr(bob.pk), 100, _pr, V.pay_lane(_pr), V.OP['mandate_pay'],
            V.sha256(_tok), "mtx_mandate_pay(token 1001, op, auth): from = the mandate id, signed by the delegate "
            "carol; the mandate's lane payLane(pay_ref) at nonce 0 (each pay_ref once per (token, mandate))")
mandate_row('mandate_revoke', carol, ua(UA_CAROL), ua(MANDATE_ID), 0, V.ZERO32, V.ZERO32, V.OP['revoke'],
            V.sha256(_tok), "mtx_revoke(token 1001, op, auth): the delegate's kill switch (the owner may sign it too); "
            "the remaining funds go back to the owner")


MBR_BOXES += [
    ('mandate', b'm' + _tok + MANDATE_ID, 204, 'mandate app: "m" ‖ token app id u64 ‖ mandate id → Mandate'),
    ('mandate_lane', b'l' + V.sha256(_tok + MANDATE_ID + V.pay_lane(_pr)), 8,
     'mandate app: "l" ‖ sha256(token app id u64 ‖ mandate id ‖ lane) → u64 (a paid pay_ref)')]


def mandate_vectors():
    """The open (its funding op 0, `MandateTerms`), ops 2 mandate_pay, 3 revoke (op 13 unused on Algorand)."""
    return MANDATES


# DEX (Task 14, spec §4.7; the NEAR rows' values, ARC-4 here). `Order` ARC-4 = sell_token uint64 ‖ buy_token uint64
# (token app ids) ‖ sell_amount uint128 ‖ min_buy uint128 ‖ relayer byte[32] (zero = any submitter) ‖ expiry uint64
# (88 B). A leg is op 1 on the order's sell token: to = relayer = the DEX app address, amount = sell_amount, pay_ref
# zero, extra = sha256(ARC-4(Order)); only `dex.settle` pulls it (inner mtx_trade). Cancel (op 14) / invalidate_nonces
# (op 15): to = from, amount / pay_ref / lane / nonce zero, extra = sha256(ARC-4((byte[32] lane, uint64 nonce))).
DEX_OPS = []


def order(sell, buy, sell_amount, min_buy, relayer_, expiry):
    return (struct.pack('>QQ', sell, buy) + sell_amount.to_bytes(16, 'big') + min_buy.to_bytes(16, 'big') + relayer_
            + struct.pack('>Q', expiry))


def dex_row(name, signer, frm, to, amount, lane, nonce, code, extra, note, contract=TOKEN, relayer_=V.ZERO32):
    row = metaop(name, signer, frm, to, amount, V.ZERO32, lane, nonce=nonce, code=code, extra=extra, note=note,
                 keep=False, contract=contract, relayer_=relayer_)
    row['authBytes'] = V.hx(account_auth(signer, V.unhx(row['digest'])))
    DEX_OPS.append(row)
    return row


_oa = order(TOKEN_APP, TOKEN_B_APP, 100, 50, relayer.pk, VU)
_ob = order(TOKEN_B_APP, TOKEN_APP, 60, 100, V.ZERO32, VU)
assert len(_oa) == 88
_ta = dex_row('trade_a', erin, ua(UA_ERIN), addr(DEX), 100, b32(0xc0), 0, V.OP['trade'], V.sha256(_oa),
              'mtx_trade leg of order A on token 1001 (erin sells 100 for >= 50 of token 1007, order relayer bound to '
              'RELAYER): to = relayer = the DEX app address, amount = sell_amount, extra = sha256(ARC-4(Order))',
              relayer_=DEX)
_ta['order'] = V.hx(_oa)
_tb = dex_row('trade_b', carol, ua(UA_CAROL), addr(DEX), 60, b32(0xc1), 3, V.OP['trade'], V.sha256(_ob),
              'mtx_trade leg of order B on token 1007 (carol sells 60 for >= 100 of token 1001, open relayer); order '
              'lane nonce 3 (any nonce >= min_nonce)', contract=TOKEN_B, relayer_=DEX)
_tb['order'] = V.hx(_ob)
DEX_SETTLE = {'legs': ['trade_a', 'trade_b'],
              'settleId': V.hx(V.sha256(V.unhx(_ta['digest']), V.unhx(_tb['digest']))),
              'derivation': 'sha256(digest(op_a) ‖ digest(op_b)), the two leg ops in settle-argument order',
              'note': 'dex.settle(order_a, op_a, auth_a, order_b, op_b, auth_b, mbr): fill-or-kill 100 >= 100 (B min_buy) '
                      'and 60 >= 50 (A min_buy); erin receives 60 of token 1007, carol 100 of token 1001; event '
                      'Matched(settle_id, 1001, 1007, digest a, digest b)'}
_p = b32(0xc0) + struct.pack('>Q', 5)
dex_row('cancel', erin, ua(UA_ERIN), ua(UA_ERIN), 0, V.ZERO32, 0, V.OP['cancel'], V.sha256(_p),
        "mtx_cancel(op, auth, target_lane, target_nonce): closes erin's open order (lane c0, nonce 5); a filled, "
        "cancelled or voided order is refused")['params'] = V.hx(_p)
_p = b32(0xc0) + struct.pack('>Q', 10)
dex_row('invalidate_nonces', erin, ua(UA_ERIN), ua(UA_ERIN), 0, V.ZERO32, 0, V.OP['invalidate_nonces'], V.sha256(_p),
        "mtx_invalidate_nonces(op, auth, lane, min_nonce): voids erin's orders below nonce 10 on lane c0; "
        "min_nonce < 2^63, strictly increasing (CTR-DEX-10)")['params'] = V.hx(_p)
MBR_BOXES += [
    ('order', b'o' + V.sha256(bytes([1]) + UA_ERIN + b32(0xc0) + struct.pack('>Q', 0)), 1,
     'token: "o" ‖ sha256(kind ‖ holder ‖ lane ‖ nonce u64) → uint8 (1 filled, 2 cancelled)'),
    ('min_nonce', b'n' + V.sha256(bytes([1]) + UA_ERIN + b32(0xc0)), 8,
     'token: "n" ‖ sha256(kind ‖ holder ‖ lane) → uint64 min_nonce (order lanes, never the meta-tx lanes)')]


def dex_vectors():
    """Ops 1 trade (`Order`, `extra = sha256(ARC-4(Order))`), 14 cancel, 15 invalidate_nonces."""
    return DEX_OPS


def selftest(doc):
    V.selftest_primitives()
    assert address(bytes(32)) == 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ'   # the well-known zero address
    for n in doc['nativeIds']['rows']:
        assert V.hx(address_key(n['address'])) == n['key']
    net = V.unhx(doc['network'])
    for r in doc['relayRefs']:                       # independent recompute from the row's own bytes
        call = V.unhx(r['call'])
        assert len(call) == r['callLength'] and int.from_bytes(call[:8], 'big') == r['targetApp']
        args, off = [], 9
        for _ in range(call[8]):
            n = int.from_bytes(call[off:off + 2], 'big')
            args.append(V.hx(call[off + 2:off + 2 + n]))
            off += 2 + n
        assert off == len(call) and args == r['args']
        ref = V.keccak256(b'scaas.relayfee' + net + V.unhx(r['target']) + V.keccak256(call) + V.unhx(r['salt']))
        assert V.hx(ref) == r['ref'] and V.hx(V.keccak256(b'scaas.pay.lane' + ref)) == r['lane'], r['name']
        f = next(m for m in doc['metaops']['vectors'] if m['name'] == r['payment'])['fields']
        assert f['extra'] == r['salt'] and f['pay_ref'] == r['ref'] and f['lane'] == r['lane'] and f['nonce'] == 0
    rows = {r['name']: r for r in V.paymeta_rows()}
    for m in doc['metaops']['vectors']:
        assert V.hx(V.sha256(V.unhx(m['encoding']))) == m['digest']
        if 'paymetaRow' in m:
            r = rows[m['paymetaRow']]
            assert m['fields']['pay_ref'] == r['payId'] and m['fields']['lane'] == r['payLane']
    assert len(rows) == sum('paymetaRow' in m for m in doc['metaops']['vectors'])
    k24 = [r for r in V._KINDS['natives'] if r['kind'] == 0x18]
    assert k24 and all(r['id'] == r['raw'] for r in k24)    # kind 0x0018 ids are the 32-byte keys themselves
    for m in KEY_OPS:                                # key ops: extra = sha256(params), the shape of §4.3
        f = m['fields']
        assert f['extra'] == V.hx(V.sha256(V.unhx(m['params']))) and f['amount'] == '0' and f['contract'] == V.hx(ACCOUNT)
    rows = {m['name']: m for m in MANDATES}         # mandate: id, extra, funding bound to the open
    o, p = rows['mandate_open'], rows['mandate_pay']['fields']
    tid = V.unhx(o['mandateId'])
    assert V.sha256(bytes([o['fields']['from']['kind']])
                    + V.unhx(o['fields']['from']['id']) + V.unhx(o['terms']) + V.unhx(o['fields']['lane'])
                    + struct.pack('>Q', o['fields']['nonce'])) == tid
    f = o['fields']
    assert V.unhx(f['extra']) == V.sha256(V.unhx(o['params'])) and V.unhx(f['pay_ref']) == tid
    assert (f['to']['id'], f['relayer'], f['contract'], f['op']) == (V.hx(MANDATE), V.hx(MANDATE), V.hx(TOKEN), 0)
    assert p['lane'] == V.hx(V.pay_lane(V.unhx(p['pay_ref']))) and p['from']['id'] == V.hx(tid)
    rows = {m['name']: m for m in DEX_OPS}          # dex: legs bound to the DEX, the order, the sell token
    for n, tok in (('trade_a', TOKEN), ('trade_b', TOKEN_B)):
        f, o = rows[n]['fields'], V.unhx(rows[n]['order'])
        assert V.unhx(f['extra']) == V.sha256(o) and int(f['amount']) == int.from_bytes(o[16:32], 'big')
        assert (f['to']['id'], f['relayer'], f['contract'], f['op']) == (V.hx(DEX), V.hx(DEX), V.hx(tok), 1)
        assert app_address(int.from_bytes(o[:8], 'big')) == tok
    s = doc['dexSettle']
    assert s['settleId'] == V.hx(V.sha256(V.unhx(rows['trade_a']['digest']), V.unhx(rows['trade_b']['digest'])))
    for n in ('cancel', 'invalidate_nonces'):
        f = rows[n]['fields']
        assert V.unhx(f['extra']) == V.sha256(V.unhx(rows[n]['params'])) and f['to'] == f['from']
    for b in doc['mbr']['boxes']:
        assert b['microAlgo'] == 2500 + 400 * (b['nameLength'] + b['valueLength']) and b['nameLength'] <= 64


def build():
    first = METAOPS[0]
    k1 = next(m for m in METAOPS if m['auth']['kind'] == 'secp256k1')
    hs, hv = V.high_s(V.unhx(k1['auth']['sig']), k1['auth']['v'], V.SECP256K1)
    pk = next(m for m in METAOPS if m['auth']['kind'] == 'passkey')
    short = RELAY_REFS[0]
    doc = {
        'note': 'Generated by smartcontracts/algorand/scripts/gen_vectors.py (python3 -I, --check); never edit by '
                'hand. Read by the Algorand apps, the scaas-node Algorand adapter and the clients.',
        'network': V.hx(NETWORK),
        'apps': {'token': {'id': TOKEN_APP, 'address': address(TOKEN), 'key': V.hx(TOKEN)},
                 'account': {'id': ACCOUNT_APP, 'address': address(ACCOUNT), 'key': V.hx(ACCOUNT)},
                 'mandate': {'id': MANDATE_APP, 'address': address(MANDATE), 'key': V.hx(MANDATE)},
                 'dex': {'id': DEX_APP, 'address': address(DEX), 'key': V.hx(DEX)},
                 'tokenB': {'id': TOKEN_B_APP, 'address': address(TOKEN_B), 'key': V.hx(TOKEN_B)},
                 'router': {'id': ROUTER_APP, 'address': address(ROUTER), 'key': V.hx(ROUTER)},
                 'target': {'id': TARGET_APP, 'address': address(app_address(TARGET_APP)),
                            'key': V.hx(app_address(TARGET_APP))}},
        'keys': {'alice': {'ed25519': V.hx(alice.pk), 'address': address(alice.pk)},
                 'bob': {'ed25519': V.hx(bob.pk), 'address': address(bob.pk)},
                 'relayer': {'ed25519': V.hx(relayer.pk), 'address': address(relayer.pk)},
                 'erin': {'ed25519': V.hx(erin.pk), 'ua': V.hx(UA_ERIN)},
                 'carol': {'secp256k1': V.hx(carol.key), 'ua': V.hx(UA_CAROL)},
                 'dave': {'p256': V.hx(dave.key), 'ua': V.hx(UA_DAVE)}},
        'metaops': {
            'encoding': 'b"scaas.metaop.v1" ‖ ARC-4 static tuple (byte[32] network, byte[32] contract, uint8 op, '
                        '(uint8,byte[32]) from, (uint8,byte[32]) to, byte[32] relayer, uint128 amount, byte[32] '
                        'pay_ref, byte[32] lane, uint64 nonce, uint64 valid_until, byte[32] extra); holder kind 0 '
                        'address, 1 UA id; relayer zero = any; %d bytes' % ENCODING_LEN,
            'digest': 'sha256(encoding)',
            'codes': V.op_codes('ARC-4'),
            'vectors': METAOPS + transfer_vectors() + key_op_vectors() + recovery_vectors() + mandate_vectors()
                       + dex_vectors()},
        'signing': {'form': '"MX" ‖ text, ed25519verify_bare by the current authority (AcctAuthAddr, else the address)',
                    'metaop': first['name'], 'text': first['text'], 'signBytes': first['auth']['signBytes'],
                    'key': first['auth']['key'], 'address': address(V.unhx(first['auth']['key'])),
                    'sig': first['auth']['sig']},
        'secp256k1': {'form': 'ecdsa_verify Secp256k1 over the op digest (kind 0x0108 raw digest), low s; v is the '
                              'recovery id (ecdsa_pk_recover)', 'metaop': k1['name'], 'digest': k1['digest'],
                      'key': k1['auth']['key'], 'sig': k1['auth']['sig'], 'v': k1['auth']['v'],
                      'highS': {'sig': V.hx(hs), 'v': hv, 'expect': 'refused'}},
        'passkey': {'metaop': pk['name'], 'challenge': V.b64url(V.unhx(pk['digest'])), **pk['auth'],
                    'webauthnSoft': V.webauthn_soft()},
        'nativeIds': {'kind': 0x18, 'rows': [
            {'name': n, 'address': address(k), 'key': V.hx(k)} for n, k in
            (('alice', alice.pk), ('zero', bytes(32)), ('token app %d' % TOKEN_APP, TOKEN),
             ('router app %d' % ROUTER_APP, ROUTER))],
            'appAddress': 'sha512_256("appID" ‖ u64 BE app id)'},
        'relayRefs': RELAY_REFS,
        'dexSettle': DEX_SETTLE,
        'routerCall': {'layout': 'target app id (u64 BE) ‖ u8 n ‖ (u16 BE len ‖ arg)×n; arg 0 = the ARC-4 selector',
                       'targetApp': short['targetApp'], 'method': METHOD, 'selector': V.hx(selector(METHOD)),
                       'args': short['args'], 'call': short['call']},
        'mbr': {'formula': '2500 + 400·(name + value) µALGO per box', 'boxes': [
            {'kind': k, 'layout': lay, 'name': V.hx(n), 'nameLength': len(n), 'valueLength': vl,
             'microAlgo': mbr(len(n), vl)} for k, n, vl, lay in MBR_BOXES]},
    }
    selftest(doc)
    return doc


if __name__ == '__main__':
    V.emit(OUT, build(), sys.argv)
