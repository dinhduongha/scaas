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
TOKEN_APP, ROUTER_APP, TARGET_APP = 1001, 1002, 1003
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


def metaop(name, signer, frm, to, amount, pay_ref, lane, nonce=0, relayer_=V.ZERO32, extra=V.ZERO32, note=None):
    op = {'contract': TOKEN, 'op': V.OP['pay'], 'from': frm, 'to': to, 'relayer': relayer_, 'amount': amount,
          'pay_ref': pay_ref, 'lane': lane, 'nonce': nonce, 'valid_until': VU, 'extra': extra}
    enc = encode(op)
    assert len(enc) == ENCODING_LEN
    dg = V.sha256(enc)
    row = {'name': name, 'fields': {
        'network': V.hx(NETWORK), 'contract': V.hx(TOKEN), 'contractApp': TOKEN_APP, 'op': op['op'],
        'from': holder_json(frm), 'to': holder_json(to), 'relayer': V.hx(relayer_), 'amount': str(amount),
        'pay_ref': V.hx(pay_ref), 'lane': V.hx(lane), 'nonce': nonce, 'valid_until': VU, 'extra': V.hx(extra)},
        'encoding': V.hx(enc), 'digest': V.hx(dg), 'text': V.text(dg).decode(), 'auth': auth(signer, dg)}
    if note:
        row['note'] = note
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
]


# ---------------------------------------------------------------- extension points (ruling R5)
def transfer_vectors():
    """Ops 4 transfer, 5 execute_transfer (`mtx_transfer`, `mtx_execute_transfer`): Task 11 adds rows here."""
    return []


def key_op_vectors():
    """Ops 6–10 (`mtx_add_key` … `mtx_set_guardian`): Task 12 adds rows, `extra = sha256(ARC-4(params))`."""
    return []


def recovery_vectors():
    """Ops 11 start_recovery, 12 cancel_recovery: Task 12 adds rows, `extra = sha256(ARC-4(params))`."""
    return []


def mandate_vectors():
    """Ops 2 mandate_pay, 3 revoke, 13 mandate_open (`MandateTerms`): Task 13 adds rows."""
    return []


def dex_vectors():
    """Ops 1 trade (`Order`, `extra = sha256(ARC-4(Order))`), 14 cancel, 15 invalidate_nonces: Task 14 adds rows."""
    return []


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
