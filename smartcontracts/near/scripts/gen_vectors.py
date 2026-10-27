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
           note=None):
    op = {'contract': TOKEN, 'op': V.OP['pay'], 'from': frm, 'to': to, 'relayer': relayer, 'amount': amount,
          'pay_ref': pay_ref, 'lane': lane, 'nonce': nonce, 'valid_until': valid_until, 'extra': extra}
    enc = encode(op)
    dg = V.sha256(enc)
    row = {'name': name, 'fields': {
        'network': V.hx(NETWORK), 'contract': TOKEN, 'op': op['op'], 'from': holder_json(frm), 'to': holder_json(to),
        'relayer': relayer, 'amount': str(amount), 'pay_ref': V.hx(pay_ref), 'lane': V.hx(lane), 'nonce': nonce,
        'valid_until': valid_until, 'extra': V.hx(extra)},
        'encoding': V.hx(enc), 'digest': V.hx(dg), 'text': V.text(dg).decode(), 'auth': auth(signer, dg, TOKEN)}
    if note:
        row['note'] = note
    METAOPS.append(row)
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
def transfer_vectors():
    """Ops 4 transfer, 5 execute_transfer (`mtx_transfer`, `mtx_execute_transfer`): Task 6 adds rows here."""
    return []


def key_op_vectors():
    """Ops 6–10 (`mtx_add_key` … `mtx_set_guardian`): Task 5 adds rows, `extra = sha256(Borsh(params))`."""
    return []


def recovery_vectors():
    """Ops 11 start_recovery, 12 cancel_recovery: Task 5 adds rows, `extra = sha256(Borsh(params))`."""
    return []


def mandate_vectors():
    """Ops 2 mandate_pay, 3 revoke, 13 mandate_open (`MandateTerms`): Task 7 adds rows."""
    return []


def dex_vectors():
    """Ops 1 trade (`Order`, `extra = sha256(Borsh(Order))`), 14 cancel, 15 invalidate_nonces: Task 8 adds rows."""
    return []


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
NATIVE_INVALID = [{'accountId': alice.pk.hex().upper(), 'reason': 'upper-case hex is not a NEAR account id: refused'}]


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
        if 'paymetaRow' in m:
            r = rows[m['paymetaRow']]
            assert m['fields']['pay_ref'] == r['payId'] and m['fields']['lane'] == r['payLane']
    assert len(rows) == sum('paymetaRow' in m for m in doc['metaops']['vectors'])
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
        'accounts': {'token': TOKEN, 'router': ROUTER, 'executor': EXECUTOR, 'dex': DEX, 'alice': ALICE, 'bob': BOB,
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
        'nativeIds': {'kind': 0x17, 'rows': NATIVE, 'invalid': NATIVE_INVALID},
        'relayRefs': RELAY_REFS,
    }
    selftest(doc)
    return doc


if __name__ == '__main__':
    V.emit(OUT, build(), sys.argv)
