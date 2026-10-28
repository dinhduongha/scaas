"""R5: the generator's vectors (`vectors/algorand-vectors.json`, `smartcontracts/vectors/metatx/paymeta.json`) against
the apps' own derivations (`contracts/common.py`) run on the AVM (the probe app, simulate)."""
import base64
import json
import os

from algosdk import abi, encoding

from conftest import LABEL, METAOP_T, REPO, ROOT, Acct, sha256, view

V = json.load(open(os.path.join(ROOT, 'vectors', 'algorand-vectors.json')))
PAYMETA = json.load(open(os.path.join(REPO, 'smartcontracts', 'vectors', 'metatx', 'paymeta.json')))


def unhx(s):
    return bytes.fromhex(s[2:])


def op_of(f):
    h = lambda x: [x['kind'], unhx(x['id'])]  # noqa: E731
    return [unhx(f['network']), unhx(f['contract']), f['op'], h(f['from']), h(f['to']), unhx(f['relayer']),
            int(f['amount']), unhx(f['pay_ref']), unhx(f['lane']), f['nonce'], f['valid_until'], unhx(f['extra'])]


def test_metaop_vectors(probe):
    rows = V['metaops']['vectors']
    assert {r['fields']['op'] for r in rows} >= {0, 4, 5}
    for r in rows:
        o = op_of(r['fields'])
        assert LABEL + METAOP_T.encode(o) == unhx(r['encoding']), r['name']   # the ARC-4 layout of the ABI type
        assert bytes(view(probe, 'op_digest', o)) == unhx(r['digest']), r['name']


def test_sign_bytes_vectors(probe):
    s = V['signing']
    d = unhx(next(r for r in V['metaops']['vectors'] if r['name'] == s['metaop'])['digest'])
    assert bytes(view(probe, 'op_sign_bytes', d)) == unhx(s['signBytes'])
    assert unhx(s['signBytes'])[:2] == b'MX' and unhx(s['signBytes'])[2:] == s['text'].encode()
    # the same bytes a wallet signs through py-algorand-sdk's util.sign_bytes (deterministic ed25519)
    alice = Acct(base64.b64encode(sha256(b'alice') + unhx(s['key'])).decode())
    assert alice.addr == s['address'] and alice.sign_op(d) == unhx(s['sig'])
    # the AVM check by the address's current authority (an address never seen on chain: itself)
    assert view(probe, 'native_ok', s['address'], d, unhx(s['sig'])) is True
    bad = bytearray(unhx(s['sig']))
    bad[0] ^= 1
    assert view(probe, 'native_ok', s['address'], d, bytes(bad)) is False
    assert view(probe, 'native_ok', V['keys']['bob']['address'], d, unhx(s['sig'])) is False


def test_pay_meta_vectors(probe):
    fit = [r for r in PAYMETA if len(r['meta']) // 2 - 1 <= 1900]
    # long_body_4096 (4,192 B) cannot reach the AVM: above the 2,048 B app-call argument limit and the 4,096 B
    # stack-value limit, so no Algorand pay-meta can carry it (the node's cap is far below, test_pay_meta_cap_measured)
    assert [r['name'] for r in PAYMETA if r not in fit] == ['long_body_4096'] and len(fit) == 5
    for r in fit:
        pid = bytes(view(probe, 'pay_id', unhx(r['salt']), unhx(r['meta'])))
        assert pid.hex() == r['payId'][2:], r['name']
        assert bytes(view(probe, 'lane_of', pid)).hex() == r['payLane'][2:], r['name']
    net = unhx(V['network'])
    for r in V['relayRefs']:
        if r['callLength'] > 1900:      # above the 2,048 B argument limit: a hash vector only
            continue
        ref = view(probe, 'ref_of', net, unhx(r['target']), unhx(r['call']), unhx(r['salt']))
        assert bytes(ref) == unhx(r['ref']), r['name']


def test_native_ids_are_the_address_keys():
    for r in V['nativeIds']['rows']:
        assert encoding.encode_address(unhx(r['key'])) == r['address']


def test_key_op_vectors(account):
    """T12 (R5): every key-op row's `extra` is sha256 of its parameters, which are the ARC-4 encoding of the entry's
    argument types (the encoding the account app hashes); its `authBytes` verify on the AVM for its signer
    (`verify_mbr`: a lazily opened UA needs its record's MBR, a native wallet signature none)."""
    rows = [r for r in V['metaops']['vectors'] if 6 <= r['fields']['op'] <= 12]
    assert {r['fields']['op'] for r in rows} == set(range(6, 13))
    for r in rows:
        p, t = unhx(r['params']), r['paramsType']
        assert sha256(p) == unhx(r['fields']['extra']), r['name']
        if t != 'action':
            typ = abi.ABIType.from_string(t) if t != '()' else None
            assert typ is None and p == b'' or typ.encode(typ.decode(p)) == p, r['name']
        frm = r['fields']['from']
        need = view(account, 'verify_mbr', frm['kind'], unhx(frm['id']), unhx(r['digest']), unhx(r['authBytes']))
        assert (need == 0) == (r['auth']['kind'] == 'native'), r['name']
