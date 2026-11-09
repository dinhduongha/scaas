# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The C ABI (include/scaas_ua.h) through ctypes against smartcontracts/vectors/ua/: mirrors
clients/ua-cxx/tests/vectors_test.cpp row for row, plus the ABI edges (buffers, NULL, non-UTF-8, per-thread last error).
ABI v6 (ua-rs-sign T12): the wallet surface over keys.json, sign.json, kem.json, seal.json and vault.json (classes Wallet*);
T14: the Zether facade over zether.json and clients/zether-prover/vectors/ (class WalletZether).
From clients/ua-c after `cargo build --locked`: python3 -m unittest -v tests.test_vectors
(overrides: SCAAS_UA_C_LIB = the shared library, SCAAS_UA_VECTORS = the vectors directory)."""
import ctypes as C
import json
import os
import pathlib
import threading
import types
import unittest


HERE = pathlib.Path(__file__).resolve().parent
LIB = C.CDLL(os.environ.get('SCAAS_UA_C_LIB', str(HERE.parent / 'target' / 'debug' / 'libscaas_ua_c.so')))
VEC = pathlib.Path(os.environ.get('SCAAS_UA_VECTORS', str(HERE.parents[2] / 'smartcontracts' / 'vectors' / 'ua')))
K = json.loads((VEC / 'kinds.json').read_text())
S = json.loads((VEC / 'structures.json').read_text())
PV = json.loads((VEC / 'portable.json').read_text())
NV = json.loads((VEC / 'nested.json').read_text())
D = json.loads((VEC / 'id_display.json').read_text())

OK, ERR_KEY_DATA, ERR_ARGUMENT, ERR_BUFFER = 0, 1, 8, 9
KEM_PK = 1601  # scheme byte + key


def kem(n, scheme=1):
    return bytes([scheme]) + bytes(n - 1)


class Kind(C.Structure):
    _fields_ = [('kind', C.c_uint16), ('native', C.c_bool), ('lengths_len', C.c_uint8), ('lengths', C.c_uint32 * 2),
                ('name', C.c_char_p), ('group', C.c_char_p)]


class Member(C.Structure):
    _fields_ = [('kind', C.c_uint16), ('id', C.c_uint8 * 32), ('weight', C.c_uint16)]


class HolderPop(C.Structure):  # ScaasUaHolderPop: byte arrays only, no padding
    _fields_ = [(n, C.c_uint8 * 32) for n in ('pqz_key_hash', 'pqz_pop_hash', 'kem_record_hash', 'portable_record_digest',
                                              'registration_digest', 'message')] + [('has_member_digest', C.c_bool),
                                                                                    ('member_digest', C.c_uint8 * 32)]


class PqzKeyRecord(C.Structure):  # ScaasUaPqzKeyRecord
    _fields_ = [(n, C.c_uint8 * 32) for n in ('pqz_key_hash', 'pqz_pop_hash', 'pqz_key_digest', 'record_digest', 'message',
                                              'pqz_reg_message')] + [('has_member_digest', C.c_bool), ('member_digest', C.c_uint8 * 32)]


P, u8, u16, u32, u64, sz, bl, st = C.c_void_p, C.c_char_p, C.c_uint16, C.c_uint32, C.c_uint64, C.c_size_t, C.c_bool, C.c_int32
def member_sig_bytes(s):
    """A member's signature object: the slot's `sig`, or `abi.encode(InnerSig[])` of an `msig` member's leaves."""
    if not s['members']:
        return bytes.fromhex(s['sig'][2:])
    w = lambda x: x.to_bytes(32, 'big')
    leaves = [(x['index'], bytes.fromhex(x['sig'][2:])) for x in s['members']]
    tuples = [w(i) + w(64) + w(len(sig)) + sig + bytes(-len(sig) % 32) for i, sig in leaves]
    offs, o = [], 32 * len(tuples)
    for t in tuples:
        offs.append(w(o))
        o += len(t)
    return w(32) + w(len(tuples)) + b''.join(offs) + b''.join(tuples)


L = types.SimpleNamespace()  # L.tag is scaas_ua_tag
for name, res, args in [
    ('abi_version', u32, []), ('status_name', C.c_char_p, [st]), ('last_error', C.c_char_p, []),
    ('kind_count', sz, []), ('kind_at', st, [sz, P]), ('kind_info', st, [u16, P]),
    ('is_native', bl, [u16]), ('is_zether', bl, [u16]), ('is_pqz_holder', bl, [u16]), ('is_signing', bl, [u16]), ('is_member', bl, [u16, bl]),
    ('governance_bit', st, [C.c_uint8, P, P]),
    ('tag', st, [u16, P]), ('kind_tag_string', st, [u16, P, P]), ('group_tag', st, [u8, P, P]),
    ('group_tag_string', st, [u8, P, P, P]), ('msg_tag', st, [P]), ('purpose_tag', st, [u8, P]), ('purpose_tag_v', st, [u8, u32, P]),
    ('ua_of', st, [u16, u8, sz, P]), ('derive_ua', st, [u16, u8, sz, bl, P]), ('native_id', st, [u16, u8, sz, P]),
    ('key_hash_of', st, [u16, u8, sz, P, P]), ('validate_key_data', st, [u16, u8, sz, bl]),
    ('in_native_space', st, [u8, P]), ('ua_message', st, [u16, u8, u8, P]), ('chain_key_hash', st, [u64, P]), ('keccak256', st, [u8, sz, P]),
    ('portable_domain_separator', st, [P]), ('kem_record_hash', st, [u8, u64, u8, sz, P]),
    ('portable_record_digest', st, [u8, u16, u8, u8, P]), ('registration_digest', st, [u8, u16, u8, u8, u8, P]),
    ('kem_record_digest', st, [u8, u64, u8, sz, P]), ('kem_record_message', st, [u16, u8, u64, u8, sz, P]),
    ('holder_pop_message', st, [u16, u8, u8, sz, u8, sz, u8, sz, u8, sz, u8, sz, P]),
    ('pqz_reg_message', st, [u16, u8, u8, sz, u8, sz, P]), ('pqz_key_digest', st, [u8, u8, P]),
    ('pqz_key_record_digest', st, [u8, u8, u8, P]), ('membership_digest', st, [u8, u8, P]),
    ('pqz_key_record_message', st, [u16, u8, u8, sz, u8, sz, u8, sz, u8, sz, bl, P]),
    ('is_portable_purpose', st, [u8, P]), ('msig_pqz_eligible', st, [u8, sz, P]), ('msig_pqz_eligible_with', st, [u8, sz, u8, P]),
    ('holder_pop_message_with', st, [u16, u8, u8, sz, u8, sz, u8, sz, u8, sz, u8, sz, u8, P]),
    ('pqz_key_record_message_with', st, [u16, u8, u8, sz, u8, sz, u8, sz, u8, sz, bl, u8, P]),
    ('replayed_member_sig', st, [u8, sz, u16, u8, sz, P, P]),
    ('ua_auth_domain_separator', st, [u32, u64, u8, u8, P]),
    ('ua_auth_digest', st, [u32, u64, u8, u8, u8, u8, u8, P]), ('member_digest', st, [u8, u8, P]),
    ('canonical_id', st, [u8, P, P]), ('id_display', st, [u8, u16, P, P]), ('encode_msig', st, [u16, P, sz, P, P]), ('registration_args', st, [u8, P, P]), ('set_kem_key_args', st, [u8, P, P]), ('set_pqz_key_args', st, [u8, P, P]), ('pay_digest', st, [u8, P, P]), ('meta_pay_id', st, [u8, P, P]), ('service_pull', st, [u8, P, P]),
]:
    f = getattr(LIB, 'scaas_ua_' + name)
    f.restype, f.argtypes = res, args
    setattr(L, name, f)


class UAErr(Exception):
    def __init__(self, status):
        self.status, self.code, self.detail = status, L.status_name(status).decode(), L.last_error().decode()
        super().__init__(self.detail)


def ok(status):
    if status != OK:
        raise UAErr(status)


def out32(fn, *args):
    buf = C.create_string_buffer(32)
    ok(fn(*args, buf))
    return buf.raw


def var(fn, *args):
    """A variable output: ask for the size, then fetch."""
    n = sz(0)
    status = fn(*args, None, C.byref(n))
    if status != ERR_BUFFER:
        ok(status)
    buf = C.create_string_buffer(n.value)
    ok(fn(*args, buf, C.byref(n)))
    return buf.raw[:n.value]


def text(fn, *args):
    return var(fn, *args)[:-1].decode()  # *out_len counts the NUL


def opt32(fn, *args):
    buf, present = C.create_string_buffer(32), bl()
    ok(fn(*args, buf, C.byref(present)))
    return buf.raw if present.value else None


def opt_text(fn, g):
    n, present = sz(0), bl()
    status = fn(g, None, C.byref(n), C.byref(present))
    if not present.value:
        ok(status)
        return None
    buf = C.create_string_buffer(n.value)
    ok(fn(g, buf, C.byref(n), C.byref(present)))
    return buf.raw[:n.value - 1].decode()


def kind_row(fn, arg):
    k = Kind()
    ok(fn(arg, C.byref(k)))
    return k


def code_of(f):
    try:
        f()
    except UAErr as e:
        return e.code
    return ''


def b(h):
    return bytes.fromhex(h[2:])


def hx(x):
    return '0x' + x.hex()


def kd(fn, kind, data, *rest):
    return fn(kind, data, len(data), *rest)


def member(kind, ua_id, weight):
    return Member(kind, (C.c_uint8 * 32)(*ua_id), weight)


def holder(kind, ua, key_data=b'', key=b'', pop=b'', pop_hash=b'', kem_pk=b''):
    o = HolderPop()
    ok(L.holder_pop_message(kind, ua, key_data, len(key_data), key, len(key), pop, len(pop), pop_hash, len(pop_hash), kem_pk,
                            len(kem_pk), C.byref(o)))
    return o


def key_record(kind, ua, key_data, key, pop=b'', pop_hash=b'', already_set=False):
    o = PqzKeyRecord()
    ok(L.pqz_key_record_message(kind, ua, key_data, len(key_data), key, len(key), pop, len(pop), pop_hash, len(pop_hash), already_set,
                                C.byref(o)))
    return o


def mh(o):
    return hx(bytes(o.member_digest)) if o.has_member_digest else ''


def register(row, hash_only=False):
    """The holder call over a registration row's attrs (and the proof bytes, or only their hash)."""
    a = row['attrs']
    pop = b'' if hash_only else b(row['pqzPop'])
    h = b(a['pqzPopHash'])
    return holder(row['kind'], b(row['ua']), b(row['keyData']), b(a['pqzKey']), pop, h if any(h) else b'', b(a['kemPk']))


def reg_input(row, **kw):
    """clientkeys `registrationArgs`' input of a registration row; an msig's pop is its typed member list."""
    a = row['attrs']
    return {'kind': row['kind'], 'keyData': row['keyData'], 'pqzKey': a['pqzKey'], 'pqzPopHash': a['pqzPopHash'],
            'pqzPop': row['pqzPop'], 'kemPk': a['kemPk'], 'pop': row['args']['pop'], **kw}


def reg_args(i):
    return json.loads(text(L.registration_args, json.dumps(i).encode()))


def record_sig(r):
    """A record row's `UASig`: its `sig`, an msig's as the typed member list; absent fields are empty."""
    return {'members': r['args']['sig']['members']} if r['kind'] == 0x0120 else {'signature': r['sig']}


class Vectors(unittest.TestCase):
    def test_table_groups_purposes_constants(self):
        self.assertEqual(L.abi_version(), 6)  # T12: 5 -> 6
        self.assertEqual(L.kind_count(), len(K['kinds']))
        for i, r in enumerate(K['kinds']):
            with self.subTest(r['name']):
                n = r['kind']
                info = kind_row(L.kind_info, n)
                self.assertEqual(kind_row(L.kind_at, i).kind, n)  # table order
                self.assertEqual(info.kind, n)
                self.assertEqual(info.name.decode(), r['name'])
                self.assertEqual(info.native, r['native'])
                self.assertEqual(list(info.lengths[:info.lengths_len]), r['lengths'])
                self.assertEqual(info.group and info.group.decode(), r['group'])
                self.assertEqual(L.is_signing(n), r['signing'])
                self.assertEqual(L.is_zether(n), r['zether'])
                self.assertEqual(L.is_pqz_holder(n), r['pqzHolder'])
                self.assertEqual(L.is_member(n, False), r['member'])
                self.assertEqual(L.is_member(n, True), r['memberHedera'])
                self.assertEqual(L.is_native(n), info.native)
                if info.native:
                    self.assertEqual(code_of(lambda: out32(L.tag, n)), 'UAKindNotDerived')
                else:
                    self.assertEqual(text(L.kind_tag_string, n), r['tag'])
                    self.assertEqual(hx(out32(L.tag, n)), r['TAG'])
        for r in K['schemes']:  # schemes are not kinds: tag and keyHash only
            self.assertEqual(text(L.kind_tag_string, r['kind']), r['tag'])
            self.assertEqual(hx(out32(L.tag, r['kind'])), r['TAG'])
            self.assertEqual(code_of(lambda: kind_row(L.kind_info, r['kind'])), 'UAKindUnknown')
            self.assertEqual(code_of(lambda: out32(lambda k, o: L.ua_of(k, b'', 0, o), r['kind'])), 'UAKindNotDerived')
            self.assertEqual(code_of(lambda: ok(L.validate_key_data(r['kind'], b'', 0, False))), 'UAKindNotDerived')
        self.assertEqual(hx(opt32(lambda *a: kd(L.key_hash_of, 0x0142, b(K['pqzKey']), *a))), K['pqzKeyHash'])
        for r in K['groups']:
            with self.subTest(r['group']):
                g = r['group'].encode()
                self.assertEqual(opt_text(L.group_tag_string, g), r['tag'])
                self.assertEqual(hx(opt32(L.group_tag, g)), r['GROUP'])
        self.assertIsNone(opt32(L.group_tag, b'nope'))
        self.assertIsNone(opt_text(L.group_tag_string, b'nope'))
        self.assertEqual(len(K['purposes']), 16)  # 15 purposes (pqz-verdict: group 3f), `pop` has v1 and v2
        for r in K['purposes']:
            self.assertEqual(hx(out32(L.purpose_tag_v, r['purpose'].encode(), r['version'])), r['purposeTag'], r['purpose'])
            if r['version'] == 1:
                self.assertEqual(hx(out32(L.purpose_tag, r['purpose'].encode())), r['purposeTag'], r['purpose'])
        for bad in ((b'metatx', 2), (b'pop', 3), (b'pop', 0), (b'nope', 1)):
            self.assertEqual(code_of(lambda: out32(L.purpose_tag_v, *bad)), 'UAPurposeUnknown')
        self.assertEqual(code_of(lambda: out32(L.purpose_tag, b'nope')), 'UAPurposeUnknown')
        c = K['constants']
        self.assertEqual(hx(out32(L.msg_tag)), c['MSG_TAG'])
        self.assertEqual(hx(out32(L.purpose_tag, b'pop')), c['POP_TAG'])
        self.assertEqual(code_of(lambda: kind_row(L.kind_info, 0x0109)), 'UAKindUnknown')

    def test_valid_rows(self):
        for r in K['valid']:
            with self.subTest(r['name']):
                n, d, hn = r['kind'], b(r['keyData']), r['hederaNative']
                self.assertEqual(hx(out32(lambda o: kd(L.derive_ua, n, d, hn, o))), r['ua'])
                self.assertEqual(hx(out32(lambda o: kd(L.ua_of, n, d, o))), r['ua'])
                kh = opt32(lambda o, p: kd(L.key_hash_of, n, d, o, p))
                self.assertEqual(kh and hx(kh), r['keyHash'])

    def test_invalid_rows(self):
        for r in K['invalid']:
            with self.subTest(r['reason'], kind=r['kind']):
                status = kd(L.validate_key_data, r['kind'], b(r['keyData']), r['hederaNative'])
                self.assertEqual(L.status_name(status).decode(), r['error'])
        # the reason label travels with UAKeyData
        self.assertEqual(kd(L.validate_key_data, 0x0101, bytes(3), False), ERR_KEY_DATA)
        self.assertRegex(L.last_error().decode(), r'^UAKeyData: .+')

    def test_natives_native_space_canonical_ids(self):
        for r in K['natives']:
            with self.subTest(r['id']):
                ua_id = out32(lambda o: kd(L.native_id, r['kind'], b(r['raw']), o))
                self.assertEqual(hx(ua_id), r['id'])
                self.assertEqual(text(L.canonical_id, hx(ua_id).encode()), r['canonical'])
        for r in K['nativeInvalid']:
            with self.subTest(r['raw'], kind=r['kind']):
                self.assertEqual(code_of(lambda: out32(lambda o: kd(L.native_id, r['kind'], b(r['raw']), o))), r['error'])
        for r in K['nativeSpace']:
            with self.subTest(r['id']):
                out = bl()
                ok(L.in_native_space(b(r['id']), C.byref(out)))
                self.assertEqual(out.value, r['inNativeSpace'])
        for r in K['canonicalIds']:
            with self.subTest(r['input']):
                t = r['input'].encode()
                if 'canonical' in r:
                    self.assertEqual(text(L.canonical_id, t), r['canonical'])
                else:
                    self.assertEqual(code_of(lambda: text(L.canonical_id, t)), r['error'])

    def test_id_display_rows(self):
        """ua-mtx-merge spec §6, MD-9: every row of id_display.json, and a row for every kind of the table."""
        for r in D['rows']:
            with self.subTest(r['name']):
                t = r['id'].encode()
                if 'display' in r:
                    self.assertEqual(text(L.id_display, t, r['kind']), r['display'].get('address') or r['display']['urn'])
                else:
                    self.assertEqual(code_of(lambda: text(L.id_display, t, r['kind'])), r['error'])
        for i in range(L.kind_count()):
            k = kind_row(L.kind_at, i)
            want = (lambda r: r.get('error') == 'UAKindNotDerived') if k.native else (lambda r: 'urn' in r.get('display', {}))
            self.assertTrue(any(r['kind'] == k.kind and want(r) for r in D['rows']), k.name)

    def test_messages(self):
        for r in K['messages']:
            with self.subTest(r['purpose'], kind=r['kind']):
                p = out32(L.purpose_tag_v, r['purpose'].encode(), r['version'])  # each row carries its purpose `version` (A4-c1)
                self.assertEqual(hx(p), r['purposeTag'])
                self.assertEqual(hx(out32(L.ua_message, r['kind'], p, b(r['digest']))), r['uaMsg'])

    def test_structures(self):
        for p in S['pop']:
            with self.subTest('pop', ua=p['ua']):
                w = (b(p['ua']), p['kind'], b(p['pqzKeyHash']), b(p['kemRecordHash']))
                self.assertEqual(hx(out32(L.portable_record_digest, *w)), p['portableRecordDigest'])
                self.assertEqual(hx(out32(L.registration_digest, *w, b(p['pqzPopHash']))), p['registrationDigest'])
        self.assertEqual(hx(out32(L.keccak256, b'', 0)), '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470')
        self.assertEqual(hx(out32(L.chain_key_hash, 2**40 + 7)), '0x6e45d591a544f53396f6e86d49f5809196c5725f9d99dbd2ca97f9925c7ce950')  # keccak256("evm:1099511627783")
        pk, proof = b(K['pqzKey']), bytes([7]) * 32
        for p in S['pqzReg']:
            ua, kem = b(p['ua']), b(p['kemRecordHash'])
            kh = opt32(lambda *a: kd(L.key_hash_of, 0x0142, pk, *a))
            self.assertEqual(hx(kh), p['pqzKeyHash'])
            portable = out32(L.portable_record_digest, ua, p['kind'], kh, kem)
            self.assertEqual(hx(portable), p['portableRecordDigest'])
            self.assertEqual(hx(out32(L.ua_message, 0x0142, out32(L.purpose_tag_v, b'pop', 2), portable)), p['pqzRegMessage'])
            if kem != out32(L.kem_record_hash, ua, 0, None, 0):
                continue  # the row's KEM record hash is opaque; the real records are in portable.json
            self.assertEqual(hx(out32(L.pqz_reg_message, p['kind'], ua, pk, len(pk), None, 0)), p['pqzRegMessage'])
            got = holder(p['kind'], ua, b'', pk, b'', proof)
            self.assertEqual((hx(bytes(got.pqz_key_hash)), hx(bytes(got.portable_record_digest))), (p['pqzKeyHash'], p['portableRecordDigest']))
            for bad in (0x0101, 0x0133):
                self.assertEqual(code_of(lambda: holder(bad, ua, b'', pk, b'', proof)), 'UAPqzHolder')
        for p in S['pqzMsig']:
            d = b(p['keyData'])
            e = bl()
            ok(L.msig_pqz_eligible(d, len(d), C.byref(e)))
            self.assertEqual(e.value, p['eligible'], p['reason'])
            h, ua = b(K['pqzKeyHash']) if p['eligible'] else bytes(32), b(p['ua'])
            self.assertEqual(hx(out32(L.portable_record_digest, ua, 0x0120, h, out32(L.kem_record_hash, ua, 0, None, 0))), p['portableRecordDigest'])
        for a in S['uaAuth']:
            with self.subTest('uaAuth', ua=a['ua']):
                c = S['contexts'][a['context']]
                dom = (a['generation'], c['chainId'], b(c['registry']), b(c['chainUid']))
                self.assertEqual(hx(out32(L.ua_auth_domain_separator, *dom)), a['domainSeparator'])
                d = out32(L.ua_auth_digest, *dom, b(a['ua']), b(a['purposeTag']), b(a['digest']))
                self.assertEqual(hx(d), a['uaAuthDigest'])
        for m in S['member']:
            self.assertEqual(hx(out32(L.member_digest, b(m['structureUa']), b(m['uaMsg']))), m['memberDigest'])
        # non-UTF-8 text stays inside the documented error contract
        bad = b'\xff\xfe'
        self.assertEqual(code_of(lambda: out32(L.purpose_tag, bad)), 'UAPurposeUnknown')
        self.assertEqual(code_of(lambda: text(L.canonical_id, bad)), 'UAIdFormat')
        self.assertIsNone(opt32(L.group_tag, bad))
        self.assertIsNone(opt_text(L.group_tag_string, bad))
        ms = (Member * 1)(member(0x0001, bytes([1]) * 32, 1))
        self.assertEqual(var(L.encode_msig, 2, ms, 1), bytes.fromhex('0002' '0001' '0001') + bytes([1]) * 32 + b'\x00\x01')
        self.assertEqual(len(var(L.encode_msig, 2, None, 0)), 4)  # NULL members with n == 0 is the empty list


    def test_portable(self):
        t = PV['tags']
        self.assertEqual(hx(out32(L.purpose_tag_v, b'pop', 2)), t['PURPOSE_POP_V2']['hash'])
        self.assertEqual(hx(out32(L.purpose_tag, b'kem')), t['PURPOSE_KEM']['hash'])
        self.assertEqual(hx(out32(L.purpose_tag, b'pqz-key')), t['PURPOSE_PQZ_KEY']['hash'])
        self.assertNotIn('KEM_RECORD_TAG', t)  # the raw record tags are legacy (TS-D3)
        self.assertEqual(hx(out32(L.portable_domain_separator)), PV['typed']['domainSeparator'])
        n = with_pqz = msigs = 0
        for r in PV['registrations']:
            with self.subTest(r['name']):
                ua = b(r['ua'])
                self.assertEqual(hx(out32(lambda o: kd(L.ua_of, r['kind'], b(r['keyData']), o))), r['ua'])
                for hash_only in (False, True):
                    h = register(r, hash_only)
                    self.assertEqual(hx(bytes(h.pqz_key_hash)), r['pqzKeyHash'])
                    self.assertEqual(hx(bytes(h.pqz_pop_hash)), r['attrs']['pqzPopHash'])
                    self.assertEqual(hx(bytes(h.kem_record_hash)), r['kemRecordHash'])
                    self.assertEqual(hx(bytes(h.portable_record_digest)), r['portableRecordDigest'])
                    self.assertEqual(hx(bytes(h.registration_digest)), r['registrationDigest'])
                    self.assertEqual(hx(bytes(h.message)), r['popMessage'])
                    w = (ua, r['kind'], bytes(h.pqz_key_hash), bytes(h.kem_record_hash))
                    self.assertEqual(out32(L.portable_record_digest, *w), bytes(h.portable_record_digest))
                    self.assertEqual(out32(L.registration_digest, *w, bytes(h.pqz_pop_hash)), bytes(h.registration_digest))
                    self.assertEqual(out32(L.ua_message, r['kind'], out32(L.purpose_tag_v, b'pop', 2), bytes(h.registration_digest)), bytes(h.message))
                    self.assertEqual(mh(h), r.get('memberDigest', ''))
                a = r['attrs']
                pk, kpk = b(a['pqzKey']), b(a['kemPk'])
                self.assertEqual(hx(out32(L.kem_record_hash, ua, 0, kpk, len(kpk))), r['kemRecordHash'])  # the register key: version 0
                if pk:
                    with_pqz += 1
                    self.assertEqual(hx(out32(L.pqz_reg_message, r['kind'], ua, pk, len(pk), kpk, len(kpk))), r['pqzRegMessage'])
                    # TS-D3: R_REG proves over the typed UAPortableRecord of the registering kind
                    self.assertEqual(hx(out32(L.ua_message, 0x0142, out32(L.purpose_tag_v, b'pop', 2), b(r['portableRecordDigest']))), r['pqzRegMessage'])
                else:
                    self.assertEqual(b(r['pqzRegMessage']), bytes(32))
                msigs += r['kind'] == 0x0120
                n += 1
        self.assertEqual(n, len(PV['registrations']))
        self.assertTrue(with_pqz and msigs)
        # mldsa87 (CTR-UA-39), fndsa1024 (CTR-UA-40): holders, read here and in the record tests
        for k in (0x0134, 0x0135):
            self.assertEqual([sum(r['kind'] == k for r in PV[s]) for s in ('registrations', 'kemRecords', 'pqzKeyRecords')], [1, 3, 4], hex(k))

    def test_kem_record(self):
        for r in PV['kemRecords']:
            with self.subTest(r['id']):
                ua, pk, v = b(r['ua']), b(r['kemPk']), int(r['version'])
                d = out32(L.kem_record_digest, ua, v, pk, len(pk))
                self.assertEqual(hx(d), r['digest'])
                self.assertEqual(hx(out32(L.kem_record_hash, ua, v, pk, len(pk))), r['structHash'])
                m = out32(L.kem_record_message, r['kind'], ua, v, pk, len(pk))
                self.assertEqual(hx(m), r['message'])
                self.assertEqual(m, out32(L.ua_message, r['kind'], out32(L.purpose_tag, b'kem'), d))
                self.assertNotEqual(r['kind'], 0x0120, 'CTR-UA-32: an msig holds no KEM key')
        self.assertEqual(len(PV['kemRecords']), 12)
        u = bytes([1]) * 32
        # CTR-UA-32 (T66a): a PQ-eligible msig holds a PQZ key but no KEM key; the same record under a single PQ kind builds
        mq = b(next(x for x in PV['registrations'] if x['name'] == 'msig-pq/n2048-kmax1024')['ua'])
        self.assertEqual(code_of(lambda: out32(L.kem_record_message, 0x0120, mq, 1, kem(KEM_PK), KEM_PK)), 'UAKemHolder')
        self.assertEqual(len(out32(L.kem_record_message, 0x0131, mq, 1, kem(KEM_PK), KEM_PK)), 32)  # the control
        for v, pk, code in ((0, kem(KEM_PK), 'UAKemVersion'), (1, kem(KEM_PK - 1), 'UAKemKeyLength'),
                            (1, kem(KEM_PK + 1), 'UAKemKeyLength'), (1, b'', 'UAKemKeyLength'),
                            (1, kem(KEM_PK, 0), 'UAKemScheme'), (1, kem(KEM_PK, 2), 'UAKemScheme'),
                            (1, kem(KEM_PK - 1, 255), 'UAKemScheme')):
            self.assertEqual(code_of(lambda: out32(L.kem_record_digest, u, v, pk, len(pk))), code)
        self.assertEqual(code_of(lambda: out32(L.kem_record_hash, u, 1, b'', 0)), 'UAKemKeyLength')
        # owner 2026-10-31: version 0 with a key is the register key's record (scheme != 0), never a setKemKey record
        # (the version-0 words against portable.json's registrations with a KEM key, above)
        self.assertNotEqual(out32(L.kem_record_hash, u, 0, kem(KEM_PK), KEM_PK), out32(L.kem_record_hash, u, 0, None, 0))
        self.assertEqual(code_of(lambda: out32(L.kem_record_hash, u, 0, kem(KEM_PK, 0), KEM_PK)), 'UAKemScheme')
        # (0, no key) = the zero record UAKemRecord{ua, 0, 0, 0} (TS-D2): checked on every registration row without a KEM key
        self.assertEqual(hx(out32(L.kem_record_digest, u, 2**64 - 1, kem(KEM_PK), KEM_PK)), '0xa0063a84b56d80c83688d8caf5aeb4be8fb4556928e8bc649686449573938f07')  # pins the 8-byte version word

    def test_pqz_key_record(self):
        regs = PV['registrations']
        n = msig_runs = 0
        for r in PV['pqzKeyRecords']:
            with self.subTest(r['name']):
                ua, key, hash_, kind = b(r['ua']), b(r['pqzKey']), b(r['pqzPopHash']), r['kind']
                kdat = b(next(x for x in regs if x['ua'] == r['ua'])['keyData'])
                pop = b(next(x for x in regs if x['set'] == r['set'])['pqzPop'])
                for hash_only in (False, True):
                    g = key_record(kind, ua, kdat, key, b'' if hash_only else pop, hash_ if hash_only else b'')
                    self.assertEqual(hx(bytes(g.pqz_key_hash)), r['pqzKeyHash'])
                    self.assertEqual(hx(bytes(g.pqz_pop_hash)), r['pqzPopHash'])
                    self.assertEqual(hx(bytes(g.pqz_key_digest)), r['pqzKeyDigest'])
                    self.assertEqual(hx(bytes(g.record_digest)), r['recordDigest'])
                    self.assertEqual(hx(bytes(g.message)), r['message'])
                    self.assertEqual(hx(bytes(g.pqz_reg_message)), r['pqzRegMessage'])
                    self.assertEqual(out32(L.pqz_key_digest, ua, bytes(g.pqz_key_hash)), bytes(g.pqz_key_digest))
                    self.assertEqual(out32(L.pqz_key_record_digest, ua, bytes(g.pqz_key_hash), bytes(g.pqz_pop_hash)), bytes(g.record_digest))
                    self.assertEqual(bool(g.has_member_digest), kind == 0x0120)
                    self.assertEqual(mh(g), r.get('memberDigest', ''))
                    if kind == 0x0120:
                        msig_runs += 1
                        self.assertEqual(bytes(g.member_digest), out32(L.member_digest, ua, bytes(g.message)))
                # write-once: a key already set refuses
                self.assertEqual(code_of(lambda: key_record(kind, ua, kdat, key, b'', hash_, True)), 'UAPqzKeySet')
                n += 1
        self.assertEqual(n, len(PV['pqzKeyRecords']))
        self.assertTrue(msig_runs)

    def test_nested_rows(self):
        """Nested msig (nested.json): the digest chain from the low-level calls, the JSON calls with `inner`. Key data alone refuses an msig
        member by name, so holder_pop_message and pqz_key_record_message stop there on a record that needs its inner keys; their `_with`
        forms take `inner` (test_nested_inner). It verifies no signature."""
        inner = {r['ua']: r['keyData'] for r in NV['registrations'] if r['kind'] == 0x0120}
        pop_tag, member_tag = out32(L.purpose_tag_v, b'pop', 2), out32(L.purpose_tag, b'member')
        eligible = lambda d: code_of(lambda: ok(L.msig_pqz_eligible(d, len(d), C.byref(C.c_bool()))))
        with self.subTest('registrations'):
            rows = NV['registrations'] + NV['afterAcceptance']
            self.assertEqual(len(rows), 17)
            for r in rows:
                ua, k, d, pk = b(r['ua']), r['kind'], b(r['keyData']), b(r['attrs']['kemPk'])
                self.assertEqual(hx(out32(lambda o: kd(L.ua_of, k, d, o))), r['ua'], r['name'])
                kem_hash = out32(L.kem_record_hash, ua, 0, pk, len(pk))
                rd = out32(L.registration_digest, ua, k, bytes(32), kem_hash, bytes(32))
                msg = out32(L.ua_message, k, pop_tag, rd)
                self.assertEqual((hx(kem_hash), hx(out32(L.portable_record_digest, ua, k, bytes(32), kem_hash)), hx(rd), hx(msg)),
                                 (r['kemRecordHash'], r['portableRecordDigest'], r['registrationDigest'], r['popMessage']), r['name'])
                self.assertEqual(reg_args(reg_input(r, kemCommit=False, inner=inner))['args'], r['args'], r['name'])
                if 'kemCommit' in r:
                    c = reg_args(reg_input(r, kemCommit=True, inner=inner))
                    self.assertEqual((c['args'], c['kemFill']), (r['kemCommit']['register'], r['kemCommit']['fill']), r['name'])
                    self.assertEqual(code_of(lambda: register(r)), 'UAMemberUnknown', r['name'])
                if k != 0x0120:
                    continue
                md = out32(L.member_digest, ua, msg)
                self.assertEqual(hx(md), r['memberDigest'], r['name'])
                for x in r.get('innerDigests', []):
                    want = out32(L.member_digest, b(x['inner']), out32(L.ua_message, 0x0120, member_tag, md))
                    self.assertEqual(hx(want), x['memberDigest'], r['name'])
        with self.subTest('records'):
            self.assertEqual((len(NV['kemRecords']), len(NV['pqzKeyRecords'])), (0, 4))  # CTR-UA-32: an msig has no KEM record
            pq = next(x for x in NV['registrations'] if x['name'] == 'msig-nested-pq')
            self.assertEqual(code_of(lambda: out32(L.kem_record_message, 0x0120, b(pq['ua']), 1, kem(KEM_PK), KEM_PK)), 'UAKemHolder')
            self.assertEqual(code_of(lambda: reg_args(reg_input(pq, inner=inner, kemPk=hx(kem(KEM_PK))))), 'UAKemHolder')
            for r in NV['kemRecords']:
                ua, v, pk = b(r['ua']), r['version'], b(r['kemPk'])
                m = out32(L.kem_record_message, r['kind'], ua, v, pk, len(pk))
                self.assertEqual((hx(out32(L.kem_record_digest, ua, v, pk, len(pk))), hx(m), hx(out32(L.member_digest, ua, m))),
                                 (r['digest'], r['message'], r['memberDigest']), r['id'])
                i = {'ua': r['ua'], 'version': v, 'kemPk': r['kemPk'], 'sig': record_sig(r)}
                self.assertEqual(json.loads(text(L.set_kem_key_args, json.dumps(i).encode())), r['args'], r['id'])
            for r in NV['pqzKeyRecords']:
                ua, h, tag = b(r['ua']), b(r['pqzKeyHash']), out32(L.purpose_tag, b'pqz-key')
                rd = out32(L.pqz_key_record_digest, ua, h, b(r['pqzPopHash']))
                pk = out32(L.pqz_key_digest, ua, h)
                m = out32(L.ua_message, 0x0120, tag, rd)
                self.assertEqual((hx(pk), hx(rd), hx(m), hx(out32(L.ua_message, 0x0142, tag, pk)), hx(out32(L.member_digest, ua, m))),
                                 (r['pqzKeyDigest'], r['recordDigest'], r['message'], r['pqzRegMessage'], r['memberDigest']), r['name'])
                i = {'ua': r['ua'], 'pqzKey': r['pqzKey'], 'pqzPopHash': r['pqzPopHash'], 'sig': record_sig(r)}
                self.assertEqual(json.loads(text(L.set_pqz_key_args, json.dumps(i).encode())), r['args'], r['name'])
                self.assertEqual(code_of(lambda: key_record(r['kind'], ua, b(inner[r['ua']]), b(r['pqzKey']), b'', b(r['pqzPopHash']))),
                                 'UAMemberUnknown', r['name'])
        with self.subTest('memberships'):
            self.assertEqual(len(NV['memberships']), 4)
            for m in NV['memberships']:
                ua, d = b(m['ua']), out32(L.membership_digest, b(m['ua']), b(m['member']))
                msg = out32(L.ua_message, 0x0120, out32(L.purpose_tag, b'membership'), d)
                self.assertEqual((hx(d), hx(msg), hx(out32(L.member_digest, ua, msg))), (m['digest'], m['message'], m['memberDigest']), m['name'])
        with self.subTest('authorizations'):
            self.assertEqual(len(NV['authorizations']), 5)
            for a in NV['authorizations']:
                md = out32(L.member_digest, b(a['ua']), out32(L.ua_message, 0x0120, b(a['purposeTag']), b(a['digest'])))
                self.assertEqual(hx(md), a['memberDigest'], a['name'])
                k = NV['pqzKeyRecords'][0]  # (was kemRecords[0]: CTR-UA-32, an msig has no KEM record)
                i = {'ua': k['ua'], 'pqzKey': k['pqzKey'], 'pqzPopHash': k['pqzPopHash'], 'sig': a['uaSig']}
                self.assertEqual(json.loads(text(L.set_pqz_key_args, json.dumps(i).encode()))['sig'], a['uaSig'], a['name'])
        with self.subTest('negatives'):
            # the builder's own refusal is the minimal rule at both levels; the others are the registry's, on the signatures
            minimal = {'inner-below-threshold', 'inner-index-past-the-members', 'inner-unsorted', 'inner-not-minimal', 'outer-not-minimal'}
            self.assertEqual(len(NV['negatives']), 13)
            for n in NV['negatives']:
                r = next(x for x in NV['registrations'] + NV['afterAcceptance'] if x['name'] == n['row'])
                i = reg_input(r, kemCommit=False, inner=inner, pop=n['popTyped'])
                if n['name'] in minimal:
                    self.assertEqual(code_of(lambda: reg_args(i)), n['error'], n['name'])
                else:
                    self.assertEqual(reg_args(i)['args']['pop'], n['popTyped'], n['name'])
        with self.subTest('structures'):
            self.assertEqual(len(NV['structures']), 2)
            for s in NV['structures']:
                self.assertEqual(hx(out32(lambda o: kd(L.ua_of, 0x0120, b(s['keyData']), o))), s['ua'], s['name'])
                self.assertEqual(eligible(b(s['keyData'])), s['error'], s['name'])
        with self.subTest('eligibility'):
            for r in NV['eligibility']:
                self.assertEqual(eligible(b(r['keyData'])), 'UAMemberUnknown', r['reason'])

    def test_nested_inner(self):
        """The `_with` calls with `inner` ({id: keyData}, the JSON calls' form): msig-nested-pq's eligibility and record (no KEM key, CTR-UA-32), every
        eligibility row and every nested PQZ key record reproduce; without `inner` they stay UAMemberUnknown, so does a third level. Every
        memberships row's `stored` turns back into its slot through scaas_ua_replayed_member_sig."""
        regs = NV['registrations']
        inner = json.dumps({r['ua']: r['keyData'] for r in regs if r['kind'] == 0x0120}).encode()

        def eligible(d, i):
            o = C.c_bool()
            ok(L.msig_pqz_eligible_with(d, len(d), i, C.byref(o)))
            return o.value

        def holder_with(r, i):
            a, o = r['attrs'], HolderPop()
            ua, d, pk = b(r['ua']), b(r['keyData']), b(a['kemPk'])
            ok(L.holder_pop_message_with(r['kind'], ua, d, len(d), b'', 0, b'', 0, b'', 0, pk, len(pk), i, C.byref(o)))
            return o

        def key_record_with(r, i):
            o, ua, d, k, h = PqzKeyRecord(), b(r['ua']), b(json.loads(inner)[r['ua']]), b(r['pqzKey']), b(r['pqzPopHash'])
            ok(L.pqz_key_record_message_with(r['kind'], ua, d, len(d), k, len(k), b'', 0, h, len(h), False, i, C.byref(o)))
            return o
        pq = next(r for r in regs if r['name'] == 'msig-nested-pq')
        self.assertTrue(eligible(b(pq['keyData']), inner))
        self.assertEqual(code_of(lambda: eligible(b(pq['keyData']), None)), 'UAMemberUnknown')
        for r in NV['eligibility']:
            self.assertEqual(eligible(b(r['keyData']), json.dumps(r['inner']).encode()), r['eligible'], r['reason'])
            for none in (None, b'', b'null', b'{}'):
                self.assertEqual(code_of(lambda: eligible(b(r['keyData']), none)), 'UAMemberUnknown', r['reason'])
        third = b(NV['structures'][0]['keyData'])
        self.assertEqual(code_of(lambda: eligible(third, json.dumps({NV['structures'][0]['member']: pq['keyData']}).encode())),
                         'UAMemberUnknown', 'a third level')
        holders = [r for r in regs + NV['afterAcceptance'] if r['attrs']['kemPk'] != '0x' or r['attrs']['pqzKey'] != '0x']
        self.assertEqual(holders, [])  # CTR-UA-32 (T66a): msig-nested-pq registers without a KEM key (was its one holder row)
        g = holder_with(pq, inner)
        self.assertEqual((hx(bytes(g.kem_record_hash)), hx(bytes(g.portable_record_digest)), hx(bytes(g.registration_digest)),
                          hx(bytes(g.message)), mh(g)),
                         (pq['kemRecordHash'], pq['portableRecordDigest'], pq['registrationDigest'], pq['popMessage'], pq['memberDigest']))
        # an msig holds no KEM key: refused by its kind, before its key data or `inner` is read
        with_kem = {**pq, 'attrs': {**pq['attrs'], 'kemPk': hx(kem(KEM_PK))}}
        for i in (inner, None):
            self.assertEqual(code_of(lambda: holder_with(with_kem, i)), 'UAKemHolder', i)
        self.assertEqual(code_of(lambda: register(with_kem)), 'UAKemHolder')
        self.assertEqual(len(NV['pqzKeyRecords']), 4)
        for r in NV['pqzKeyRecords']:
            g = key_record_with(r, inner)
            self.assertEqual((hx(bytes(g.pqz_key_hash)), hx(bytes(g.pqz_pop_hash)), hx(bytes(g.pqz_key_digest)), hx(bytes(g.record_digest)),
                              hx(bytes(g.message)), hx(bytes(g.pqz_reg_message)), mh(g)),
                             (r['pqzKeyHash'], r['pqzPopHash'], r['pqzKeyDigest'], r['recordDigest'], r['message'], r['pqzRegMessage'],
                              r['memberDigest']), r['name'])
            self.assertEqual(code_of(lambda: key_record_with(r, None)), 'UAMemberUnknown', r['name'])
        for bad in (b'not json', b'[]', json.dumps({'0x01': '0x'}).encode(), b' ' * 65537, b'\xff'):
            self.assertEqual(code_of(lambda: eligible(b(pq['keyData']), bad)), 'UAArgument', bad[:12])
        msig_rows = [r for r in PV['registrations'] + NV['registrations'] + NV['afterAcceptance'] if r['kind'] == 0x0120]
        self.assertEqual(sum(len(r['memberSigHashes']) for r in msig_rows), sum(len(r['args']['pop']) for r in msig_rows))
        for r in msig_rows:  # owner 2026-11-03: memberSigHashOf per slot, the hash of the bytes its UAMemberSig carries
            got = [{'index': s['index'], 'hash': hx(out32(L.keccak256, member_sig_bytes(s), len(member_sig_bytes(s))))} for s in r['args']['pop']]
            self.assertEqual(got, r['memberSigHashes'], r['name'])
        self.assertEqual(len(NV['memberships']), 4)
        for m in NV['memberships']:
            d, st_ = b(next(r for r in regs if r['ua'] == m['ua'])['keyData']), b(m['stored'])
            self.assertEqual(member_sig_bytes(m), st_, m['name'])  # control: the test's encoder against the kept bytes
            self.assertEqual(hx(out32(L.keccak256, st_, len(st_))), m['storedHash'], m['name'])  # the event's bytes, the kept hash
            got = json.loads(text(L.replayed_member_sig, d, len(d), m['index'], st_, len(st_)))
            self.assertEqual(got, {'index': m['index'], 'members': m['members'], 'sig': m['sig']}, m['name'])
            self.assertEqual(code_of(lambda: text(L.replayed_member_sig, d, len(d), 16, st_, len(st_))), 'UAUnauthorized', m['name'])
            if m['members']:
                self.assertEqual(code_of(lambda: text(L.replayed_member_sig, d, len(d), m['index'], st_ + b'\0', len(st_) + 1)),
                                 'UAUnauthorized', 'not canonical')
        self.assertEqual(L.status_name(20).decode(), 'UAUnauthorized')

    def test_registration_args(self):
        commits = 0
        for r in PV['registrations']:
            with self.subTest(r['name']):
                a = reg_args(reg_input(r, kemCommit=False))
                self.assertEqual(a['args'], r['args'])
                self.assertIsNone(a['kemFill'])
                self.assertIsNone(a['kemFillCalldataLength'])
                self.assertEqual(reg_args(reg_input(r))['args'], r['args'])  # under the limit: the full key
                if r['attrs']['kemPk'] == '0x':
                    self.assertNotIn('kemCommit', r)
                    continue
                c = reg_args(reg_input(r, kemCommit=True))
                self.assertEqual(c['args'], r['kemCommit']['register'])
                self.assertEqual(c['kemFill'], r['kemCommit']['fill'])
                self.assertEqual(c['kemFillCalldataLength'], 2020)
                commits += 1
        self.assertEqual(commits, sum('kemCommit' in r for r in PV['registrations']))
        self.assertEqual(commits, 7)  # CTR-UA-32: msig-pq/<set> registers without a KEM key
        # CTR-UA-32 (T66a): a PQ-eligible msig holds no KEM key, in either form
        mq = next(x for x in PV['registrations'] if x['name'] == 'msig-pq/n2048-kmax1024')
        for commit in ({'kemCommit': True}, {'kemCommit': False}, {}):
            self.assertEqual(code_of(lambda: reg_args(reg_input(mq, kemPk=PV['kemRecords'][0]['kemPk'], **commit))), 'UAKemHolder', commit)
        typed = {0x0100: ('registerWebAuthn', 580), 0x0110: ('registerMuSig2', 1124), 0x0112: ('registerMuSig2', 1124),
                 0x0111: ('registerFrost', 2308), 0x0113: ('registerFrost', 2308)}
        rows = [v for v in K['valid'] if v['kind'] in typed]
        self.assertEqual(len(rows), 6)
        for v in rows:  # no attributes, a 32-byte pop (cast 1.8.5)
            a = reg_args({'kind': v['kind'], 'keyData': v['keyData'], 'pop': '0x' + '00' * 32})
            self.assertEqual((a['args']['entry'], a['calldataLength']), typed[v['kind']], v['name'])
        self.assertEqual(reg_args({'kind': 0x0101, 'keyData': K['valid'][1]['keyData']})['args']['entry'], 'register')
        # the hash commit only over 261,909 B (PQZH n2560-kmax16384's sizes; ua-rs registration_hash_commit_when_over_limit)
        x = {'kind': 0x0131, 'keyData': '0x' + '5a' * 1952, 'pqzKey': '0x' + '5a' * 20480, 'pqzPop': '0x' + '5a' * 234238,
             'kemPk': '0x01' + '5a' * 1600, 'pop': '0x' + '5a' * 3309}
        self.assertEqual(reg_args({**x, 'kemCommit': False})['calldataLength'], 262116)
        auto = reg_args(x)
        self.assertEqual((auto['calldataLength'], auto['kemFillCalldataLength']), (260548, 2020))
        self.assertEqual(auto['kemFill']['version'], 0)
        for bad, code in ((b'not json', 'UAArgument'), (b'{"kind": 65536}', 'UAArgument'),
                          (b'{"kind": 257, "keyData": "0xzz"}', 'UAArgument'), (b'{"kind": 288, "keyData": "0x00020000", "pop": "0x"}', 'UAArgument'),
                          (b'{"kind": 288, "keyData": "0x000200"}', 'UAKeyData'), (b'{"kind": 305, "kemPk": "0x0101"}', 'UAKemKeyLength'),
                          (b'{"kind": 305, "pqzKey": "0x01", "pqzPopHash": "0x01", "pqzPop": "0x01"}', 'UAPqzPopHash')):
            self.assertEqual(code_of(lambda: text(L.registration_args, bad)), code, bad)
        self.assertEqual(code_of(lambda: text(L.registration_args, None)), 'UAArgument')

    def test_set_key_args(self):
        self.assertEqual(len(PV['kemRecords']), 12)  # + v1-v3 of mldsa87, fndsa1024 (CTR-UA-39 / -40); no msig (CTR-UA-32)
        for k in PV['kemRecords']:
            i = {'ua': k['ua'], 'version': k['version'], 'kemPk': k['kemPk'], 'sig': record_sig(k)}
            self.assertEqual(json.loads(text(L.set_kem_key_args, json.dumps(i).encode())), k['args'], k['id'])
        self.assertEqual(len(PV['pqzKeyRecords']), 16)  # + mldsa87, fndsa1024 at the four sets
        for r in PV['pqzKeyRecords']:
            i = {'ua': r['ua'], 'pqzKey': r['pqzKey'], 'pqzPopHash': r['pqzPopHash'], 'sig': record_sig(r)}
            self.assertEqual(json.loads(text(L.set_pqz_key_args, json.dumps(i).encode())), r['args'], r['name'])
        ua = '"0x' + '11' * 32 + '"'
        for fn, bad, code in ((L.set_kem_key_args, b'not json', 'UAArgument'), (L.set_pqz_key_args, b'not json', 'UAArgument'),
                              (L.set_kem_key_args, b'{"ua": "0x11", "version": 1}', 'UAArgument'),
                              (L.set_kem_key_args, f'{{"ua": {ua}}}'.encode(), 'UAArgument'),
                              (L.set_kem_key_args, f'{{"ua": {ua}, "version": 1, "kemPk": "0x0101"}}'.encode(), 'UAKemKeyLength'),
                              (L.set_pqz_key_args, f'{{"ua": {ua}, "pqzPopHash": "0x01"}}'.encode(), 'UAPqzPopHash'),
                              (L.set_pqz_key_args, f'{{"ua": {ua}, "pqzPopHash": {ua}, "sig": "0x01"}}'.encode(), 'UAArgument')):
            self.assertEqual(code_of(lambda: text(fn, bad)), code, bad)
        self.assertEqual(code_of(lambda: text(L.set_kem_key_args, None)), 'UAArgument')
        self.assertEqual(code_of(lambda: text(L.set_pqz_key_args, None)), 'UAArgument')

    def test_membership_rows(self):
        self.assertEqual(len(PV['memberships']), 6)
        for r in PV['memberships']:
            u = b(r['ua'])
            d = out32(L.membership_digest, u, b(r['member']))
            self.assertEqual(hx(d), r['digest'], r['name'])
            m = out32(L.ua_message, 0x0120, out32(L.purpose_tag, b'membership'), d)
            self.assertEqual(hx(m), r['message'], r['name'])
            self.assertEqual(hx(out32(L.member_digest, u, m)), r['memberDigest'], r['name'])

    def test_portable_purposes(self):
        def portable(tag):
            o = bl()
            ok(L.is_portable_purpose(tag, C.byref(o)))
            return o.value
        pop2, kem, pqz = out32(L.purpose_tag_v, b'pop', 2), out32(L.purpose_tag, b'kem'), out32(L.purpose_tag, b'pqz-key')
        self.assertEqual([portable(pop2), portable(kem), portable(pqz)], [True] * 3)
        self.assertFalse(portable(out32(L.purpose_tag, b'metatx')) or portable(out32(L.purpose_tag, b'pop')))
        n = next(x for x in PV['negatives'] if x['name'] == 'native-personal-sign-under-metatx')
        self.assertFalse(portable(b(n['mutation']['set']['purposeTag'])))

    def test_holder_refusals(self):
        regs = PV['registrations']
        run = sig_level = 0
        for n in PV['negatives']:
            if n.get('rule') == 'msig-minimal':
                continue  # a registry rule over a full registration (msig minimal form), not a digest-layer row
            m, err, s = n['mutation'], n['error'], n['mutation'].get('set', {})
            if n['entry'] in ('register', 'storePqzPop') and all(k.startswith('attrs.') or k == 'pqzPop' for k in s):
                row = next(x for x in regs if x['name'] == m['row'])
                mut = {**row, 'attrs': dict(row['attrs'])}
                for k, v in {**m.get('registerWith', {}), **s}.items():  # registerWith first, then the mutation
                    if k.startswith('attrs.'):
                        mut['attrs'][k[6:]] = v
                    else:
                        mut[k] = v
                if err == 'UAPoP':  # the digest layer accepts it; the PoP of the unmutated row does not cover it
                    self.assertNotEqual(row['popMessage'], hx(bytes(register(mut).message)), n['name'])
                else:
                    self.assertEqual(code_of(lambda: register(mut)), err, n['name'])
                run += 1
            elif n['entry'] == 'setPqzKey' and err in ('UAPqzKeySet', 'UAPqzHolder', 'UAPqzPopHash'):
                rec = next(x for x in PV['pqzKeyRecords'] if x['name'] == m['row'])
                ua_hex = s.get('ua', rec['ua'])
                holder_row = next(x for x in regs if x['ua'] == ua_hex)
                self.assertEqual(code_of(lambda: key_record(holder_row['kind'], b(ua_hex), b(holder_row['keyData']), b(rec['pqzKey']), b'',
                                                            b(s.get('pqzPopHash', rec['pqzPopHash'])), holder_row['attrs']['pqzKey'] != '0x')), err, n['name'])
                run += 1
            elif n['entry'] == 'setKemKey' and err == 'UAKemHolder':
                # CTR-UA-32 (msig-kem-record): an msig's KEM record is refused by its kind (the target's kind is the row's)
                k = next(x for x in PV['kemRecords'] if x['id'] == m['row'])
                t = next(x for x in regs if x['ua'] == s['ua'])
                self.assertEqual(t['kind'], m['kind'], n['name'])
                pk = b(s['kemPk'])
                self.assertEqual(code_of(lambda: out32(L.kem_record_message, t['kind'], b(s['ua']), int(k['version']), pk, len(pk))), err, n['name'])
                run += 1
            elif n['entry'] == 'setKemKey' and n['name'] == 'kem-record-of-other-ua':
                # the record of one UA offered for another: the signed message differs, so the signature cannot verify
                k = next(x for x in PV['kemRecords'] if x['id'] == m['row'])
                t = next(x for x in regs if x['ua'] == s['ua'])
                pk = b(k['kemPk'])
                msg = out32(L.kem_record_message, t['kind'], b(s['ua']), int(k['version']), pk, len(pk))
                self.assertNotEqual(k['message'], hx(msg))
                run += 1
            elif n['name'] == 'record-kind-mismatch':
                # the typed record binds `kind`: the same UA and attributes under another kind is another message
                row = next(x for x in regs if x['name'] == m['row'])
                ua, zero = b(row['ua']), out32(L.kem_record_hash, b(row['ua']), 0, None, 0)
                d = out32(L.registration_digest, ua, m['otherKind'], bytes(32), zero, bytes(32))
                self.assertNotEqual(hx(out32(L.ua_message, row['kind'], out32(L.purpose_tag_v, b'pop', 2), d)), row['popMessage'])
                run += 1
            elif n['name'] == 'kem-record-as-registration':
                # the row's own typed KEM record is not its registration (struct type)
                row = next(x for x in regs if x['name'] == m['row'])
                k = next(x for x in PV['kemRecords'] if x['ua'] == row['ua'])
                self.assertNotEqual(k['digest'], row['registrationDigest'])
                run += 1
            else:
                sig_level += 1  # signatures / native members: verified by the signature vectors
        self.assertEqual(run + sig_level + 1, len(PV['negatives']))  # + the skipped msig-minimal row
        self.assertTrue(run and sig_level)
        u, key, proof = bytes([1]) * 32, bytes(16384), bytes([7]) * 32
        mq = b(next(x for x in regs if x['name'] == 'msig-pq/n2048-kmax1024')['keyData'])
        # malformed msig key data is UAKeyData, not "not a holder"; an msig without key data is not a holder
        for kdat in (bytes([0, 2, 0]), bytes([0, 2, 0, 2, 9, 9])):
            self.assertEqual(code_of(lambda: holder(0x0120, u, kdat, key, b'', proof)), 'UAKeyData')
        for args, code in (((0x0120, u, b'', key, b'', proof), 'UAPqzHolder'),
                           ((0x0130, u, b'', key, b'', bytes(31)), 'UAPqzPopHash'),
                           ((0x0130, u, b'', bytes(100), b'', proof), 'UAKeyData'),
                           ((0x0130, u, b'', b'', b'', b'', kem(KEM_PK - 1)), 'UAKemKeyLength'),
                           ((0x0130, u, b'', b'', b'', b'', kem(KEM_PK, 0)), 'UAKemScheme'),
                           ((0x0101, u, b'', b'', b'', b'', kem(KEM_PK)), 'UAKemHolder'),
                           ((0x0120, u, mq, b'', b'', b'', kem(KEM_PK)), 'UAKemHolder')):  # a PQ-eligible msig (CTR-UA-32)
            self.assertEqual(code_of(lambda: holder(*args)), code, args[:2])
        # a NULL / zero-length proof hash is absent (same as no hash); an empty proof is no proof
        self.assertEqual(bytes(holder(0x0130, u).message), bytes(holder(0x0130, u, b'', b'', b'', b'').message))
        self.assertEqual(code_of(lambda: holder(0x0130, u, b'', key, b'', b'')), 'UAPqzPopHash')


class Abi(unittest.TestCase):
    def test_layout(self):
        self.assertEqual((C.sizeof(HolderPop), C.alignment(HolderPop)), (225, 1))
        self.assertEqual((C.sizeof(PqzKeyRecord), C.alignment(PqzKeyRecord)), (225, 1))
        self.assertEqual(C.sizeof(Member), 36)
        self.assertEqual(C.alignment(Member), 2)

    def test_buffer_too_small(self):
        """SCAAS_UA_ERR_BUFFER with the size needed, and nothing written, for capacity 0, 1 and needed - 1."""
        ms = (Member * 2)(member(0x0001, bytes(32), 1), member(0x0102, bytes([7]) * 32, 2))
        calls = {
            'kind_tag_string': lambda o, n: L.kind_tag_string(0x0102, o, n),
            'canonical_id': lambda o, n: L.canonical_id(b'0x804D4D3B798F2D5F0902318D3E50AE8B24D83E04', o, n),
            'group_tag_string': lambda o, n: L.group_tag_string(b'secp256k1', o, n, C.byref(bl())),
            'encode_msig': lambda o, n: L.encode_msig(2, ms, 2, o, n),
        }
        for name, f in calls.items():
            with self.subTest(name):
                n = sz(0)
                self.assertEqual(f(None, C.byref(n)), ERR_BUFFER)
                need = n.value
                self.assertEqual(L.last_error().decode(), f'UABuffer: need {need}')
                for cap in (0, 1, need - 1):
                    buf = C.create_string_buffer(b'\xaa' * (need + 8), need + 8)
                    n = sz(cap)
                    self.assertEqual(f(buf, C.byref(n)), ERR_BUFFER)
                    self.assertEqual(n.value, need)
                    self.assertEqual(buf.raw, b'\xaa' * (need + 8))
                buf = C.create_string_buffer(b'\xaa' * (need + 8), need + 8)
                n = sz(need)
                ok(f(buf, C.byref(n)))
                self.assertEqual(n.value, need)
                self.assertEqual(buf.raw[need:], b'\xaa' * 8)
                if name != 'encode_msig':
                    self.assertEqual(buf.raw[need - 1], 0)  # NUL-terminated

    def test_null_arguments(self):
        o = C.create_string_buffer(32)
        n = sz(64)
        for name, status in {
            'tag out32': L.tag(0x0102, None),
            'msg_tag out32': L.msg_tag(None),
            'purpose NULL': L.purpose_tag(None, o),
            'group NULL': L.group_tag(None, o, C.byref(bl())),
            'present NULL': L.group_tag(b'p256', o, None),
            'key_data NULL len 5': L.derive_ua(0x0102, None, 5, False, o),
            'in_native_space id NULL': L.in_native_space(None, C.byref(bl())),
            'in_native_space out NULL': L.in_native_space(bytes(32), None),
            'ua_message digest NULL': L.ua_message(0x0102, bytes(32), None, o),
            'holder_pop_message pqz_pop_hash NULL len 32': L.holder_pop_message(0x0130, bytes(32), b'', 0, b'', 0, b'', 0, None, 32, b'', 0, C.byref(HolderPop())),
            'pqz_key_record_message out NULL': L.pqz_key_record_message(0x0130, bytes(32), b'', 0, bytes(16384), 16384, b'', 0, bytes([7]) * 32, 32, False, None),
            'portable_record_digest ua NULL': L.portable_record_digest(None, 0x0130, bytes(32), bytes(32), o),
            'registration_digest pqz_pop_hash NULL': L.registration_digest(bytes(32), 0x0130, bytes(32), bytes(32), None, o),
            'portable_domain_separator out NULL': L.portable_domain_separator(None),
            'holder_pop_message out NULL': L.holder_pop_message(0x0130, bytes(32), b'', 0, b'', 0, b'', 0, b'', 0, b'', 0, None),
            'domain separator chain_uid NULL': L.ua_auth_domain_separator(1, 1, bytes(20), None, o),
            'member_digest NULL': L.member_digest(None, bytes(32), o),
            'canonical_id text NULL': L.canonical_id(None, o, C.byref(n)),
            'canonical_id out_len NULL': L.canonical_id(b'0x00000000000000000000000000000000000000ab', o, None),
            'canonical_id out NULL, big capacity': L.canonical_id(b'0x00000000000000000000000000000000000000ab', None, C.byref(sz(64))),
            'encode_msig members NULL n 1': L.encode_msig(1, None, 1, o, C.byref(sz(32))),
            'kind_info out NULL': L.kind_info(0x0102, None),
            'kind_at index out of range': L.kind_at(L.kind_count(), C.byref(Kind())),
        }.items():
            with self.subTest(name):
                self.assertEqual(status, ERR_ARGUMENT)
        self.assertEqual(L.last_error().decode(), 'UAArgument: index')
        # NULL with length 0 is the empty slice: a key-data error, not an argument error
        self.assertEqual(L.validate_key_data(0x0102, None, 0, False), ERR_KEY_DATA)
        self.assertRegex(L.last_error().decode(), r'^UAKeyData: .+')
        self.assertEqual(L.status_name(99).decode(), 'UAStatusUnknown')

    def test_embedded_nul_ends_the_string(self):
        """A C string ends at its first NUL, so b'pop\\x00x' is "pop"."""
        self.assertEqual(out32(L.purpose_tag, b'pop\x00x'), out32(L.purpose_tag, b'pop'))

    def test_last_error_is_per_thread(self):
        self.assertEqual(kd(L.validate_key_data, 0x0101, bytes(3), False), ERR_KEY_DATA)
        main = L.last_error().decode()
        seen = {}

        def other():
            seen['fresh'] = L.last_error().decode()
            L.purpose_tag(b'nope', C.create_string_buffer(32))
            seen['own'] = L.last_error().decode()

        t = threading.Thread(target=other)
        t.start()
        t.join()
        self.assertEqual(seen, {'fresh': '', 'own': 'UAPurposeUnknown'})
        self.assertEqual(L.last_error().decode(), main)
        out32(L.msg_tag)  # a later success clears it
        self.assertEqual(L.last_error().decode(), '')



class GovernanceBits(unittest.TestCase):
    def test_governance_bits_rows(self):
        """governance T14: scaas_ua_governance_bit against governance_bits.json on disk, every row; past bit 24 UAArgument."""
        v = json.loads((VEC.parent / 'governance' / 'governance_bits.json').read_text())
        self.assertEqual(len(v['bits']), 25)
        for row in v['bits']:
            self.assertEqual(json.loads(text(L.governance_bit, row['bit'])), row, row['bit'])
        for bit in (25, 127, 128, 255):
            self.assertEqual(code_of(lambda: text(L.governance_bit, bit)), 'UAArgument', bit)

    def test_pay_digest_and_meta_pay_id(self):
        """pay-meta-tax T41, T83: paymeta.json v3 rows (save without a payNo refused; the UUIDv7 shown) and paytax.json's
        UAPayWithTax digest row."""
        meta = VEC.parent / 'metatx'
        for r in json.loads((meta / 'paymeta.json').read_text()):
            i = json.dumps({k: r[k] for k in ('salt', 'payNo', 'save', 'schema', 'body')}).encode()
            if r['accepted']:
                got = json.loads(text(L.meta_pay_id, i))
                self.assertEqual((got['payId'], got['save']), (r['payId'], r['save']), r['name'])
                self.assertEqual(got['payNoUuid'], r.get('payNoUuid'), r['name'])
            else:
                self.assertEqual(code_of(lambda: text(L.meta_pay_id, i)), 'UAArgument', r['name'])
        r = next(x for x in json.loads((meta / 'paytax.json').read_text()) if x['name'] == 'digest_unbound_relayer_fee_recipient')
        payment = {k: r[k] for k in ('from', 'to', 'value', 'entryRef', 'batch', 'nonce', 'validUntil', 'mode', 'relayer', 'fee',
                                     'feeRecipient')}
        i = json.dumps({'struct': 'UAPayWithTax', 'domain': r['domain'],
                        'message': {'payment': payment, 'taxMode': r['taxMode'], 'tax': r['tax']}}).encode()
        got = json.loads(text(L.pay_digest, i))
        self.assertEqual(got['structHash'], r['structHash'])
        self.assertEqual(got['digest'], r['digest'])

    def test_service_pull(self):
        """T80 (CLI-SGN-48): servicepull.json's Note row (a string and a bytes field) through scaas_ua_service_pull: entryRef,
        the transfer digest, the calldata and job once signed, the relay-fee wrap at nonce + 1; another payer refused."""
        r = next(x for x in json.loads((VEC.parent / 'metatx' / 'servicepull.json').read_text())['rows'] if x['name'] == 'note_native')
        t, f = r['t'], r['relayFee']
        i = {'name': r['token']['name'], 'token': r['token']['address'], 'chainId': r['chainId'], 'chainUid': r['token']['salt'],
             'entry': r['entry'], 'op': r['typedData'], 'from': t['from'], 'amount': t['value'], 'batch': t['batch'],
             'nonce': t['nonce'], 'validUntil': t['validUntil']}
        got = json.loads(text(L.service_pull, json.dumps(i).encode()))
        self.assertEqual((got['entryRef'], got['digest'], got['selector']), (r['entryRef'], r['transferDigest'], r['selector']))
        fee = {k: f[k] for k in ('feeToken', 'router', 'executor', 'value', 'batch', 'validUntil')}
        fee.update(nonce=int(t['nonce']) + 1, feeAuth={'keyData': '0x', 'signature': f['signature'], 'members': []})
        got = json.loads(text(L.service_pull, json.dumps({**i, 'auth': r['auth'], 'relayFee': fee}).encode()))
        self.assertEqual((got['calldata'], got['job']), (r['calldata'], r['job']))
        self.assertEqual((got['relayFee']['digest'], got['relayFee']['relayCalldata']), (f['digest'], f['relayCalldata']))
        other = json.dumps({**i, 'from': '0x' + '11' * 32}).encode()
        self.assertEqual(code_of(lambda: text(L.service_pull, other)), 'UAArgument')



# --- ABI v6 (ua-rs-sign T12): the wallet surface over keys.json, sign.json, kem.json, seal.json, vault.json ---

KEYS, SIGN, KEMV, SEAL, VAULT = (json.loads((VEC / f).read_text()) for f in ('keys.json', 'sign.json', 'kem.json', 'seal.json', 'vault.json'))
MN = {m['id']: m for m in KEYS['mnemonics']}
NETWORKS = ['evm', 'cosmos', 'hedera_ecdsa', 'hedera_ed25519', 'sui', 'stellar', 'ton', 'aptos', 'solana']
COIN_DEFAULT, MNEMONIC_MAX, KEM_CT = 0xFFFFFFFF, 256, 1568
FEATURES = ['wallet', 'pq', 'falcon', 'zether', 'pqz', 'pqz-set-n2048-kmax1024', 'pqz-set-n2304-kmax4096', 'pqz-set-n2560-kmax16384',
            'pqz-set-n2816-kmax65536', 'external', 'mlock', 'vectors']
FEATURE = {n: 1 << i for i, n in enumerate(FEATURES)}
# appended after SCAAS_UA_ERR_UNAUTHORIZED (20), no renumbering; a KEM key of a non-holder is the existing UAKemHolder (12)
STATUS = {n: i for i, n in enumerate(['SealOpen', 'SealVersion', 'KemCheck', 'Aead', 'VaultOpen', 'VaultParams', 'VaultVersion',
                                      'RawDigestRefused', 'PolicyRefused', 'ExternalSignature', 'WalletLocked', 'KeyRevoked',
                                      'ContainerSender', 'ContainerReplay', 'BackupRollback', 'WebAuthnAssertion', 'KindUnavailable',
                                      'WalletMismatch', 'Rng', 'PqzSetMismatch', 'PqzKeyVersion', 'KeyInUse'], 21)}
# deterministic in a release build (RFC 6979, ed25519, BLS): byte-equal; the others are randomized: the length only
DETERMINISTIC = {0x0101, 0x0102, 0x0106, 0x0107, 0x0108}


class MemoryProtection(C.Structure):
    _fields_ = [('chunks', sz), ('locked', sz), ('no_dump', sz)]


class Recipient(C.Structure):
    _fields_ = [('kind', u16), ('key_data', C.c_char_p), ('key_data_len', sz), ('version', u64), ('kem_pk', C.c_char_p),
                ('kem_pk_len', sz), ('ephemeral', bl)]


for name, res, args in [
    ('features', u64, []),
    ('wallet_generate', st, [P, P]), ('wallet_from_mnemonic', st, [u8, u8, P]), ('wallet_open_vault', st, [u8, u8, u8, u8, P]),
    ('wallet_unlock', st, [P, u8, u8, u8, u8]), ('wallet_seal_vault', st, [P, u8, P, P]), ('wallet_lock', st, [P]),
    ('wallet_free', None, [P]), ('wallet_memory_protection', st, [P, P]), ('wallet_ua_key', st, [P, u16, u32, u32, P]),
    ('wallet_native_key', st, [P, u32, u32, u32, P]), ('wallet_import_native_key', st, [P, u32, u8, sz, P]),
    ('wallet_manifest_json', st, [P, P, P]), ('wallet_discover_candidates', st, [P, u16, u32, u32, P, P]),
    ('wallet_backup_seal', st, [P, P, P, sz, P, P]),
    ('wallet_restore_backup', st, [P, u8, u8, u8, u8, P, u8, P, P]),
    ('wallet_restore_backup_rollback', st, [P, u8, u8, u8, u8, P, u8, P, P]),
    ('wallet_from_link', st, [P, u8, u8, u8, u8, u8, P]),
    ('seed_backup_reveal', st, [P, P, P]), ('seed_backup_challenge', st, [P, P]), ('seed_backup_verify', st, [P, P, sz, P]),
    ('seed_backup_take', st, [P, P, P, P]), ('seed_backup_free', None, [P]),
    ('key_free', None, [P]), ('key_data', st, [P, P, P]),
    ('sign_ua', st, [P, u8, u8, P, P]), ('sign_member', st, [P, u8, u8, P, P]), ('sign_typed', st, [P, u8, u8, P, P]),
    ('sign_typed_any', st, [P, u8, P, P]), ('sign_transaction', st, [P, u8, P, P]), ('sign_key_proof', st, [P, u8, sz, P, P]),
    ('sign_digest_raw', st, [P, u8, P, P]), ('uasig', st, [u8, P, sz, P, P]), ('external_key_new', st, [u8, P, P]),
    ('kem_key', st, [P, u64, P]), ('kem_ephemeral', st, [P]), ('kem_free', None, [P]), ('kem_pk', st, [P, P]),
    ('kem_decaps', st, [P, u8, sz, u8, P]), ('kem_encaps', st, [u8, sz, P, P, P]),
    ('seal', st, [u8, sz, u8, u8, sz, u8, sz, P, P, P, P, P]), ('open', st, [P, u8, u8, sz, u8, sz, u8, u8, sz, P, P]),
    ('open_container', st, [P, u8, u8, u8, u8, P, P]),
    ('link_session_new', st, [P]), ('link_session_kem_pk', st, [P, P]), ('link_session_short_code', st, [P, P, P]),
    ('link_session_free', None, [P]),
    ('vault_needs_rewrap', st, [u8, P]), ('vault_rewrap_pin', st, [u8, u8, u8, P, P]),
    ('vault_enable_prf', st, [u8, u8, u8, u8, u8, sz, P, P]),
    ('aead_seal', st, [u32, u8, u8, u8, sz, u8, sz, P, P]), ('aead_open', st, [u32, u8, u8, u8, sz, u8, sz, P, P]),
    ('hkdf_sha256', st, [u8, sz, u8, sz, u8, sz, P, sz]), ('hmac_sha256', st, [u8, sz, u8, sz, P]),
    ('webauthn_challenge', st, [u8, u8, P]), ('webauthn_assertion', st, [u8, sz, u8, u8, sz, u8, sz, u8, u8, P, P]),
    ('wallet_zether_key', st, [P, u32, u32, u32, P]), ('zether_key_free', None, [P]), ('zether_public', st, [P, P, P]),
    ('zether_call', st, [P, u8, u8, P, P]), ('zether_seal_balance_cache', st, [P, u8, sz, P, P]),
    ('zether_open_balance_cache', st, [P, u8, P, P]),
    ('wallet_link_seal', st, [P, P, u8, sz, u8, P, P]), ('wallet_seal_label_vault', st, [P, u8, u8, P, P]),
    ('wallet_open_label_vault', st, [P, u8, u8, u8]), ('wallet_imported_key', st, [P, u32, u32, P]),
    ('wallet_imported_ua_key', st, [P, u32, u32, u16, P]),
    ('wallet_pqz_key', st, [P, u32, u32, P]), ('pqz_key_free', None, [P]), ('pqz_public', st, [P, P, P]),
    ('pqz_call', st, [P, u8, u8, P, P]), ('pqz_seal_balance_cache', st, [P, u8, sz, P, P]),
    ('pqz_open_balance_cache', st, [P, u8, P, P]), ('pqz_set', st, [P, P]), ('pqz_check_set', st, [u8]),
    ('pqz_check', st, [u8, P, P]),
    ('export_pqz_leaf_raw', st, [P, u32, u32, P]),
    ('wallet_pqz_key_version', st, [P, u32, u32, u64, P]), ('export_pqz_leaf_raw_version', st, [P, u32, u32, u64, P]),
    ('pqz_seed_backup', st, [P, P, u8, sz, u64, C.c_uint8, P, sz, P, P]),
    ('pqz_share_reseal', st, [P, u8, u8, u8, u8, P, P, P, P]),
    ('wallet_pqz_reconstruct', st, [P, P, u8, u8, u8, u8, u8, u64, u8, P]),
    ('wallet_pqz_held_key', st, [P, u8, P]),
    ('pqz_seed_backup_warning', st, [u16, u8, u64, u8, sz, u8, P]),
]:
    f = getattr(LIB, 'scaas_ua_' + name)
    f.restype, f.argtypes = res, args
    setattr(L, name, f)


def handle(fn, *args):
    h = P()
    ok(fn(*args, C.byref(h)))
    return h


def name_of(status):
    return '' if status == OK else L.status_name(status).decode()


def jb(v):
    return None if v is None else json.dumps(v).encode()


def mnemonic_wallet(mid):
    m = MN[mid]
    return handle(L.wallet_from_mnemonic, m['words'].encode(), m['passphrase'].encode())


def sig_of(fn, *args):
    """`(status name, bytes)` of a call with a variable output."""
    n = sz(0)
    status = fn(*args, None, C.byref(n))
    if status != ERR_BUFFER:
        return name_of(status), b'' if status == OK else None  # OK at the size query: an empty output
    buf = C.create_string_buffer(n.value)
    status = fn(*args, buf, C.byref(n))
    return name_of(status), buf.raw[:n.value] if status == OK else None


def once(fn, *args, cap=1 << 20):
    """A variable output fetched in one call (no size query): for a call that changes state each time (backup_seal raises the
    generation)."""
    buf, n = C.create_string_buffer(cap), sz(cap)
    ok(fn(*args, buf, C.byref(n)))
    return buf.raw[:n.value - 1].decode()


def abi_word(x):
    return x.to_bytes(32, 'big')


def abi_bytes(b):
    return abi_word(len(b)) + b + bytes(-len(b) % 32)


def abi_list(items):
    offs, o = b'', 32 * len(items)
    for t in items:
        offs += abi_word(o)
        o += len(t)
    return abi_word(len(items)) + offs + b''.join(items)


def member_sigs(members):
    """`abi.encode(MemberSig[])` of a UASig JSON's members (ua8.rs `encode_member_sigs`)."""
    inner = lambda x: abi_word(x['index']) + abi_word(64) + abi_bytes(b(x['sig']))
    def slot(m):
        lst = abi_list([inner(x) for x in m['members']])
        return abi_word(m['index']) + abi_word(96) + abi_word(96 + len(lst)) + lst + abi_bytes(b(m['sig']))
    return abi_word(32) + abi_list([slot(m) for m in members]) if members else b''


class WalletCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.wallets = {}

    @classmethod
    def tearDownClass(cls):
        for w in cls.wallets.values():
            L.wallet_free(w)

    def w(self, mid):
        if mid not in self.wallets:
            self.wallets[mid] = mnemonic_wallet(mid)
        return self.wallets[mid]

    def key(self, mid, kind, account=0, index=0, w=None):
        k = handle(L.wallet_ua_key, w or self.w(mid), kind, account, index)
        self.addCleanup(L.key_free, k)
        return k

    def native(self, mid, net='evm', index=0, coin=None):
        k = handle(L.wallet_native_key, self.w(mid), NETWORKS.index(net), index, COIN_DEFAULT if coin is None else coin)
        self.addCleanup(L.key_free, k)
        return k

    def kem(self, r, w=None):
        """The KEM key `{mnemonic, kind, account, index, version}` names."""
        kk = handle(L.kem_key, self.key(r.get('mnemonic', 'pq_kat'), r['kind'], r['account'], r['index'], w=w), int(r['version']))
        self.addCleanup(L.kem_free, kk)
        return kk

    def opener(self, r):
        return self.kem(r['opener']['kem'])

    def raw_sig(self, k, digest):
        return var(L.sign_digest_raw, k, digest)

    def open_container(self, kk, r, accepted=True):
        acc = r.get('accepted') if accepted else None
        return sig_of(L.open_container, kk, jb(r['container']), jb(r['expect']), jb(r.get('members')), jb(acc))


class WalletAbi(WalletCase):
    def test_abi_version_is_6(self):
        self.assertEqual(L.abi_version(), 6)

    def test_features_bits(self):
        f = L.features()
        self.assertTrue(f & FEATURE['wallet'] and f & FEATURE['pq'], hex(f))
        self.assertFalse(f & FEATURE['external'], 'MD-13: no external key in a release build')
        self.assertFalse(f & FEATURE['vectors'], 'C1: never a vectors build')
        self.assertEqual(f >> len(FEATURES), 0, 'no bit past the named ones')
        self.assertLessEqual(bin(f >> 5 & 0xf).count('1'), 1, 'at most one pqz-set-*')

    def test_status_codes_appended(self):
        for n, v in STATUS.items():
            self.assertEqual(L.status_name(v).decode(), 'UA' + n)
        self.assertEqual(L.status_name(12).decode(), 'UAKemHolder')
        self.assertEqual(L.status_name(43).decode(), 'UAStatusUnknown')  # T15: 40 -> 41 (UAPqzSetMismatch appended); T15o: 41 -> 43
        self.assertNotEqual(STATUS['KindUnavailable'], 3)

    def test_free_null_is_a_noop(self):
        for f in (L.wallet_free, L.key_free, L.kem_free, L.link_session_free, L.seed_backup_free):
            f(None)

    def test_external_key_new_is_KIND_UNAVAILABLE(self):
        self.assertEqual(name_of(L.external_key_new(b'{}', None, C.byref(P()))), 'UAKindUnavailable')
        self.assertEqual(L.status_name(3).decode(), 'UAKindUnknown')

    def test_null_handles_and_arguments(self):
        o, n = C.create_string_buffer(64), sz(64)
        for label, status in {
            'ua_key wallet NULL': L.wallet_ua_key(None, 0x0102, 0, 0, C.byref(P())),
            'ua_key out NULL': L.wallet_ua_key(self.w('pq_kat'), 0x0102, 0, 0, None),
            'sign_ua key NULL': L.sign_ua(None, bytes(32), bytes(32), o, C.byref(n)),
            'from_mnemonic words NULL': L.wallet_from_mnemonic(None, None, C.byref(P())),
            'open_container expect NULL': L.open_container(None, b'{}', None, None, None, o, C.byref(n)),
            'unknown network': L.wallet_native_key(self.w('pq_kat'), 9, 0, COIN_DEFAULT, C.byref(P())),
        }.items():
            with self.subTest(label):
                self.assertEqual(status, ERR_ARGUMENT)


class WalletKeys(WalletCase):
    def test_keys_json_ua_rows(self):
        falcon = L.features() & FEATURE['falcon']
        n = 0
        for r in KEYS['ua']:
            if r['kind'] in (0x0132, 0x0135) and not falcon:
                continue
            with self.subTest(r['name'], account=r['account'], index=r['index']):
                k = self.key(r['mnemonic'], r['kind'], r['account'], r['index'])
                self.assertEqual(hx(var(L.key_data, k)), r['keyData'])
                n += 1
        self.assertGreaterEqual(n, 184)

    def test_keys_json_native_rows(self):
        for r in KEYS['native']:
            with self.subTest(r['network'], index=r['index'], coin=r['coinType']):
                k = self.native(r['mnemonic'], r['network'], r['index'], r['coinType'])
                self.assertEqual(var(L.key_data, k).hex(), r['publicKey'].removeprefix('0x'))

    def test_keys_json_refusals(self):
        for r in KEYS['refusals']:
            with self.subTest(r['reason']):
                out = C.byref(P())
                if r['what'] == 'ua':
                    status = L.wallet_ua_key(self.w(r['mnemonic']), r['kind'], r['account'], r['index'], out)
                else:
                    coin = COIN_DEFAULT if r['coinType'] is None else r['coinType']
                    status = L.wallet_native_key(self.w(r['mnemonic']), NETWORKS.index(r['network']), r['index'], coin, out)
                self.assertEqual(name_of(status), 'UA' + r['error'])


class WalletSign(WalletCase):
    def test_sign_json_ua_rows(self):
        falcon = L.features() & FEATURE['falcon']
        exact = 0
        for r in SIGN['ua']:
            if r['kind'] in (0x0132, 0x0135) and not falcon:
                continue
            with self.subTest(r['name'], purpose=r['purpose']):
                k = self.key(r['mnemonic'], r['kind'], r['account'], r['index'])
                sig = var(L.sign_ua, k, b(r['purposeTag']), b(r['digest']))
                if r['kind'] in DETERMINISTIC:
                    self.assertEqual(hx(sig), r['signature'])
                    exact += 1
                elif r['kind'] not in (0x0132, 0x0135):  # Falcon padded: a fixed length too, but the row may be the unpadded vector's
                    self.assertEqual(len(sig), len(b(r['signature'])))
        self.assertGreaterEqual(exact, 10)

    def test_sign_json_member_rows(self):
        for r in SIGN['member']:
            with self.subTest(r['name']):
                k = self.key(r['mnemonic'], r['kind'], r['account'], r['index'])
                sig = var(L.sign_member, k, b(r['structureUa']), b(r['structureUaMsg']))
                if r['kind'] in DETERMINISTIC:
                    self.assertEqual(hx(sig), r['signature'])
                else:
                    self.assertEqual(len(sig), len(b(r['signature'])))

    def test_sign_json_policy_rows(self):
        k = self.native('pq_kat')
        signed = refused = 0
        for r in SIGN['policy']:
            with self.subTest(r['id']):
                got = sig_of(L.sign_typed, k, jb(r['td']), jb(r['expect']))
                if 'refused' in r:
                    self.assertEqual(got[0], 'UAPolicyRefused')
                    refused += 1
                else:
                    # RFC 6979: the typed signature is the raw signature of the digest the row approves
                    self.assertEqual(got, ('', self.raw_sig(k, b(r['digest']))))
                    signed += 1
        self.assertEqual((signed, refused), (10, 14))

    def test_sign_json_typed_any(self):
        k = self.native('pq_kat')
        for r in SIGN['typed']['generic']:
            with self.subTest(r['id']):
                self.assertEqual(var(L.sign_typed_any, k, jb(r['td'])), self.raw_sig(k, b(r['digest'])))
        for r in SIGN['typed']['refusals']:
            with self.subTest(r['id']):
                self.assertEqual(sig_of(L.sign_typed_any, k, jb(r['td']))[0], 'UAArgument')

    def test_sign_json_tx_rows(self):
        for r in SIGN['tx']['rows']:
            with self.subTest(r['tx']['type']):
                s = r['signer']
                k = self.native(s['mnemonic'], s['network'], s['index'])
                self.assertEqual(hx(var(L.sign_transaction, k, jb(r['tx']))), r['raw'])
        k = self.native('pq_kat')
        for r in SIGN['tx']['refusals']:
            with self.subTest(r['id']):
                self.assertEqual(sig_of(L.sign_transaction, k, jb(r['tx']))[0], 'UAArgument')

    def test_sign_json_webauthn(self):
        for r in SIGN['webauthn']['accepted']:
            self.assertEqual(out32(L.webauthn_challenge, b(r['purposeTag']), b(r['digest'])), b(r['expectedChallenge']))
            self.assertEqual(out32(L.webauthn_challenge, b(r['purposeTag']), b(r['digest'])),
                             out32(L.ua_message, 0x0100, b(r['purposeTag']), b(r['digest'])))
        rows = [(r, None) for r in SIGN['webauthn']['accepted']] + [(r, r['error']) for r in SIGN['webauthn']['refusals']]
        for r, err in rows:
            with self.subTest(r.get('case', 'accepted')):
                kd_, ad, cd = b(r['keyData']), b(r['authData']), b(r['clientDataJSON'])
                got = sig_of(L.webauthn_assertion, kd_, len(kd_), b(r['expectedChallenge']), ad, len(ad), cd, len(cd), b(r['r']), b(r['s']))
                self.assertEqual(got, ('UA' + err, None) if err else ('', b(r['assertion'])))

    def test_sign_json_msig_rows_through_uasig(self):
        built = refused = 0
        for r in SIGN['msig']:
            with self.subTest(r['case']):
                keys = []
                def pos(x):
                    k = x['key']
                    keys.append(self.key(k['mnemonic'], k['kind'], k['account'], k['index']))
                    return len(keys) - 1
                slots = [{'index': s['index'], 'members': [{'index': x['index'], 'key': pos(x)} for x in s['members']]}
                         if 'members' in s else {'index': s['index'], 'key': pos(s)} for s in r['slots']]
                m = {'keyData': r['keyData'], 'slots': slots, **({'inner': r['inner']} if 'inner' in r else {})}
                req = jb({'purpose': r['purposeTag'], 'digest': r['digest'], 'msig': m})
                arr = (P * len(keys))(*keys)
                got = sig_of(L.uasig, req, arr, len(keys))
                if 'refused' in r:
                    self.assertEqual(got, (r['refused'], None))  # the row's code is UAPoP already
                    refused += 1
                else:
                    sig = json.loads(got[1][:-1])
                    self.assertEqual((sig['keyData'], sig['signature']), ('0x', '0x'))
                    self.assertEqual(hx(member_sigs(sig['members'])), r['memberSigs'])
                    built += 1
        self.assertEqual((built, refused), (3, 4))

    def test_uasig_single_key_is_sign_ua(self):
        r = next(x for x in SIGN['ua'] if x['kind'] == 0x0101)
        k = self.key(r['mnemonic'], r['kind'])
        arr = (P * 1)(k)
        got = json.loads(text(L.uasig, jb({'purpose': r['purposeTag'], 'digest': r['digest'], 'key': 0}), arr, 1))
        self.assertEqual(got, {'keyData': r['keyData'], 'signature': r['signature'], 'members': []})
        self.assertEqual(sig_of(L.uasig, jb({'purpose': r['purposeTag'], 'digest': r['digest'], 'key': 1}), arr, 1)[0], 'UAArgument')

    def test_sign_digest_raw_on_a_ua_key_is_RawDigestRefused(self):
        k = self.key('pq_kat', 0x0108)
        self.assertEqual(sig_of(L.sign_digest_raw, k, bytes(32))[0], 'UARawDigestRefused')
        self.assertEqual(len(self.raw_sig(self.native('pq_kat'), bytes(32))), 65)

    def test_sign_key_proof(self):
        n = self.native('pq_kat')
        self.assertEqual(len(var(L.sign_key_proof, n, b'challenge', 9)), 65)
        self.assertEqual(sig_of(L.sign_key_proof, self.key('pq_kat', 0x0101), b'challenge', 9)[0], 'UAArgument')


class WalletKem(WalletCase):
    def test_kem_json_keys(self):
        for r in KEMV['keys']:
            with self.subTest(kind=r['kind'], version=r['version']):
                pk = C.create_string_buffer(KEM_PK)
                ok(L.kem_pk(self.kem(r), pk))
                self.assertEqual(hx(pk.raw), r['kemPk'])

    def test_kem_json_refusals(self):
        for r in KEMV['refusals']:
            if 'mnemonic' not in r or not isinstance(r['version'], int):
                continue  # the msig row: no wallet handle of 0x0120; 2^64: not a uint64_t
            with self.subTest(kind=r['kind']):
                k = self.key(r['mnemonic'], r['kind'], r['account'], r['index'])
                self.assertEqual(name_of(L.kem_key(k, r['version'], C.byref(P()))), 'UA' + r['error'])

    def test_kem_json_encaps_refusals_and_round_trip(self):
        ct, e, ss = C.create_string_buffer(KEM_CT), C.create_string_buffer(32), C.create_string_buffer(32)
        for r in KEMV['encapsRefusals']:
            with self.subTest(r['id']):
                pk = b(r['kemPk'])
                self.assertEqual(name_of(L.kem_encaps(pk, len(pk), ct, e, ss)), 'UA' + r['error'])
        kk = self.kem(KEMV['keys'][0])
        pk = b(KEMV['keys'][0]['kemPk'])
        ok(L.kem_encaps(pk, len(pk), ct, e, ss))
        self.assertEqual(out32(L.kem_decaps, kk, ct.raw, KEM_CT, e.raw), ss.raw)

    def test_kem_json_decaps(self):
        for r in KEMV['decaps']:
            eph = b(r['x25519Eph'])
            if len(eph) != 32:
                continue  # a 31-byte E is not a uint8_t[32]
            with self.subTest(r['id']):
                kk, ct = self.kem(r['key']), b(r['mlkemCt'])
                got = C.create_string_buffer(32)
                status = L.kem_decaps(kk, ct, len(ct), eph, got)
                self.assertEqual((name_of(status), got.raw if status == OK else None),
                                 ('UA' + r['error'], None) if r.get('error') else ('', b(r['ss'])))

    def test_kem_ephemeral(self):
        kk = handle(L.kem_ephemeral)
        self.addCleanup(L.kem_free, kk)
        pk = C.create_string_buffer(KEM_PK)
        ok(L.kem_pk(kk, pk))
        self.assertEqual(pk.raw[0], 1)


class WalletSeal(WalletCase):
    def seal_open(self, kk, purpose, aad, mlkem_ct, eph, ct):
        return sig_of(L.open, kk, purpose.encode(), aad, len(aad), mlkem_ct, len(mlkem_ct), eph, ct, len(ct))

    def test_seal_json_seal_rows(self):
        for r in SEAL['seal']:
            if 'kind' not in r['recipient']:
                continue  # an ephemeral recipient from a fixed seed: under `vectors` only
            with self.subTest(r['id']):
                kk = self.kem(r['recipient'])
                got = self.seal_open(kk, r['purpose'], b(r['aad']), b(r['mlkemCt']), b(r['x25519Eph']), b(r['ciphertext']))
                self.assertEqual(got, ('', b(r['pt'])))
                # a fresh seal of the same plaintext opens to it
                pk, aad, pt = b(r['kemPk']), b(r['aad']), b(r['pt'])
                mct, nm, e, ct, nc = C.create_string_buffer(KEM_CT), sz(KEM_CT), C.create_string_buffer(32), C.create_string_buffer(len(pt) + 16), sz(len(pt) + 16)
                ok(L.seal(pk, len(pk), r['purpose'].encode(), aad, len(aad), pt, len(pt), mct, C.byref(nm), e, ct, C.byref(nc)))
                self.assertEqual((nm.value, nc.value), (KEM_CT, len(pt) + 16))
                self.assertEqual(self.seal_open(kk, r['purpose'], aad, mct.raw, e.raw, ct.raw), ('', pt))

    def test_seal_json_refusals(self):
        base = next(r for r in SEAL['seal'] if r['id'] == SEAL['refusals']['base'])
        for r in SEAL['refusals']['rows']:
            wire = b(r.get('wire', base['wire']))
            if wire[:2] != b'\x01\x01':
                continue  # version or scheme 2: the named fields carry neither (container v 2 below is SealVersion)
            with self.subTest(r['id']):
                kk = self.kem(r.get('key', SEAL['refusals']['key']))
                aad = b(r['aad']) if 'aad' in r else b(base['aad'])
                got = self.seal_open(kk, r.get('purpose', base['purpose']), aad, wire[2:2 + KEM_CT], wire[2 + KEM_CT:2 + KEM_CT + 32],
                                     wire[2 + KEM_CT + 32:])
                self.assertEqual(got, ('UA' + r['error'], None))

    def test_seal_json_argument_refusals(self):
        pk = b(SEAL['seal'][0]['kemPk'])
        for r in SEAL['argumentRefusals']:
            with self.subTest(r['id']):
                pt = bytes(r['ptLength'])
                mct, nm, e, ct, nc = C.create_string_buffer(KEM_CT), sz(KEM_CT), C.create_string_buffer(32), C.create_string_buffer(len(pt) + 16), sz(len(pt) + 16)
                status = L.seal(pk, len(pk), r['purpose'].encode(), b'', 0, pt, len(pt), mct, C.byref(nm), e, ct, C.byref(nc))
                self.assertEqual(name_of(status), 'UA' + r['error'])

    def test_seal_json_containers(self):
        n = 0
        for r in SEAL['containers']:
            if 'session' in r['opener']:
                continue  # a link container opens only through its session (a fixed one exists under `vectors` only)
            with self.subTest(r['id']):
                self.assertEqual(self.open_container(self.opener(r), r), ('', b(r['pt'])))
                n += 1
        self.assertEqual(n, 3)

    def test_seal_json_acceptance(self):
        n = 0
        for r in SEAL['acceptance']:
            if 'link' in r:
                continue  # its session's short code: a fixed session exists under `vectors` only
            with self.subTest(r['id']):
                kk = self.opener(r)
                if r.get('restore'):
                    out, installed = P(), bl()
                    status = L.wallet_restore_backup(kk, jb(r['container']), jb(r['expect']), jb(r.get('members')), jb(r.get('accepted')),
                                                     None, b'', C.byref(out), C.byref(installed))
                    got = name_of(status)
                    if status == OK:
                        L.wallet_free(out)
                else:
                    got = self.open_container(kk, r)[0]
                self.assertEqual(got, 'UA' + r['error'] if r.get('error') else '')
                n += 1
        self.assertEqual(n, 28)

    def test_open_container_msig_without_accepted_json_is_ContainerSender(self):
        r = next(x for x in SEAL['containers'] if x.get('accepted'))
        kk = self.opener(r)
        self.assertEqual(self.open_container(kk, r, accepted=False), ('UAContainerSender', None))
        self.assertEqual(self.open_container(kk, r), ('', b(r['pt'])))

    def test_container_json_inputs_are_bounded(self):
        r = SEAL['containers'][0]
        kk = self.opener(r)
        deep = dict(r['expect'], x=[[[[0]]]])
        self.assertEqual(sig_of(L.open_container, kk, jb(r['container']), jb(deep), None, None)[0], 'UAArgument')
        big = json.dumps(r['expect']).encode() + b' ' * (16 << 10)
        self.assertEqual(sig_of(L.open_container, kk, jb(r['container']), big, None, None)[0], 'UAArgument')
        # members_json: 512 KiB (owner 2026-11-06), the other two 16 KiB
        members = b'{}' + b' ' * ((512 << 10) - 2)
        self.assertEqual(sig_of(L.open_container, kk, jb(r['container']), jb(r['expect']), members, None), ('', b(r['pt'])), '512 KiB')
        self.assertEqual(sig_of(L.open_container, kk, jb(r['container']), jb(r['expect']), members + b' ', None)[0], 'UAArgument')

    def replay_current(self, r):
        """A wallet holding `current.ua` at `current.generation` (raised by backup_seal), or None."""
        c = r['current']
        if c is None:
            return None
        twelve = handle(L.wallet_ua_key, self.w('twelve_words'), 0x0102, 0, 0)
        sender_ua = out32(L.derive_ua, 0x0102, var(L.key_data, twelve), 32, False)
        L.key_free(twelve)
        w = mnemonic_wallet('twelve_words' if b(c['ua']) == sender_ua else 'pq_kat')
        self.addCleanup(L.wallet_free, w)
        k = self.key(None, 0x0102, w=w)
        self.assertEqual(out32(L.derive_ua, 0x0102, var(L.key_data, k), 32, False), b(c['ua']))
        rec_key = self.key('pq_kat', 0x0130)
        kd_, pk = var(L.key_data, rec_key), b(KEMV['keys'][0]['kemPk'])
        rec = Recipient(0x0130, kd_, len(kd_), 0, pk, len(pk), False)
        for _ in range(c['generation']):
            once(L.wallet_backup_seal, w, k, C.byref(rec), 1)
        self.assertEqual(json.loads(text(L.wallet_manifest_json, w))['backupGeneration'], c['generation'])
        return w

    def test_seal_json_replay_backup_rows_and_the_none_flag(self):
        n = 0
        for r in SEAL['replay']:
            if r['kind'] != 'backup':
                continue  # link windows: a session starts now in a release build
            with self.subTest(r['id']):
                cur = self.replay_current(r)
                fn = L.wallet_restore_backup_rollback if r.get('allowRollback') else L.wallet_restore_backup
                out, installed = P(), bl(True)
                status = fn(self.opener(r), jb(r['container']), jb(r['expect']), None, None, cur, b'', C.byref(out), C.byref(installed))
                if r.get('error'):
                    self.assertEqual(name_of(status), 'UA' + r['error'])
                else:
                    ok(status)
                    self.assertEqual(installed.value, r['install'])
                    self.assertEqual(out.value is not None, r['install'], 'an equal generation installs nothing: out stays NULL')
                    L.wallet_free(out)
                n += 1
        self.assertEqual(n, 6)

    def test_backup_seal_restores_a_wallet(self):
        w = mnemonic_wallet('twelve_words')
        self.addCleanup(L.wallet_free, w)
        sender = self.key(None, 0x0102, w=w)
        self.key(None, 0x0101, 0, 1, w=w)
        rec_key = self.key('pq_kat', 0x0130)
        kd_, pk = var(L.key_data, rec_key), b(KEMV['keys'][0]['kemPk'])
        recs = (Recipient * 2)(Recipient(0x0130, kd_, len(kd_), 0, pk, len(pk), False), Recipient(0, None, 0, 0, pk, len(pk), True))
        cs = json.loads(once(L.wallet_backup_seal, w, sender, recs, 2))
        self.assertEqual(len(cs), 2)
        ua = hx(out32(L.derive_ua, 0x0102, var(L.key_data, sender), 32, False))
        expect = {'purpose': 'scaas/backup/v1', 'sender': {'ua': ua}, 'recipient': {'ua': hx(out32(L.derive_ua, 0x0130, kd_, len(kd_), False)), 'version': 0}}
        out, installed = P(), bl()
        ok(L.wallet_restore_backup(self.kem(KEMV['keys'][0]), jb(cs[0]), jb(expect), None, None, None, b'', C.byref(out), C.byref(installed)))
        self.addCleanup(L.wallet_free, out)
        self.assertTrue(installed.value)
        self.assertEqual(var(L.key_data, self.key(None, 0x0102, w=out)), var(L.key_data, sender))
        m = json.loads(text(L.wallet_manifest_json, out))
        self.assertEqual((m['backupGeneration'], len(m['entries'])), (1, 2))
        self.assertEqual(sig_of(L.wallet_backup_seal, w, self.native('pq_kat'), recs, 1)[0], 'UAArgument', 'a native key seals no container')
        self.assertEqual(sig_of(L.wallet_backup_seal, w, sender, recs, 0)[0], 'UAArgument', 'no recipient')

    def test_link_session_is_consumed(self):
        s = handle(L.link_session_new)
        self.addCleanup(L.link_session_free, s)
        pk = C.create_string_buffer(KEM_PK)
        ok(L.link_session_kem_pk(s, pk))
        self.assertRegex(text(L.link_session_short_code, s), r'^[0-9]{8}$')
        r = next(x for x in SEAL['containers'] if 'session' in x['opener'])
        expect = dict(r['expect'], recipient={'kemPkHash': hx(out32(L.keccak256, pk.raw, KEM_PK))})
        out = P()
        status = L.wallet_from_link(s, jb(r['container']), jb(expect), None, None, b'', C.byref(out))
        self.assertEqual(name_of(status), 'UAContainerReplay', "the vector container's created is outside this session's window")
        for f in (lambda: L.wallet_from_link(s, jb(r['container']), jb(expect), None, None, b'', C.byref(out)),
                  lambda: L.link_session_kem_pk(s, pk)):
            self.assertEqual(name_of(f()), 'UAKeyRevoked', 'the session is consumed by its first install')

    def test_link_seal_round_trip(self):
        """T12 follow-up (owner 2026-11-06): the existing device seals the link container; the new device installs it; a wrong
        short code and a key of another wallet are refused."""
        w = mnemonic_wallet('twelve_words')
        self.addCleanup(L.wallet_free, w)
        key = self.key(None, 0x0102, w=w)
        ok(L.wallet_import_native_key(w, 0, bytes(range(1, 33)), 32, C.byref(P())))
        ua = hx(out32(L.derive_ua, 0x0102, var(L.key_data, key), 32, False))
        for wrong in (False, True):
            s = handle(L.link_session_new)
            self.addCleanup(L.link_session_free, s)
            pk = C.create_string_buffer(KEM_PK)
            ok(L.link_session_kem_pk(s, pk))
            code = text(L.link_session_short_code, s)
            if wrong:
                code = '00000000' if code != '00000000' else '00000001'
            c = text(L.wallet_link_seal, w, key, pk.raw, KEM_PK, code.encode())
            expect = {'purpose': 'scaas/link/v1', 'sender': {'ua': ua}, 'recipient': {'kemPkHash': hx(out32(L.keccak256, pk.raw, KEM_PK))}}
            out = P()
            status = L.wallet_from_link(s, c.encode(), jb(expect), None, None, b'', C.byref(out))
            if wrong:
                self.assertEqual(name_of(status), 'UASealOpen')
                continue
            ok(status)
            self.addCleanup(L.wallet_free, out)
            self.assertEqual(var(L.key_data, self.key(None, 0x0102, w=out)), var(L.key_data, key))
            self.assertEqual(json.loads(text(L.wallet_manifest_json, out))['imports'], json.loads(text(L.wallet_manifest_json, w))['imports'])
        s = handle(L.link_session_new)
        self.addCleanup(L.link_session_free, s)
        pk = C.create_string_buffer(KEM_PK)
        ok(L.link_session_kem_pk(s, pk))
        other = self.key('pq_kat', 0x0102)
        self.assertEqual(sig_of(L.wallet_link_seal, w, other, pk.raw, KEM_PK, b'12345678')[0], 'UAArgument', "another wallet's key")
        self.assertEqual(sig_of(L.wallet_link_seal, w, key, pk.raw, KEM_PK - 1, b'12345678')[0], 'UAKemCheck')


class WalletVault(WalletCase):
    def unlock_of(self, u):
        prf = b(u['prfOutput']) if 'prfOutput' in u else None
        return (u['pin'].encode() if 'pin' in u else None), prf

    def open_vault(self, v, pin, prf, bip39=b''):
        out = P()
        status = L.wallet_open_vault(jb(v), pin, prf, bip39, C.byref(out))
        if status == OK:
            self.addCleanup(L.wallet_free, out)
        return name_of(status), out

    def test_vault_json_vaults(self):
        by_entropy = {m['entropy']: m['id'] for m in KEYS['mnemonics'] if not m['passphrase']}
        for r in VAULT['vaults']:
            with self.subTest(r['id']):
                got, w = self.open_vault(r['vault'], *self.unlock_of(r['unlock']))
                self.assertEqual(got, '')
                mid = by_entropy[r['plaintext']]
                self.assertEqual(var(L.key_data, self.key(None, 0x0102, w=w)), var(L.key_data, self.key(mid, 0x0102)))

    def test_vault_json_refusals(self):
        for r in VAULT['refusals']:
            with self.subTest(r['id']):
                self.assertEqual(self.open_vault(r['vault'], *self.unlock_of(r['unlock']))[0], 'UA' + r['error'])

    def test_exactly_one_unlock_secret(self):
        r = next(x for x in VAULT['vaults'] if 'prfOutput' in x['unlock'])
        prf = b(r['unlock']['prfOutput'])
        pin_row = VAULT['vaults'][0]
        self.assertEqual(self.open_vault(r['vault'], None, None)[0], 'UAArgument', 'neither')
        self.assertEqual(self.open_vault(r['vault'], b'not the passphrase', prf)[0], '', 'both: PRF first, the passphrase not tried')
        self.assertEqual(self.open_vault(r['vault'], pin_row['unlock']['pin'].encode(), bytes(32))[0], 'UAVaultOpen', 'both: a wrong PRF')
        self.assertEqual(self.open_vault(pin_row['vault'], None, prf)[0], 'UAArgument', 'a PRF for a vault without its envelope')

    def test_seal_vault_rewrap_enable_prf(self):
        w = self.w('twelve_words')
        v = json.loads(text(L.wallet_seal_vault, w, b'correct horse 9'))
        self.assertEqual(sig_of(L.wallet_seal_vault, w, b'12345678')[0], 'UAArgument', 'the new-passphrase policy')
        flag = bl(True)
        ok(L.vault_needs_rewrap(jb(v), C.byref(flag)))
        self.assertFalse(flag.value)
        v2 = json.loads(text(L.vault_rewrap_pin, jb(v), b'correct horse 9', b'battery staple 7'))
        v3 = json.loads(text(L.vault_enable_prf, jb(v2), b'battery staple 7', bytes(range(32)), b'cred-1', b'salt', 4))
        want = var(L.key_data, self.key('twelve_words', 0x0102))
        for vault, pin, prf in ((v, b'correct horse 9', None), (v2, b'battery staple 7', None), (v3, None, bytes(range(32)))):
            got, w2 = self.open_vault(vault, pin, prf)
            self.assertEqual(got, '')
            self.assertEqual(var(L.key_data, self.key(None, 0x0102, w=w2)), want)
        self.assertEqual(self.open_vault(v2, b'correct horse 9', None)[0], 'UAVaultOpen', 'the old passphrase after the rewrap')


class WalletCustody(WalletCase):
    def test_lock_revokes_and_unlock_does_not_revive(self):
        w = mnemonic_wallet('twelve_words')
        self.addCleanup(L.wallet_free, w)
        v = text(L.wallet_seal_vault, w, b'correct horse 9').encode()
        k = self.key(None, 0x0101, w=w)
        before = var(L.sign_ua, k, out32(L.purpose_tag, b'metatx'), bytes(32))
        ok(L.wallet_lock(w))
        self.assertEqual(sig_of(L.sign_ua, k, out32(L.purpose_tag, b'metatx'), bytes(32))[0], 'UAKeyRevoked')
        self.assertEqual(name_of(L.wallet_ua_key(w, 0x0101, 0, 0, C.byref(P()))), 'UAWalletLocked')
        mp = MemoryProtection(1, 1, 1)
        ok(L.wallet_memory_protection(w, C.byref(mp)))
        self.assertEqual((mp.chunks, mp.locked, mp.no_dump), (0, 0, 0))
        ok(L.wallet_unlock(w, v, b'correct horse 9', None, b''))
        self.assertEqual(sig_of(L.sign_ua, k, out32(L.purpose_tag, b'metatx'), bytes(32))[0], 'UAKeyRevoked', 'unlock does not revive')
        self.assertEqual(var(L.sign_ua, self.key(None, 0x0101, w=w), out32(L.purpose_tag, b'metatx'), bytes(32)), before)
        self.assertEqual(name_of(L.wallet_unlock(w, v, b'correct horse 9', None, b'')), 'UAArgument', 'already unlocked')

    def test_imported_key_after_unlock(self):
        """T12 follow-up (owner 2026-11-06): an imported key is reachable again after unlock through its label vault."""
        w = mnemonic_wallet('twelve_words')
        self.addCleanup(L.wallet_free, w)
        seed_v = text(L.wallet_seal_vault, w, b'correct horse 9').encode()
        k = handle(L.wallet_import_native_key, w, 0, bytes(range(1, 33)), 32)
        self.addCleanup(L.key_free, k)
        d = bytes(range(32))
        before = var(L.sign_digest_raw, k, d)
        label_v = text(L.wallet_seal_label_vault, w, b'native-import:evm:0', b'correct horse 9').encode()
        self.assertEqual(sig_of(L.wallet_seal_label_vault, w, b'native-import:evm:7', b'correct horse 9')[0], 'UAArgument', 'not held')
        ok(L.wallet_lock(w))
        self.assertEqual(name_of(L.wallet_imported_key(w, 0, 0, C.byref(P()))), 'UAWalletLocked')
        ok(L.wallet_unlock(w, seed_v, b'correct horse 9', None, b''))
        self.assertEqual(name_of(L.wallet_imported_key(w, 0, 0, C.byref(P()))), 'UAArgument', 'listed, not held before its vault opens')
        self.assertEqual(name_of(L.wallet_open_label_vault(w, label_v, b'wrong horse 9', None)), 'UAVaultOpen')
        self.assertEqual(name_of(L.wallet_open_label_vault(w, seed_v, b'correct horse 9', None)), 'UAArgument', 'the seed vault is not a label vault')
        ok(L.wallet_open_label_vault(w, label_v, b'correct horse 9', None))
        k2 = handle(L.wallet_imported_key, w, 0, 0)
        self.addCleanup(L.key_free, k2)
        self.assertEqual(var(L.sign_digest_raw, k2, d), before, 'the same key (RFC 6979)')
        self.assertEqual(sig_of(L.sign_digest_raw, k, d)[0], 'UAKeyRevoked', 'the old handle stays revoked')
        self.assertEqual(name_of(L.wallet_imported_key(w, 1, 0, C.byref(P()))), 'UAArgument', 'another network (CLI-SGN-11)')
        self.assertEqual(name_of(L.wallet_imported_key(w, 0, 1, C.byref(P()))), 'UAArgument', 'an unknown n')

    def test_imported_ua_key_rows(self):
        """T20c (owner 2026-11-08): keys.json / sign.json `imported`: an imported key's UA (0x0108 / 0x0102 only) has the row's id
        and key data and signs the rows byte for byte; every other kind, another network, a KEM key, a backup sender refused."""
        sign = {r['id']: r for r in SIGN['imported']['rows']}
        for r in KEYS['imported']['rows']:
            w = mnemonic_wallet('twelve_words')
            self.addCleanup(L.wallet_free, w)
            nk = handle(L.wallet_import_native_key, w, NETWORKS.index(r['network']), bytes.fromhex(r['secret'][2:]), 32)
            self.addCleanup(L.key_free, nk)
            k = handle(L.wallet_imported_ua_key, w, NETWORKS.index(r['network']), 0, r['kind'])
            self.addCleanup(L.key_free, k)
            self.assertEqual('0x' + var(L.key_data, k).hex(), r['keyData'], r['network'])
            self.assertIn('"importedUas":[{"kind":%d,"source":"native-import:%s:0","ua":"%s"}]' % (r['kind'], r['network'], r['ua']),
                          text(L.wallet_manifest_json, w), r['network'])
            for what in ('pop', 'metatx'):
                x = sign.get('%s %s' % (r['network'], what))
                if x:
                    got = var(L.sign_ua, k, bytes.fromhex(x['purposeTag'][2:]), bytes.fromhex(x['digest'][2:]))
                    self.assertEqual('0x' + got.hex(), x['signature'], x['id'])
            self.assertEqual(name_of(L.kem_key(k, 0, C.byref(P()))), 'UAKemHolder', r['network'])
        for x in KEYS['imported']['refusals']:
            r = next(y for y in KEYS['imported']['rows'] if y['network'] == x['network'])
            w = mnemonic_wallet('twelve_words')
            self.addCleanup(L.wallet_free, w)
            nk = handle(L.wallet_import_native_key, w, NETWORKS.index(r['network']), bytes.fromhex(r['secret'][2:]), 32)
            self.addCleanup(L.key_free, nk)
            self.assertEqual(name_of(L.wallet_imported_ua_key(w, NETWORKS.index(r['network']), 0, x['kind'], C.byref(P()))), 'UAArgument', x['reason'])
            self.assertEqual(name_of(L.wallet_imported_ua_key(w, NETWORKS.index(r['network']), 0, r['kind'], C.byref(P()))), '', 'positive control')
        self.assertEqual(name_of(L.wallet_imported_ua_key(w, NETWORKS.index('cosmos'), 0, 0x0108, C.byref(P()))), 'UAArgument', 'another network')

    def test_unlock_with_another_wallets_vault_is_WalletMismatch(self):
        w = mnemonic_wallet('twelve_words')
        self.addCleanup(L.wallet_free, w)
        self.key(None, 0x0102, w=w)
        other = text(L.wallet_seal_vault, self.w('pq_kat'), b'correct horse 9').encode()
        ok(L.wallet_lock(w))
        self.assertEqual(name_of(L.wallet_unlock(w, other, b'correct horse 9', None, b'')), 'UAWalletMismatch')

    def test_child_handle_after_wallet_free_is_KEY_REVOKED(self):
        w = mnemonic_wallet('pq_kat')
        k = handle(L.wallet_ua_key, w, 0x0130, 0, 0)
        kk = handle(L.kem_key, k, 0)
        n = handle(L.wallet_native_key, w, 0, 0, COIN_DEFAULT)
        L.wallet_free(w)  # defined before its children: they stay valid memory and answer KEY_REVOKED
        try:
            self.assertEqual(sig_of(L.sign_ua, k, out32(L.purpose_tag, b'metatx'), bytes(32))[0], 'UAKeyRevoked')
            self.assertEqual(sig_of(L.sign_digest_raw, n, bytes(32))[0], 'UAKeyRevoked')
            self.assertEqual(name_of(L.kem_key(k, 1, C.byref(P()))), 'UAKeyRevoked')
            self.assertEqual(name_of(L.kem_decaps(kk, bytes(KEM_CT), KEM_CT, bytes(range(1, 33)), C.create_string_buffer(32))), 'UAKeyRevoked')
            self.assertEqual(len(var(L.key_data, k)), 1312, 'public data stays readable')
        finally:
            L.kem_free(kk)
            L.key_free(k)
            L.key_free(n)

    def test_memory_protection(self):
        w = mnemonic_wallet('pq_kat')
        self.addCleanup(L.wallet_free, w)
        self.key(None, 0x0102, w=w)
        mp = MemoryProtection()
        ok(L.wallet_memory_protection(w, C.byref(mp)))
        self.assertGreaterEqual(mp.chunks, 1)
        self.assertLessEqual(max(mp.locked, mp.no_dump), mp.chunks)
        if L.features() & FEATURE['mlock']:
            self.assertEqual(mp.no_dump, mp.chunks, 'MADV_DONTDUMP needs no rlimit')

    def test_seed_backup_sequence(self):
        w, s = P(), P()
        ok(L.wallet_generate(C.byref(w), C.byref(s)))
        self.addCleanup(L.wallet_free, w)
        self.addCleanup(L.seed_backup_free, s)
        n = sz(MNEMONIC_MAX - 1)
        self.assertEqual(L.seed_backup_reveal(s, C.create_string_buffer(MNEMONIC_MAX), C.byref(n)), ERR_BUFFER)
        self.assertEqual(n.value, MNEMONIC_MAX, 'a short buffer reveals nothing')
        words = text(L.seed_backup_reveal, s).split()
        self.assertEqual(len(words), 24)
        self.assertEqual(sig_of(L.seed_backup_reveal, s)[0], 'UAArgument', 'shown once')
        pos = (u32 * 3)()
        ok(L.seed_backup_challenge(s, pos))
        self.assertTrue(1 <= pos[0] < pos[1] < pos[2] <= 24)
        good = (C.c_char_p * 3)(*[words[i - 1].encode() for i in pos])
        bad = (C.c_char_p * 3)(*[b'x', b'y', b'z'])
        flag, taken = bl(True), bl(True)
        e, ne = C.create_string_buffer(32), sz(32)
        self.assertEqual(L.seed_backup_take(s, e, C.byref(ne), C.byref(taken)), OK)
        self.assertFalse(taken.value, 'not before the words are confirmed')
        ok(L.seed_backup_verify(s, bad, 3, C.byref(flag)))
        self.assertFalse(flag.value)
        ok(L.seed_backup_challenge(s, pos))
        good = (C.c_char_p * 3)(*[words[i - 1].encode() for i in pos])
        ok(L.seed_backup_verify(s, good, 3, C.byref(flag)))
        self.assertTrue(flag.value)
        ne = sz(32)
        ok(L.seed_backup_take(s, e, C.byref(ne), C.byref(taken)))
        self.assertEqual((taken.value, ne.value), (True, 32))
        ne = sz(32)
        ok(L.seed_backup_take(s, e, C.byref(ne), C.byref(taken)))
        self.assertFalse(taken.value, 'handed out once')
        w2 = handle(L.wallet_from_mnemonic, ' '.join(words).encode(), None)
        self.addCleanup(L.wallet_free, w2)
        self.assertEqual(var(L.key_data, self.key(None, 0x0102, w=w2)), var(L.key_data, self.key(None, 0x0102, w=w)))

    def test_import_manifest_discover(self):
        w = mnemonic_wallet('pq_kat')
        self.addCleanup(L.wallet_free, w)
        k = handle(L.wallet_import_native_key, w, 0, bytes(range(1, 33)), 32)
        self.addCleanup(L.key_free, k)
        self.assertEqual(len(var(L.key_data, k)), 33)
        self.assertEqual(name_of(L.wallet_import_native_key(w, 0, bytes(31), 31, C.byref(P()))), 'UAArgument')
        m = json.loads(text(L.wallet_manifest_json, w))
        self.assertEqual(m['imports'], [{'network': 'evm', 'n': 0}])
        got = json.loads(text(L.wallet_discover_candidates, w, 0x0102, 0, 3))
        row = next(r for r in KEYS['ua'] if r['mnemonic'] == 'pq_kat' and r['kind'] == 0x0102 and r['account'] == 0 and r['index'] == 0)
        self.assertEqual([x['index'] for x in got], [0, 1, 2])
        self.assertEqual(got[0]['ua'], row['ua'])


class WalletErrors(WalletCase):
    def test_error_strings_never_contain_an_input(self):
        secrets = [b'zebrasecretword', b'Pa55-word-Secret', b'SECRETvalue0xdead', b'deadbeefcafe1234', b'Qx7SekritPurp0se']
        w = self.w('pq_kat')
        evm, ua, kk = self.native('pq_kat'), self.key('pq_kat', 0x0101), self.kem(KEMV['keys'][0])
        words = ' '.join(MN['pq_kat']['words'].split()[:23] + ['zebrasecretword']).encode()
        vault = jb(VAULT['vaults'][0]['vault'])
        td = jb({'types': {'EIP712Domain': []}, 'primaryType': 'SECRETvalue0xdead', 'domain': {}, 'message': {'v': 'SECRETvalue0xdead'}})
        expect = jb({'check': 'Payment', 'account': '0xdeadbeefcafe1234', 'payee': 'Pa55-word-Secret'})
        o, n = C.create_string_buffer(8192), sz(8192)
        zk = handle(L.wallet_zether_key, w, 60, 0, 7)
        self.addCleanup(L.zether_key_free, zk)
        qk = handle(L.wallet_pqz_key, w, 0, 0)
        self.addCleanup(L.pqz_key_free, qk)
        calls = [
            lambda: L.pqz_call(qk, b'zebrasecretword', b'{}', o, C.byref(n)),
            lambda: L.pqz_call(qk, b'proveRegister', jb({'key': {'seed32': 'zebrasecretword Pa55-word-Secret'}}), o, C.byref(n)),
            lambda: L.pqz_call(qk, b'dec', jb({'ct': '0xdeadbeefcafe1234', 'window': 'SECRETvalue0xdead'}), o, C.byref(n)),
            lambda: L.pqz_call(qk, b'proveRegister', jb({'proofSystemId': '0x' + 'de' * 32, 'kind': 305, 'ua': '0x' + '11' * 32}), o, C.byref(n)),
            lambda: L.pqz_open_balance_cache(qk, jb({'iv': 'Qx7SekritPurp0se', 'ct': 'zebrasecretword'}), o, C.byref(n)),
            lambda: L.pqz_check_set(jb({'set': 'Qx7SekritPurp0se', 'pkLen': 1, 'pqzlId': '0x' + '00' * 32, 'pqzhId': None})),
            lambda: L.zether_call(zk, b'zebrasecretword', b'{}', o, C.byref(n)),
            lambda: L.zether_call(zk, b'proveTransfer', jb({'key': {'mnemonic': 'zebrasecretword Pa55-word-Secret'}}), o, C.byref(n)),
            lambda: L.zether_call(zk, b'checkBalance', jb({'acc': {'C': '0xdeadbeefcafe1234', 'D': '0x'}, 'balance': 'SECRETvalue0xdead'}), o, C.byref(n)),
            lambda: L.zether_open_balance_cache(zk, jb({'iv': 'Qx7SekritPurp0se', 'ct': 'zebrasecretword'}), o, C.byref(n)),
            lambda: L.wallet_from_mnemonic(words, b'Pa55-word-Secret', C.byref(P())),
            lambda: L.wallet_open_vault(vault, b'Pa55-word-Secret', None, b'zebrasecretword', C.byref(P())),
            lambda: L.wallet_open_vault(b'{"v":1,"label":"Pa55-word-Secret"}', b'Pa55-word-Secret', None, None, C.byref(P())),
            lambda: L.wallet_seal_vault(w, b'deadbeefcafe1234'[:6], o, C.byref(n)),
            lambda: L.sign_typed(evm, td, expect, o, C.byref(n)),
            lambda: L.sign_typed_any(evm, td, o, C.byref(n)),
            lambda: L.sign_transaction(evm, jb({'type': 2, 'chainId': 'SECRETvalue0xdead'}), o, C.byref(n)),
            lambda: L.open_container(kk, b'{"v":"Pa55-word-Secret"}', jb({'purpose': 'Qx7SekritPurp0se'}), None, None, o, C.byref(n)),
            lambda: L.open_container(kk, jb(SEAL['containers'][0]['container']), jb({'purpose': 'Qx7SekritPurp0se'}), None, None, o, C.byref(n)),
            lambda: L.seal(b'\x01' * KEM_PK, KEM_PK, b'Qx7SekritPurp0se', None, 0, b'zebrasecretword', 15, o, C.byref(n), o, o, C.byref(n)),
            lambda: L.wallet_import_native_key(w, 0, b'deadbeefcafe1234', 16, C.byref(P())),
            lambda: L.uasig(jb({'purpose': 'zebrasecretword'}), None, 0, o, C.byref(n)),
            lambda: L.vault_rewrap_pin(vault, b'Pa55-word-Secret', b'zebrasecretword', o, C.byref(n)),
            lambda: L.sign_ua(ua, b'zebrasecretword_padding_to_32byt', bytes(32), o, C.byref(n)),
        ]
        for i, call in enumerate(calls):
            with self.subTest(i):
                status = call()
                detail = L.last_error()
                self.assertNotEqual(status, OK)
                for sec in secrets:
                    for j in range(len(sec) - 5):
                        self.assertNotIn(sec[j:j + 6], detail, (sec, detail))


class WalletCrypto(WalletCase):
    def test_aead_hkdf_hmac(self):
        # RFC 4231 test case 1, RFC 5869 A.1
        self.assertEqual(out32(L.hmac_sha256, b'\x0b' * 20, 20, b'Hi There', 8).hex(),
                         'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7')
        okm = C.create_string_buffer(42)
        ok(L.hkdf_sha256(b'\x0b' * 22, 22, bytes(range(13)), 13, bytes(range(0xf0, 0xfa)), 10, okm, 42))
        self.assertEqual(okm.raw.hex(), '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865')
        self.assertEqual(name_of(L.hkdf_sha256(b'k', 1, None, 0, None, 0, C.create_string_buffer(8161), 255 * 32 + 1)), 'UAArgument')
        key, nonce, aad, data = bytes(range(32)), bytes(12), b'aad', b'plaintext'
        for alg in (1, 2):
            ct = var(L.aead_seal, alg, key, nonce, aad, 3, data, len(data))
            self.assertEqual(len(ct), len(data) + 16)
            self.assertEqual(var(L.aead_open, alg, key, nonce, aad, 3, ct, len(ct)), data)
            bad = ct[:-1] + bytes([ct[-1] ^ 1])
            self.assertEqual(sig_of(L.aead_open, alg, key, nonce, aad, 3, bad, len(bad)), ('UAAead', None))
        self.assertEqual(sig_of(L.aead_seal, 3, key, nonce, aad, 3, data, len(data))[0], 'UAArgument')


ZV = HERE.parents[1] / 'zether-prover' / 'vectors'
R33 = json.loads((ZV / 'r33_keys.json').read_text())
ZJ = json.loads((VEC / 'zether.json').read_text())
STATE = HERE.parents[2] / 'smartcontracts' / 'vectors'


def commands(name):
    """scaas-ua `facade::<name>::COMMANDS` read from its source (T15g): (the release commands, the `vectors`-only raw forms).
    A test asserts that a command is in it, never that it equals a list (spec no-decryption-oracle §4.13)."""
    src = (HERE.parents[1] / 'ua-rs' / 'src' / 'facade' / f'{name}.rs').read_text()
    body = src[src.index('pub const COMMANDS: &[&str] = &['):]
    out, gated = ([], []), False
    for ln in body[:body.index('];')].splitlines()[1:]:
        ln = ln.strip()
        if ln == '#[cfg(feature = "vectors")]':
            gated = True
        elif ln.startswith('"'):
            out[gated].append(ln.strip('",'))
            gated = False
    return out


class WalletZether(WalletCase):
    """T14 (spec §10.1): the Zether facade through the C ABI."""

    def zw(self, passphrase=''):
        w = handle(L.wallet_from_mnemonic, R33['mnemonic'].encode(), passphrase.encode())
        self.addCleanup(L.wallet_free, w)
        return w

    def zk(self, w, coin=60, account=0, use=7):
        k = handle(L.wallet_zether_key, w, coin, account, use)
        self.addCleanup(L.zether_key_free, k)
        return k

    def public(self, k):
        y, ua = C.create_string_buffer(128), C.create_string_buffer(32)
        ok(L.zether_public(k, y, ua))
        return '0x' + y.raw.hex(), '0x' + ua.raw.hex()

    def call(self, k, cmd, req):
        st_, out = sig_of(L.zether_call, k, cmd.encode(), jb(req))
        return st_, None if out is None else json.loads(out[:-1])

    def request(self, f):
        r = json.loads((ZV / f).read_text())['request']
        r.pop('key')
        r.pop('includeWitness')
        return r

    def test_zether_feature_in_the_default_build(self):
        self.assertTrue(L.features() & FEATURE['zether'])

    def test_r33_keys(self):
        w = self.zw()
        for r in R33['bls12381']['keys']:
            _, _, coin, account, use = r['path'].split('/')
            self.assertEqual(self.public(self.zk(w, int(coin), int(account), int(use))), (r['Y'], r['UA']), r['path'])
        self.assertEqual(name_of(L.wallet_zether_key(w, 60, 0, 9, C.byref(P()))), 'UAArgument')

    def test_pop_and_check_balance(self):
        k = self.zk(self.zw())
        st_, pop = self.call(k, 'pop', {'curve': 'bls12381'})
        self.assertEqual(st_, '')
        r = R33['bls12381']['keys'][0]['pop']
        for f in ('popDigest', 'registrationDigest', 'uaMsg'):
            self.assertEqual(pop[f], r[f], f)
        t = self.request('transfer_bls12381.json')
        # ARCH-POS-13 (T15c, T14b): no command of a release build decrypts a caller's ciphertext (the words commands: below)
        for cmd, req in [('checkBalance', {'acc': t['acc'], 'balance': t['balance']}), ('proveTransfer', t),
                         ('decrypt', {'ct': t['acc']}), ('recoverTransfer', {})]:
            self.assertEqual(self.call(k, cmd, req), ('UAArgument', None), cmd)

    def test_pick_decoys(self):
        """T15n (CTR-UA-29, owner 2026-11-07): `pickDecoys` through the C ABI (in COMMANDS): distinct decoys, never an
        excluded UA, too few refused (UAArgument); no key."""
        self.assertIn('pickDecoys', commands('zether')[0])
        c = ['0x' + bytes([i]).hex() * 32 for i in range(1, 6)]
        st_, out = self.call(self.zk(self.zw()), 'pickDecoys', {'candidates': c, 'exclude': [c[0]], 'count': 4})
        self.assertEqual((st_, sorted(out['decoys'])), (name_of(OK), c[1:]))
        self.assertEqual(self.call(self.zk(self.zw()), 'pickDecoys', {'candidates': c, 'exclude': [c[0]], 'count': 5}), ('UAArgument', None))

    def test_words_commands_on_the_forge_rows(self):
        """T15g (ARCH-POS-13): the words commands through the C ABI on the forge rows (smartcontracts/vectors/zether/state.json;
        the holders are r33_keys.json's): each in COMMANDS, the balances the contract's; another holder's words refused before
        the key (ua-rs tests/facade_zether_state.rs counts the key's uses); every `vectors`-only raw form refused here."""
        release, raw = commands('zether')
        for c in ('balance', 'pendingBalance'):
            self.assertIn(c, release)
        for c in ('decrypt', 'decryptPending'):
            self.assertIn(c, raw)
        rows = json.loads((STATE / 'zether' / 'state.json').read_text())
        row = {r['name'].split(':')[0]: r for r in rows['accounts']}
        loc = {f: rows[f] for f in ('family', 'chainId', 'chainUid', 'token', 'block', 'psid')}

        def words(name):
            return dict(loc, ua=row[name]['ua'], account=row[name]['account'], accountData=row[name]['accountData'], tableBits=18,
                        boundBits=20)
        w = self.zw()
        alice, bob = self.zk(w, 60, 0, 7), self.zk(w, 60, 1, 7)
        st_, out = self.call(alice, 'balance', words('alice'))
        self.assertEqual((st_, out['amount']), ('', str(row['alice']['balance'])))
        st_, out = self.call(bob, 'pendingBalance', words('bob'))
        self.assertEqual((st_, out['amount']), ('', str(row['bob']['pending'])))
        self.assertEqual(self.call(bob, 'balance', words('alice')), ('UAArgument', None), "another holder's words")
        for c in raw:
            self.assertEqual(self.call(alice, c, {}), ('UAArgument', None), c)

    def test_a_key_field_in_command_json_is_refused(self):
        k = self.zk(self.zw())
        t = self.request('transfer_bls12381.json')
        for cmd, req in [('pop', {}), ('encrypt', {'Y': self.public(k)[0], 'amount': 1})]:
            self.assertEqual(self.call(k, cmd, req)[0], '', cmd + ': positive control')
            bad = dict(req, key={'seed': '0x' + '11' * 64, 'coin': 60, 'account': 0})
            self.assertEqual(self.call(k, cmd, bad), ('UAArgument', None), cmd)
        for f in ('includeWitness', 'revealSecret'):
            self.assertEqual(self.call(k, 'pop', {f: True}), ('UAArgument', None), f)
        self.assertEqual(self.call(k, 'verifyTransfer', {})[0], 'UAArgument', 'verifiers are not exposed')
        self.assertEqual(self.call(k, 'pop', {'curve': 'bls12381', 'x': {'a': ' ' * 10}})[0], 'UAArgument')

    def test_cache_box_rows(self):
        for r in ZJ['cacheBox']:
            m = MN[r['mnemonic']]
            w = handle(L.wallet_from_mnemonic, m['words'].encode(), m['passphrase'].encode())
            self.addCleanup(L.wallet_free, w)
            k = self.zk(w, r['coin'], r['account'], r['use'])
            self.assertEqual(self.public(k), (r['Y'], r['UA']))
            pt = var(L.zether_open_balance_cache, k, jb(r['box']))
            self.assertEqual('0x' + pt.hex(), r['plaintext'], r['id'])
            box = text(L.zether_seal_balance_cache, k, pt, len(pt))
            self.assertEqual(var(L.zether_open_balance_cache, k, box.encode()), pt, r['id'] + ': round trip')
        for r in ZJ['cacheRefusals']:
            m = MN[r['mnemonic']]
            w = handle(L.wallet_from_mnemonic, m['words'].encode(), m['passphrase'].encode())
            self.addCleanup(L.wallet_free, w)
            self.assertEqual(sig_of(L.zether_open_balance_cache, self.zk(w, r['coin'], r['account'], r['use']), jb(r['box'])),
                             ('UAAead', None), r['id'])

    def test_zether_handle_after_lock_and_free_is_KEY_REVOKED(self):
        w = self.zw()
        k = self.zk(w)
        y = self.public(k)
        ok(L.wallet_lock(w))
        self.assertEqual(self.call(k, 'pop', {}), ('UAKeyRevoked', None))
        self.assertEqual(sig_of(L.zether_seal_balance_cache, k, b'{}', 2), ('UAKeyRevoked', None))
        self.assertEqual(self.public(k), y, 'public data stays readable')
        self.assertEqual(name_of(L.wallet_zether_key(w, 60, 0, 7, C.byref(P()))), 'UAWalletLocked')
        w2 = handle(L.wallet_from_mnemonic, R33['mnemonic'].encode(), b'')
        k2 = handle(L.wallet_zether_key, w2, 60, 1, 7)
        L.wallet_free(w2)
        try:
            self.assertEqual(self.call(k2, 'pop', {}), ('UAKeyRevoked', None))
        finally:
            L.zether_key_free(k2)
        L.zether_key_free(None)


PQZL_ID = {'n2048-kmax1024': 'c752e7f57778114dbfaac5d43843577b54e13e3ed162517145a37b5a3ec6cdfe',
           'n2304-kmax4096': 'ef1ffbcbd05394f8276e50a6c254022edf53bbd08a56e22aadddac2b9b90336e',
           'n2560-kmax16384': 'eacf34a3a8b6b5aff9be26e24ec03176e2699784c4ff8a1b4c8921cb09276882',
           'n2816-kmax65536': 'a801f5c4697a35a88b90a28249d73cf2e1634d8875bf1a5f6af6c283ac8e8aa9'}


PQZ_OUT_MAX = 1_052_672  # SCAAS_UA_PQZ_OUT_MAX


class WalletPqz(WalletCase):
    """T15 (spec §10.2): the PQZ facade through the C ABI (the Rust suite tests/facade_pqz.rs verifies every proof)."""

    def qw(self):
        m = MN['pq_kat']
        w = handle(L.wallet_from_mnemonic, m['words'].encode(), m['passphrase'].encode())
        self.addCleanup(L.wallet_free, w)
        return w

    def qk(self, w, account=0, index=0, version=None):
        k = handle(L.wallet_pqz_key, w, account, index) if version is None else handle(L.wallet_pqz_key_version, w, account, index, version)
        self.addCleanup(L.pqz_key_free, k)
        return k

    def call(self, k, cmd, req):
        # one call into a buffer of SCAAS_UA_PQZ_OUT_MAX: a size query would prove again, and a proof's length varies
        buf, n = C.create_string_buffer(PQZ_OUT_MAX), sz(PQZ_OUT_MAX)
        status = L.pqz_call(k, cmd.encode(), jb(req), buf, C.byref(n))
        return name_of(status), json.loads(buf.raw[:n.value - 1]) if status == OK else None

    def test_out_max_holds_a_proof_twice(self):
        k = self.qk(self.qw())
        req = {'proofSystemId': '0x' + PQZL_ID['n2304-kmax4096'], 'kind': 0x0131, 'ua': '0x' + '11' * 32}
        small = C.create_string_buffer(64)
        n = sz(64)
        self.assertEqual(name_of(L.pqz_call(k, b'proveRegister', jb(req), small, C.byref(n))), 'UABuffer')
        self.assertLessEqual(n.value, PQZ_OUT_MAX)
        self.assertEqual(self.call(k, 'proveRegister', req)[0], '')

    def the_set(self):
        return json.loads(text(L.pqz_set))

    def test_pqz_and_one_set_in_the_default_build(self):
        f = L.features()
        self.assertTrue(f & FEATURE['pqz'])
        sets = [n for n in FEATURES if n.startswith('pqz-set-') and f & FEATURE[n]]
        self.assertEqual(sets, ['pqz-set-n2304-kmax4096'])
        s = self.the_set()
        self.assertEqual((s['set'], s['pkLen'], s['pqzlId']), ('n2304-kmax4096', 18432, '0x' + PQZL_ID['n2304-kmax4096']))
        self.assertEqual(name_of(L.pqz_check_set(jb(s))), '')
        for other in (dict(s, set='n2048-kmax1024'), dict(s, pkLen=16384), dict(s, pqzlId='0x' + PQZL_ID['n2048-kmax1024']),
                      dict(s, pqzhId=None)):
            self.assertEqual(name_of(L.pqz_check_set(jb(other))), 'UAPqzSetMismatch', other)
        self.assertEqual(name_of(L.pqz_check_set(jb(dict(s, extra=1)))), 'UAArgument')
        self.assertEqual(L.status_name(40).decode(), 'UAPqzSetMismatch')

    def test_leaf_is_the_ua_pq_rule(self):
        import hashlib
        import hmac
        m = MN['pq_kat']
        seed = hashlib.pbkdf2_hmac('sha512', m['words'].encode(), b'mnemonic' + m['passphrase'].encode(), 2048)
        prk = hmac.new(b'scaas.ua.pq.v1', seed, hashlib.sha256).digest()
        w = self.qw()
        for a, i in ((0, 0), (1, 2)):
            info = b'scaas.ua.pqz-mlwe.v1' + a.to_bytes(4, 'big') + i.to_bytes(4, 'big')
            want = hmac.new(prk, info + b'\x01', hashlib.sha256).digest()
            leaf = C.create_string_buffer(32)
            ok(L.export_pqz_leaf_raw(w, a, i, leaf))
            self.assertEqual(leaf.raw, want, (a, i))
            self.assertEqual(len(var(L.pqz_public, self.qk(w, a, i))), 18432)
        self.assertEqual(name_of(L.export_pqz_leaf_raw(w, 1 << 31, 0, C.create_string_buffer(32))), 'UAArgument')
        self.assertEqual(name_of(L.export_pqz_leaf_raw(w, 0, 0, None)), 'UAArgument')

    def test_pqz_key_versions_are_the_pq_kat_rows(self):
        """Group 3g C8 (T15o): scaas_ua_wallet_pqz_key_version / scaas_ua_export_pqz_leaf_raw_version give pq_kat.json's
        `pqzSeeds` (version 0 the info without a suffix, v >= 1 with be64(v)); version 0 is scaas_ua_wallet_pqz_key's key."""
        rows = json.loads((STATE / 'ua' / 'pq_kat.json').read_text())['pqzSeeds']
        self.assertEqual([r['version'] for r in rows], [0, 1, 2])
        w = self.qw()
        pks = []
        for r in rows:
            leaf = C.create_string_buffer(32)
            ok(L.export_pqz_leaf_raw_version(w, r['account'], r['index'], r['version'], leaf))
            self.assertEqual('0x' + leaf.raw.hex(), r['seed32'], r['version'])
            pks.append(var(L.pqz_public, self.qk(w, r['account'], r['index'], r['version'])))
        self.assertEqual(pks[0], var(L.pqz_public, self.qk(w)))
        self.assertEqual(len(set(pks)), 3, 'one key per version')
        self.assertEqual(name_of(L.wallet_pqz_key_version(w, 1 << 31, 0, 1, C.byref(P()))), 'UAArgument')
        self.assertEqual(name_of(L.export_pqz_leaf_raw_version(w, 0, 0, 1, None)), 'UAArgument')

    def test_register_set_mismatch_and_key_field(self):
        k = self.qk(self.qw())
        req = {'proofSystemId': '0x' + PQZL_ID['n2304-kmax4096'], 'kind': 0x0131, 'ua': '0x' + '11' * 32}
        st_, out = self.call(k, 'proveRegister', req)
        self.assertEqual(st_, '')
        pk = var(L.pqz_public, k)
        self.assertEqual(bytes.fromhex(out['stmt'][2:])[96:], pk)
        self.assertEqual(self.call(k, 'proveRegister', dict(req, proofSystemId='0x' + PQZL_ID['n2048-kmax1024'])), ('UAPqzSetMismatch', None))
        for f in ('key', 'seed32', 's', 'witness'):
            self.assertEqual(self.call(k, 'proveRegister', dict(req, **{f: {'seed32': '0x' + '11' * 32}})), ('UAArgument', None), f)
        self.assertEqual(self.call(k, 'verify', {})[0], 'UAArgument', 'verifiers are not exposed')

    def test_enc_dec_and_cache_box(self):
        w = self.qw()
        k = self.qk(w)
        pk = '0x' + var(L.pqz_public, k).hex()
        st_, e = self.call(k, 'enc', {'pks': [pk], 'values': [123456]})
        self.assertEqual(st_, '')
        # ARCH-POS-13 (T15c): a release build has no raw decrypt; a well-formed `dec` is an unknown command
        self.assertEqual(self.call(k, 'dec', {'ct': e['u'] + e['vs'][0][2:]}), ('UAArgument', None))
        box = text(L.pqz_seal_balance_cache, k, b'{"v":1}', 7)
        self.assertEqual(var(L.pqz_open_balance_cache, k, box.encode()), b'{"v":1}')
        self.assertEqual(sig_of(L.pqz_open_balance_cache, self.qk(w, 0, 1), box.encode()), ('UAAead', None))

    def test_pick_decoys(self):
        """T15n (CTR-UA-29, owner 2026-11-07): `pickDecoys` through the C ABI (in COMMANDS), op 7's decoys: weight 0 never
        drawn, never an excluded UA, too few refused (UAArgument); no key."""
        self.assertIn('pickDecoys', commands('pqz')[0])
        c = ['0x' + bytes([i]).hex() * 32 for i in range(1, 6)]
        k = self.qk(self.qw())
        st_, out = self.call(k, 'pickDecoys', {'candidates': c, 'exclude': [c[0]], 'count': 2, 'weights': [9, 1, 0, 0, 3]})
        self.assertEqual((st_, sorted(out['decoys'])), (name_of(OK), [c[1], c[4]]))
        self.assertEqual(self.call(k, 'pickDecoys', {'candidates': c, 'exclude': [], 'count': 6}), ('UAArgument', None))
        # T15n2: `recipient` (excluded implicitly) answers `legs`, the recipient once with the decoys, shuffled
        st_, out = self.call(k, 'pickDecoys', {'candidates': c, 'exclude': [c[0]], 'count': 3, 'recipient': c[1]})
        self.assertEqual((st_, sorted(out['legs']), c[1] in out['decoys']), (name_of(OK), c[1:], False))

    def test_words_commands_on_the_forge_rows(self):
        """T15g (ARCH-POS-13): `balance` through the C ABI on a forge row (smartcontracts/vectors/pqz/n2304-kmax4096/state.json):
        in COMMANDS; the forge keys are mocked, so the words bind to no wallet key and are refused (UAArgument), with the
        other set's psid UAPqzSetMismatch, both before the key (ua-rs tests/facade_pqz_state.rs counts the key's uses); every
        `vectors`-only raw form refused here."""
        release, raw = commands('pqz')
        self.assertIn('balance', release)
        self.assertIn('dec', raw)
        rows = json.loads((STATE / 'pqz' / 'n2304-kmax4096' / 'state.json').read_text())
        a = rows['accounts'][0]
        words = dict({f: rows[f] for f in ('chainUid', 'token', 'psid')},
                     **{f: a[f] for f in ('ua', 'block', 'account', 'pending', 'accWords', 'blobs', 'keyRecord')}, forOp7=False,
                     # group 3g (T15o): the UA's sendCounter word, version 0, pqzVersions (latest 0, current 0, listed)
                     sendCounterWord='0x' + a['sendCounter'].to_bytes(32, 'big').hex(), keyVersion=0,
                     keyVersions='0x' + (1 << 128).to_bytes(32, 'big').hex())
        k = self.qk(self.qw())
        self.assertEqual(self.call(k, 'balance', words), ('UAArgument', None))
        self.assertEqual(self.call(k, 'balance', dict(words, psid='0x' + PQZL_ID['n2048-kmax1024'])), ('UAPqzSetMismatch', None))
        for c in raw:
            self.assertEqual(self.call(k, c, {}), ('UAArgument', None), c)
        # T15i: words rows for wallet keys (smartcontracts/vectors/pqz/n2304-kmax4096/wallet_state.json, written by ua-rs
        # under `vectors`, gen_wallet_state.sh): each row's own handle decrypts its balance through the C ABI
        w = self.qw()
        ws = json.loads((STATE / 'pqz' / 'n2304-kmax4096' / 'wallet_state.json').read_text())
        for r in ws['rows']:
            st_, out = self.call(self.qk(w, r['account'], r['index'], r['version']), 'balance', r['request'])
            self.assertEqual((st_, out and out['value']), (name_of(OK), r['value']), r['name'])
        # T20d9 (C-PP-8): the proof path's commands are in COMMANDS; each proven row end to end (provenOpen, provenAdd with the
        # session, balanceProven), and the quorum's row through scaas_ua_pqz_check (no handle)
        for c in ['provenOpen', 'provenAdd', 'provenCancel', 'balanceProven', 'proveTransferProven', 'proveTransferMultiProven', 'proveBurnProven', 'proveRefreshProven']:
            self.assertIn(c, commands('pqz')[0], c)
        for r in ws['proven']:
            k = self.qk(w, r['account'], r['index'], r['version'])
            st_, o = self.call(k, 'provenOpen', r['open'])
            self.assertEqual(st_, name_of(OK), r['name'])
            st_, a = self.call(k, 'provenAdd', dict(r['add'], session=o['session']))
            self.assertEqual((st_, a['accepted']), (name_of(OK), o['need']), r['name'])
            st_, b = self.call(k, 'balanceProven', {'session': o['session']})
            self.assertEqual((b['value'], [p['kind'] for p in b['parts']]), (r['value'], r['kinds']), r['name'])
        for r in ws['check']:
            buf, n = C.create_string_buffer(PQZ_OUT_MAX), sz(PQZ_OUT_MAX)
            self.assertEqual(name_of(L.pqz_check(jb(r['request']), buf, C.byref(n))), name_of(OK), r['name'])
            self.assertEqual(json.loads(buf.raw[:n.value - 1]), r['answer'], r['name'])
            self.assertEqual(name_of(L.pqz_check(jb(dict(r['request'], keyRecord='0x' + '00' * 32)), buf, C.byref(n))), 'UAArgument')

    def test_pqz_handle_after_lock_and_free_is_KEY_REVOKED(self):
        w = self.qw()
        k = self.qk(w)
        pk = var(L.pqz_public, k)
        box = text(L.pqz_seal_balance_cache, k, b'{}', 2)
        ok(L.wallet_lock(w))
        self.assertEqual(sig_of(L.pqz_open_balance_cache, k, box.encode()), ('UAKeyRevoked', None))
        req = {'proofSystemId': '0x' + PQZL_ID['n2304-kmax4096'], 'kind': 0x0131, 'ua': '0x' + '11' * 32}
        self.assertEqual(self.call(k, 'proveRegister', req), ('UAKeyRevoked', None))
        self.assertEqual(var(L.pqz_public, k), pk, 'public data stays readable')
        self.assertEqual(name_of(L.wallet_pqz_key(w, 0, 0, C.byref(P()))), 'UAWalletLocked')
        self.assertEqual(name_of(L.export_pqz_leaf_raw(w, 0, 0, C.create_string_buffer(32))), 'UAWalletLocked')
        m = MN['pq_kat']
        w2 = handle(L.wallet_from_mnemonic, m['words'].encode(), m['passphrase'].encode())
        k2 = handle(L.wallet_pqz_key, w2, 0, 1)
        L.wallet_free(w2)
        try:
            self.assertEqual(sig_of(L.pqz_seal_balance_cache, k2, b'{}', 2), ('UAKeyRevoked', None))
        finally:
            L.pqz_key_free(k2)
        L.pqz_key_free(None)


class WalletPqzBackup(WalletCase):
    """T16a (owner 2026-11-06): the k-of-n backup of an msig holder's PQZ seed32 through the C ABI (the Rust suite
    tests/pqz_backup.rs pins the field, the split and every refusal). Three members (0x0130, one mnemonic each), a 2-of-3 msig."""

    def setUp(self):
        self.mids = ['bip39_test', 'twelve_words', 'non_ascii_passphrase']
        self.op = self.w('pq_kat')
        self.op_key = self.key('pq_kat', 0x0130)
        self.pqz = handle(L.wallet_pqz_key, self.op, 7, 0)
        self.addCleanup(L.pqz_key_free, self.pqz)
        self.mkeys = [self.key(m, 0x0130) for m in self.mids]
        self.mkd = [var(L.key_data, k) for k in self.mkeys]
        self.mua = [out32(L.derive_ua, 0x0130, kd, len(kd), False) for kd in self.mkd]
        self.kks = [handle(L.kem_key, k, 0) for k in self.mkeys]
        for kk in self.kks:
            self.addCleanup(L.kem_free, kk)
        self.kpk = []
        for kk in self.kks:
            buf = C.create_string_buffer(KEM_PK)
            ok(L.kem_pk(kk, buf))
            self.kpk.append(buf.raw)
        order = sorted(range(3), key=lambda i: self.mua[i])
        self.msig_kd = (2).to_bytes(2, 'big') + (3).to_bytes(2, 'big') + b''.join(
            (0x0130).to_bytes(2, 'big') + self.mua[i] + (1).to_bytes(2, 'big') for i in order)
        self.msig_ua = out32(L.derive_ua, 0x0120, self.msig_kd, len(self.msig_kd), False)
        self.op_ua = out32(L.derive_ua, 0x0130, var(L.key_data, self.op_key), len(var(L.key_data, self.op_key)), False)

    def rec(self, i):
        return Recipient(0x0130, self.mkd[i], len(self.mkd[i]), 0, self.kpk[i], len(self.kpk[i]), False)

    def expect(self, i):
        return {'purpose': 'scaas/pqz-share/v1', 'sender': {'set': [hx(u) for u in [self.op_ua] + self.mua]},
                'recipient': {'ua': hx(self.mua[i]), 'version': 0}}

    def deal(self, threshold=0):
        recs = (Recipient * 3)(*[self.rec(i) for i in range(3)])
        return json.loads(once(L.pqz_seed_backup, self.pqz, self.op_key, self.msig_kd, len(self.msig_kd), 0, threshold, recs, 3))

    def rebuild(self, cs, ua=None, kh=None):
        out = P()
        status = L.wallet_pqz_reconstruct(self.w(self.mids[0]), self.kks[0], jb(cs), jb(self.expect(0)), None, None,
                                          ua or self.msig_ua, 0, kh or self.kh, C.byref(out))
        if status == OK:
            self.addCleanup(L.pqz_key_free, out)
        return name_of(status), out

    def warn(self, backups, version=0):
        m = bl()
        ok(L.pqz_seed_backup_warning(0x0120, self.msig_ua, version, self.pk, len(self.pk), jb(backups), C.byref(m)))
        return m.value

    def test_two_of_three_rebuild_through_the_abi(self):
        self.pk = var(L.pqz_public, self.pqz)
        b = self.deal()
        self.kh = bytes.fromhex(b['pqzKeyHash'][2:])
        self.assertEqual((b['k'], b['n'], b['version'], b['msigUa']), (2, 3, 0, hx(self.msig_ua)))
        self.assertEqual(len(b['shares']), 3)
        # member 1 seals its share on to member 0, who rebuilds from its own and that one
        r0 = self.rec(0)
        fwd = json.loads(once(L.pqz_share_reseal, self.kks[1], jb(b['shares'][1]), jb(self.expect(1)), None, None,
                              C.byref(r0), self.mkeys[1]))
        st_, k = self.rebuild([b['shares'][0], fwd])
        self.assertEqual(st_, '')
        self.assertEqual(var(L.pqz_public, k), self.pk, 'the rebuilt key is the operator\'s')
        self.assertEqual(self.rebuild([b['shares'][0]])[0], 'UAArgument', 'k - 1 shares')
        other = bytes([self.msig_ua[0] ^ 1]) + self.msig_ua[1:]
        self.assertEqual(self.rebuild([b['shares'][0], fwd], ua=other)[0], 'UAArgument', 'another msig')
        self.assertEqual(self.rebuild([b['shares'][0], fwd], kh=bytes(32))[0], 'UAArgument', 'another key hash')
        # the warning: missing without a backup, cleared by this one; never a refusal (a status OK either way)
        self.assertTrue(self.warn(None))
        self.assertTrue(self.warn([]))
        self.assertFalse(self.warn([b]))
        self.assertTrue(self.warn([b], version=1))
        m = bl()
        ok(L.pqz_seed_backup_warning(0x0130, self.mua[0], 0, self.pk, len(self.pk), None, C.byref(m)))
        self.assertFalse(m.value, 'a single key needs no backup')

    def test_rebuilt_key_after_lock_and_unlock(self):
        """T16b (owner 2026-11-06): the rebuilt key persists in the rebuilder's pqz-held vault; after unlock it is held again
        once that vault opens, checked against its pqzKeyHash."""
        self.pk = var(L.pqz_public, self.pqz)
        b = self.deal()
        self.kh = bytes.fromhex(b['pqzKeyHash'][2:])
        w = mnemonic_wallet(self.mids[0])  # a wallet of its own: it is locked below
        self.addCleanup(L.wallet_free, w)
        out = P()
        ok(L.wallet_pqz_reconstruct(w, self.kks[0], jb(b['shares'][:1] + [json.loads(once(
            L.pqz_share_reseal, self.kks[1], jb(b['shares'][1]), jb(self.expect(1)), None, None, C.byref(self.rec(0)),
            self.mkeys[1]))]), jb(self.expect(0)), None, None, self.msig_ua, 0, self.kh, C.byref(out)))
        self.addCleanup(L.pqz_key_free, out)
        self.assertEqual(json.loads(text(L.wallet_manifest_json, w))['pqzHeld'],
                         [{'ua': hx(self.msig_ua), 'version': 0, 'pqzKeyHash': hx(self.kh)}])
        label = f'pqz-held:{hx(self.msig_ua)}:0:{hx(self.kh)}'.encode()
        seed_v = text(L.wallet_seal_vault, w, b'correct horse 9').encode()
        held_v = text(L.wallet_seal_label_vault, w, label, b'correct horse 9').encode()
        ok(L.wallet_lock(w))
        self.assertEqual(name_of(L.wallet_pqz_held_key(w, self.kh, C.byref(P()))), 'UAWalletLocked')
        ok(L.wallet_unlock(w, seed_v, b'correct horse 9', None, b''))
        self.assertEqual(name_of(L.wallet_pqz_held_key(w, self.kh, C.byref(P()))), 'UAArgument', 'listed, not held before its vault opens')
        ok(L.wallet_open_label_vault(w, held_v, b'correct horse 9', None))
        k = handle(L.wallet_pqz_held_key, w, self.kh)
        self.addCleanup(L.pqz_key_free, k)
        self.assertEqual(var(L.pqz_public, k), self.pk, 'the operator\'s key again')
        self.assertEqual(name_of(L.wallet_pqz_held_key(w, bytes(32), C.byref(P()))), 'UAArgument', 'another key hash')

    def test_k_and_recipients_checked(self):
        self.assertEqual(self.deal(3)['k'], 3)
        recs = (Recipient * 3)(*[self.rec(i) for i in range(3)])
        status = lambda t, rs, n: sig_of(L.pqz_seed_backup, self.pqz, self.op_key, self.msig_kd, len(self.msig_kd), 0, t, rs, n)[0]
        self.assertEqual(status(4, recs, 3), 'UAArgument', 'k > n')
        twice = (Recipient * 2)(self.rec(0), self.rec(0))
        self.assertEqual(status(0, twice, 2), 'UAArgument', 'a member twice')
        eph = (Recipient * 2)(self.rec(0), Recipient(0, None, 0, 0, self.kpk[1], len(self.kpk[1]), True))
        self.assertEqual(status(0, eph, 2), 'UAArgument', 'an ephemeral key')
        ms = (Recipient * 1)(Recipient(0x0120, self.msig_kd, len(self.msig_kd), 0, self.kpk[0], len(self.kpk[0]), False))
        self.assertEqual(status(1, ms, 1), 'UAKemHolder', 'MD-11: an msig holds no KEM key')

if __name__ == '__main__':
    unittest.main()
