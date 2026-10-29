# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The C ABI (include/scaas_ua.h) through ctypes against smartcontracts/vectors/ua/: mirrors
clients/ua-cxx/tests/vectors_test.cpp row for row, plus the ABI edges (buffers, NULL, non-UTF-8, per-thread last error).
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

OK, ERR_KEY_DATA, ERR_ARGUMENT, ERR_BUFFER = 0, 1, 8, 9
KEM_PK = 1600


class Kind(C.Structure):
    _fields_ = [('kind', C.c_uint16), ('native', C.c_bool), ('lengths_len', C.c_uint8), ('lengths', C.c_uint32 * 2),
                ('name', C.c_char_p), ('group', C.c_char_p)]


class Member(C.Structure):
    _fields_ = [('kind', C.c_uint16), ('id', C.c_uint8 * 32), ('weight', C.c_uint16)]


class HolderPop(C.Structure):  # ScaasUaHolderPop: byte arrays only, no padding
    _fields_ = [(n, C.c_uint8 * 32) for n in ('pqz_key_hash', 'pqz_pop_hash', 'kem_record_hash', 'portable_pop_digest',
                                              'registration_digest', 'message')] + [('has_member_digest', C.c_bool),
                                                                                    ('member_digest', C.c_uint8 * 32)]


class PqzKeyRecord(C.Structure):  # ScaasUaPqzKeyRecord
    _fields_ = [(n, C.c_uint8 * 32) for n in ('pqz_key_hash', 'pqz_pop_hash', 'pqz_key_digest', 'record_digest', 'message',
                                              'pqz_reg_message')] + [('has_member_digest', C.c_bool), ('member_digest', C.c_uint8 * 32)]


P, u8, u16, u32, u64, sz, bl, st = C.c_void_p, C.c_char_p, C.c_uint16, C.c_uint32, C.c_uint64, C.c_size_t, C.c_bool, C.c_int32
L = types.SimpleNamespace()  # L.tag is scaas_ua_tag
for name, res, args in [
    ('abi_version', u32, []), ('status_name', C.c_char_p, [st]), ('last_error', C.c_char_p, []),
    ('kind_count', sz, []), ('kind_at', st, [sz, P]), ('kind_info', st, [u16, P]),
    ('is_native', bl, [u16]), ('is_zether', bl, [u16]), ('is_pqz_holder', bl, [u16]), ('is_signing', bl, [u16]), ('is_member', bl, [u16, bl]),
    ('tag', st, [u16, P]), ('kind_tag_string', st, [u16, P, P]), ('group_tag', st, [u8, P, P]),
    ('group_tag_string', st, [u8, P, P, P]), ('msg_tag', st, [P]), ('purpose_tag', st, [u8, P]), ('purpose_tag_v', st, [u8, u32, P]),
    ('kem_record_tag', st, [P]), ('pqz_key_record_tag', st, [P]),
    ('ua_of', st, [u16, u8, sz, P]), ('derive_ua', st, [u16, u8, sz, bl, P]), ('native_id', st, [u16, u8, sz, P]),
    ('key_hash_of', st, [u16, u8, sz, P, P]), ('validate_key_data', st, [u16, u8, sz, bl]),
    ('in_native_space', st, [u8, P]), ('ua_message', st, [u16, u8, u8, P]), ('chain_key_hash', st, [u64, P]),
    ('portable_pop_digest', st, [u8, u8, u8, P]), ('registration_digest', st, [u8, u8, P]),
    ('kem_record_digest', st, [u8, u64, u8, sz, P]), ('kem_record_message', st, [u16, u8, u64, u8, sz, P]),
    ('holder_pop_message', st, [u16, u8, u8, sz, u8, sz, u8, sz, u8, sz, u64, u8, sz, P]),
    ('pqz_reg_message', st, [u8, u8, sz, u64, u8, sz, P]), ('pqz_key_digest', st, [u8, u8, P]),
    ('pqz_key_record_digest', st, [u8, u8, P]),
    ('pqz_key_record_message', st, [u16, u8, u8, sz, u8, sz, u8, sz, u8, sz, bl, P]),
    ('personal_sign_digest', st, [u8, P]), ('is_portable_purpose', st, [u8, P]), ('msig_pqz_eligible', st, [u8, sz, P]),
    ('ua_auth_domain_separator', st, [u32, u64, u8, u8, P]),
    ('ua_auth_digest', st, [u32, u64, u8, u8, u8, u8, u8, P]), ('member_digest', st, [u8, u8, P]),
    ('canonical_id', st, [u8, P, P]), ('encode_msig', st, [u16, P, sz, P, P]),
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


def holder(kind, ua, key_data=b'', key=b'', pop=b'', pop_hash=b'', ver=0, kem_pk=b''):
    o = HolderPop()
    ok(L.holder_pop_message(kind, ua, key_data, len(key_data), key, len(key), pop, len(pop), pop_hash, len(pop_hash), ver, kem_pk,
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
    return holder(row['kind'], b(row['ua']), b(row['keyData']), b(a['pqzKey']), pop, h if any(h) else b'', int(a['kemVersion']), b(a['kemPk']))


class Vectors(unittest.TestCase):
    def test_table_groups_purposes_constants(self):
        self.assertEqual(L.abi_version(), 2)
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
        self.assertEqual(len(K['purposes']), 14)  # 13 purposes, `pop` has v1 and v2
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

    def test_messages(self):
        for r in K['messages']:
            with self.subTest(r['purpose'], kind=r['kind']):
                p = out32(L.purpose_tag_v, r['purpose'].encode(), r['version'])  # each row carries its purpose `version` (A4-c1)
                self.assertEqual(hx(p), r['purposeTag'])
                self.assertEqual(hx(out32(L.ua_message, r['kind'], p, b(r['digest']))), r['uaMsg'])

    def test_structures(self):
        for p in S['pop']:
            with self.subTest('pop', ua=p['ua']):
                d = out32(L.portable_pop_digest, b(p['ua']), b(p['pqzKeyHash']), b(p['kemRecordHash']))
                self.assertEqual(hx(d), p['portablePopDigest'])
                self.assertEqual(hx(out32(L.registration_digest, d, b(p['pqzPopHash']))), p['registrationDigest'])
        self.assertEqual(hx(out32(L.chain_key_hash, 2**40 + 7)), '0x6e45d591a544f53396f6e86d49f5809196c5725f9d99dbd2ca97f9925c7ce950')  # keccak256("evm:1099511627783")
        pk, proof = b(K['pqzKey']), bytes([7]) * 32
        for p in S['pqzReg']:
            ua, kem = b(p['ua']), b(p['kemRecordHash'])
            kh = opt32(lambda *a: kd(L.key_hash_of, 0x0142, pk, *a))
            self.assertEqual(hx(kh), p['pqzKeyHash'])
            portable = out32(L.portable_pop_digest, ua, kh, kem)
            self.assertEqual(hx(portable), p['portablePopDigest'])
            self.assertEqual(hx(out32(L.ua_message, 0x0142, out32(L.purpose_tag_v, b'pop', 2), portable)), p['pqzRegMessage'])
            if any(kem):
                continue  # the row's KEM record hash is opaque; the real records are in portable.json
            self.assertEqual(hx(out32(L.pqz_reg_message, ua, pk, len(pk), 0, None, 0)), p['pqzRegMessage'])
            got = holder(p['kind'], ua, b'', pk, b'', proof)
            self.assertEqual((hx(bytes(got.pqz_key_hash)), hx(bytes(got.portable_pop_digest))), (p['pqzKeyHash'], p['portablePopDigest']))
            for bad in (0x0101, 0x0133):
                self.assertEqual(code_of(lambda: holder(bad, ua, b'', pk, b'', proof)), 'UAPqzHolder')
        for p in S['pqzMsig']:
            d = b(p['keyData'])
            e = bl()
            ok(L.msig_pqz_eligible(d, len(d), C.byref(e)))
            self.assertEqual(e.value, p['eligible'], p['reason'])
            h = b(K['pqzKeyHash']) if p['eligible'] else bytes(32)
            self.assertEqual(hx(out32(L.portable_pop_digest, b(p['ua']), h, bytes(32))), p['portablePopDigest'])
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
        self.assertEqual(hx(out32(L.kem_record_tag)), t['KEM_RECORD_TAG']['hash'])
        self.assertEqual(hx(out32(L.pqz_key_record_tag)), t['PQZ_KEY_RECORD_TAG']['hash'])
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
                    self.assertEqual(hx(bytes(h.portable_pop_digest)), r['portablePopDigest'])
                    self.assertEqual(hx(bytes(h.registration_digest)), r['registrationDigest'])
                    self.assertEqual(hx(bytes(h.message)), r['popMessage'])
                    self.assertEqual(out32(L.portable_pop_digest, ua, bytes(h.pqz_key_hash), bytes(h.kem_record_hash)), bytes(h.portable_pop_digest))
                    self.assertEqual(out32(L.registration_digest, bytes(h.portable_pop_digest), bytes(h.pqz_pop_hash)), bytes(h.registration_digest))
                    self.assertEqual(out32(L.ua_message, r['kind'], out32(L.purpose_tag_v, b'pop', 2), bytes(h.registration_digest)), bytes(h.message))
                    self.assertEqual(mh(h), r.get('memberDigest', ''))
                a = r['attrs']
                pk = b(a['pqzKey'])
                if pk:
                    with_pqz += 1
                    ver, kpk = int(a['kemVersion']), b(a['kemPk']) if int(a['kemVersion']) else b''
                    self.assertEqual(hx(out32(L.pqz_reg_message, ua, pk, len(pk), ver, kpk, len(kpk))), r['pqzRegMessage'])
                else:
                    self.assertEqual(b(r['pqzRegMessage']), bytes(32))
                msigs += r['kind'] == 0x0120
                n += 1
        self.assertEqual((n, with_pqz, msigs), (25, 8, 6))

    def test_kem_record(self):
        for r in PV['kemRecords']:
            with self.subTest(r['id']):
                ua, pk, v = b(r['ua']), b(r['kemPk']), int(r['version'])
                d = out32(L.kem_record_digest, ua, v, pk, len(pk))
                self.assertEqual(hx(d), r['digest'])
                m = out32(L.kem_record_message, r['kind'], ua, v, pk, len(pk))
                self.assertEqual(hx(m), r['message'])
                self.assertEqual(m, out32(L.ua_message, r['kind'], out32(L.purpose_tag, b'kem'), d))
                if r['kind'] == 0x0120:
                    self.assertEqual(hx(out32(L.member_digest, ua, m)), r['memberDigest'])
        self.assertEqual(len(PV['kemRecords']), 9)
        u = bytes([1]) * 32
        for v, pk, code in ((0, bytes(KEM_PK), 'UAKemVersion'), (1, bytes(KEM_PK - 1), 'UAKemKeyLength'),
                            (1, bytes(KEM_PK + 1), 'UAKemKeyLength'), (1, b'', 'UAKemKeyLength')):
            self.assertEqual(code_of(lambda: out32(L.kem_record_digest, u, v, pk, len(pk))), code)
        self.assertEqual(hx(out32(L.kem_record_digest, u, 2**64 - 1, bytes(KEM_PK), KEM_PK)), '0xdea39530ca31145e34cb14a02a34952227ee39703d12cbeb2428539002c7dd31')  # pins the 8-byte version word

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
                    self.assertEqual(out32(L.pqz_key_record_digest, bytes(g.pqz_key_digest), bytes(g.pqz_pop_hash)), bytes(g.record_digest))
                    self.assertEqual(bool(g.has_member_digest), kind == 0x0120)
                    self.assertEqual(mh(g), r.get('memberDigest', ''))
                    if kind == 0x0120:
                        msig_runs += 1
                        self.assertEqual(bytes(g.member_digest), out32(L.member_digest, ua, bytes(g.message)))
                # write-once: a key already set refuses
                self.assertEqual(code_of(lambda: key_record(kind, ua, kdat, key, b'', hash_, True)), 'UAPqzKeySet')
                n += 1
        self.assertEqual((n, msig_runs), (8, 8))  # 4 msig rows, each with the proof bytes and hash-only

    def test_personal_sign_portable_purposes(self):
        def portable(tag):
            o = bl()
            ok(L.is_portable_purpose(tag, C.byref(o)))
            return o.value
        pop2, kem, pqz = out32(L.purpose_tag_v, b'pop', 2), out32(L.purpose_tag, b'kem'), out32(L.purpose_tag, b'pqz-key')
        self.assertEqual([portable(pop2), portable(kem), portable(pqz)], [True] * 3)
        self.assertFalse(portable(out32(L.purpose_tag, b'metatx')) or portable(out32(L.purpose_tag, b'pop')))
        md = b(next(x for x in PV['registrations'] if x['name'] == 'msig-pq-native')['memberDigest'])
        # known answer from the JS reference (clientkeys ua.js); the prefix is 0x19 + "Ethereum Signed Message:\n32" (28 bytes)
        self.assertEqual(hx(md), '0x606d9a70c70d39e5d8d079c3ae31eefa6db574219dab56d6c776cb6731e61a7c')
        self.assertEqual(hx(out32(L.personal_sign_digest, md)), '0xe5d24987e9b4e710063a5432d6215eaead64d8dc073f7561726d21644d54c3d8')
        n = next(x for x in PV['negatives'] if x['name'] == 'native-personal-sign-under-metatx')
        self.assertFalse(portable(b(n['mutation']['set']['purposeTag'])))

    def test_holder_refusals(self):
        regs = PV['registrations']
        run = sig_level = 0
        for n in PV['negatives']:
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
            elif n['entry'] == 'setKemKey' and n['name'] == 'kem-record-of-other-ua':
                # the record of one UA offered for another: the signed message differs, so the signature cannot verify
                k = next(x for x in PV['kemRecords'] if x['id'] == m['row'])
                t = next(x for x in regs if x['ua'] == s['ua'])
                pk = b(k['kemPk'])
                msg = out32(L.kem_record_message, t['kind'], b(s['ua']), int(k['version']), pk, len(pk))
                self.assertNotEqual(k['message'], hx(msg))
                run += 1
            else:
                sig_level += 1  # signatures / native personal_sign: verified by the signature vectors
        self.assertEqual((run, sig_level), (56, 7))
        u, key, proof = bytes([1]) * 32, bytes(16384), bytes([7]) * 32
        # malformed msig key data is UAKeyData, not "not a holder"; an msig without key data is not a holder
        for kdat in (bytes([0, 2, 0]), bytes([0, 2, 0, 2, 9, 9])):
            self.assertEqual(code_of(lambda: holder(0x0120, u, kdat, key, b'', proof)), 'UAKeyData')
        for args, code in (((0x0120, u, b'', key, b'', proof), 'UAPqzHolder'),
                           ((0x0130, u, b'', key, b'', bytes(31)), 'UAPqzPopHash'),
                           ((0x0130, u, b'', bytes(100), b'', proof), 'UAKeyData'),
                           ((0x0130, u, b'', b'', b'', b'', 1, b''), 'UAKemKeyLength'),
                           ((0x0101, u, b'', b'', b'', b'', 1, bytes(KEM_PK)), 'UAKemHolder')):
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
            'holder_pop_message pqz_pop_hash NULL len 32': L.holder_pop_message(0x0130, bytes(32), b'', 0, b'', 0, b'', 0, None, 32, 0, b'', 0, C.byref(HolderPop())),
            'pqz_key_record_message out NULL': L.pqz_key_record_message(0x0130, bytes(32), b'', 0, bytes(16384), 16384, b'', 0, bytes([7]) * 32, 32, False, None),
            'portable_pop_digest ua NULL': L.portable_pop_digest(None, bytes(32), bytes(32), o),
            'holder_pop_message out NULL': L.holder_pop_message(0x0130, bytes(32), b'', 0, b'', 0, b'', 0, b'', 0, 0, b'', 0, None),
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


if __name__ == '__main__':
    unittest.main()
