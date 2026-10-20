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

OK, ERR_KEY_DATA, ERR_ARGUMENT, ERR_BUFFER = 0, 1, 8, 9


class Kind(C.Structure):
    _fields_ = [('kind', C.c_uint16), ('native', C.c_bool), ('lengths_len', C.c_uint8), ('lengths', C.c_uint32 * 2),
                ('name', C.c_char_p), ('group', C.c_char_p)]


class Member(C.Structure):
    _fields_ = [('kind', C.c_uint16), ('id', C.c_uint8 * 32), ('weight', C.c_uint16)]


P, u8, u16, u32, u64, sz, bl, st = C.c_void_p, C.c_char_p, C.c_uint16, C.c_uint32, C.c_uint64, C.c_size_t, C.c_bool, C.c_int32
L = types.SimpleNamespace()  # L.tag is scaas_ua_tag
for name, res, args in [
    ('abi_version', u32, []), ('status_name', C.c_char_p, [st]), ('last_error', C.c_char_p, []),
    ('kind_count', sz, []), ('kind_at', st, [sz, P]), ('kind_info', st, [u16, P]),
    ('is_native', bl, [u16]), ('is_zether', bl, [u16]), ('is_pqz_holder', bl, [u16]), ('is_signing', bl, [u16]), ('is_member', bl, [u16, bl]),
    ('tag', st, [u16, P]), ('kind_tag_string', st, [u16, P, P]), ('group_tag', st, [u8, P, P]),
    ('group_tag_string', st, [u8, P, P, P]), ('msg_tag', st, [P]), ('purpose_tag', st, [u8, P]),
    ('ua_of', st, [u16, u8, sz, P]), ('derive_ua', st, [u16, u8, sz, bl, P]), ('native_id', st, [u16, u8, sz, P]),
    ('key_hash_of', st, [u16, u8, sz, P, P]), ('validate_key_data', st, [u16, u8, sz, bl]),
    ('in_native_space', st, [u8, P]), ('ua_message', st, [u16, u8, u8, P]), ('chain_key_hash', st, [u64, P]),
    ('pop_digest', st, [u64, u8, u8, u8, u8, P]), ('msig_pqz_eligible', st, [u8, sz, P]),
    ('holder_pop_message', st, [u16, u64, u8, u8, u8, u8, sz, P, P, P]), ('pqz_reg_message', st, [u64, u8, u8, u8, u8, sz, P]), ('ua_auth_domain_separator', st, [u32, u64, u8, u8, P]),
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


class Vectors(unittest.TestCase):
    def test_table_groups_purposes_constants(self):
        self.assertEqual(L.abi_version(), 1)
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
        self.assertEqual(len(K['purposes']), 12)
        for r in K['purposes']:
            self.assertEqual(hx(out32(L.purpose_tag, r['purpose'].encode())), r['purposeTag'], r['purpose'])
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
                p = out32(L.purpose_tag, r['purpose'].encode())
                self.assertEqual(hx(p), r['purposeTag'])
                self.assertEqual(hx(out32(L.ua_message, r['kind'], p, b(r['digest']))), r['uaMsg'])

    def test_structures(self):
        for p in S['pop']:
            with self.subTest('pop', ua=p['ua']):
                c = S['contexts'][p['context']]
                self.assertEqual(hx(out32(L.chain_key_hash, c['chainId'])), p['chainKeyHash'])  # context E is 2^40+7
                d = out32(L.pop_digest, c['chainId'], b(c['chainUid']), b(c['registry']), b(p['ua']), b(p['pqzKeyHash']))
                self.assertEqual(hx(d), p['popDigest'])
        pk = b(K['pqzKey'])
        for p in S['pqzReg']:
            c = S['contexts'][p['context']]
            args = (c['chainId'], b(c['chainUid']), b(c['registry']), b(p['ua']))
            h, d, m = C.create_string_buffer(32), C.create_string_buffer(32), C.create_string_buffer(32)
            ok(L.holder_pop_message(p['kind'], *args, pk, len(pk), h, d, m))
            self.assertEqual((hx(h.raw), hx(d.raw)), (p['pqzKeyHash'], p['popDigest']))
            self.assertEqual(hx(out32(L.pqz_reg_message, *args, pk, len(pk))), p['pqzRegMessage'])
            for bad in (0x0101, 0x0133):
                self.assertEqual(code_of(lambda: ok(L.holder_pop_message(bad, *args, pk, len(pk), h, d, m))), 'UAPqzHolder')
            ok(L.holder_pop_message(p['kind'], *args, None, 0, h, d, m))  # no key: hash 0
            self.assertEqual(h.raw, bytes(32))
        for p in S['pqzMsig']:
            e = bl()
            ok(L.msig_pqz_eligible(b(p['keyData']), len(b(p['keyData'])), C.byref(e)))
            self.assertEqual(e.value, p['eligible'], p['reason'])
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


class Abi(unittest.TestCase):
    def test_layout(self):
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
            'pop_digest registry NULL': L.pop_digest(1, bytes(32), None, bytes(32), bytes(32), o),
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
