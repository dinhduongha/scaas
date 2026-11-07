# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas_ua.wallet (libscaas_ua_c, C ABI v6, ctypes) against smartcontracts/vectors/ua/{keys,sign,kem,seal,vault,zether}.json,
clients/zether-prover/vectors/ and the PQZ facade; the load check, handle freeing and secret wiping of the binding itself.
Needs the library: cargo build --release in clients/ua-c (or SCAAS_UA_C_LIB). From clients/ua-py:
python3 -m unittest tests.test_wallet"""
import hashlib
import hmac
import json
import pathlib
import threading
import unittest

import scaas_ua as ua
from scaas_ua import wallet as W

ROOT = pathlib.Path(__file__).resolve().parents[3]
VEC = ROOT / 'smartcontracts' / 'vectors' / 'ua'
ZV = ROOT / 'clients' / 'zether-prover' / 'vectors'
KEYS, SIGN, KEMV, SEAL, VAULT, ZJ = (json.loads((VEC / f).read_text()) for f in
                                     ('keys.json', 'sign.json', 'kem.json', 'seal.json', 'vault.json', 'zether.json'))
R33 = json.loads((ZV / 'r33_keys.json').read_text())
STATE = ROOT / 'smartcontracts' / 'vectors'
MN = {m['id']: m for m in KEYS['mnemonics']}
DETERMINISTIC = {0x0101, 0x0102, 0x0106, 0x0107, 0x0108}  # RFC 6979, ed25519, BLS: byte-equal in a release build
FALCON = (0x0132, 0x0135)
PQZL_ID = {'n2048-kmax1024': 'c752e7f57778114dbfaac5d43843577b54e13e3ed162517145a37b5a3ec6cdfe',
           'n2304-kmax4096': 'ef1ffbcbd05394f8276e50a6c254022edf53bbd08a56e22aadddac2b9b90336e'}


def b(h):
    return bytes.fromhex(h[2:] if h.startswith('0x') else h)


def hx(x):
    return '0x' + bytes(x).hex()


def code(f):
    """The status name a call raises, '' if it returns."""
    try:
        f()
    except W.WalletError as e:
        return e.code
    return ''


def commands(name):
    """scaas-ua `facade::<name>::COMMANDS` read from its source (T15g): (the release commands, the `vectors`-only raw forms).
    A test asserts that a command is in it, never that it equals a list (spec no-decryption-oracle §4.13)."""
    src = (ROOT / 'clients' / 'ua-rs' / 'src' / 'facade' / f'{name}.rs').read_text()
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


def abi_word(x):
    return x.to_bytes(32, 'big')


def abi_bytes(x):
    return abi_word(len(x)) + x + bytes(-len(x) % 32)


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


def secret(s):
    return bytearray(s.encode())


class Case(unittest.TestCase):
    wallets = {}

    @classmethod
    def tearDownClass(cls):
        for w in cls.wallets.values():
            w.close()
        cls.wallets.clear()

    def w(self, mid):
        if mid not in self.wallets:
            m = MN[mid]
            self.wallets[mid] = W.Wallet.from_mnemonic(secret(m['words']), secret(m['passphrase']))
        return self.wallets[mid]

    def new_wallet(self, mid):
        m = MN[mid]
        w = W.Wallet.from_mnemonic(secret(m['words']), secret(m['passphrase']))
        self.addCleanup(w.close)
        return w

    def keep(self, h):
        self.addCleanup(h.close)
        return h

    def key(self, mid, kind, account=0, index=0, w=None):
        return self.keep((w or self.w(mid)).ua_key(kind, account, index))

    def native(self, mid, net='evm', index=0, coin=None):
        return self.keep(self.w(mid).native_key(net, index, coin))

    def kem(self, r, w=None):
        return self.keep(self.key(r.get('mnemonic', 'pq_kat'), r['kind'], r['account'], r['index'], w=w).kem_key(int(r['version'])))


class Load(unittest.TestCase):
    def test_load_refuses_wrong_abi_or_features(self):
        lib = W.load()
        try:
            W._abi_hook = lambda v: 5
            with self.assertRaises(W.LibraryMismatch):
                W.load(W._default_path())
        finally:
            W._abi_hook = None
        self.assertIs(W._lib, lib, 'a refused library is not kept')
        f = W.FEATURE
        good = f['wallet'] | f['pq'] | f['pqz'] | f['pqz-set-n2304-kmax4096']
        W.check_build(6, good)
        W.check_build(6, f['wallet'] | f['pq'])
        for label, abi, feats in [('abi 5', 5, good), ('abi 7', 7, good), ('no wallet', 6, good & ~f['wallet']),
                                  ('no pq', 6, good & ~f['pq']), ('an unknown bit', 6, good | 1 << 12),
                                  ('a vectors build (C1)', 6, good | f['vectors']),
                                  ('two sets', 6, good | f['pqz-set-n2048-kmax1024']), ('pqz without a set', 6, f['wallet'] | f['pq'] | f['pqz']),
                                  ('a set without pqz', 6, f['wallet'] | f['pq'] | f['pqz-set-n2304-kmax4096'])]:
            with self.subTest(label), self.assertRaises(W.LibraryMismatch):
                W.check_build(abi, feats)

    def test_abi_version_is_6_and_features_bits(self):
        self.assertEqual(W.abi_version(), 6)
        f = W.features()
        self.assertTrue(f & W.FEATURE['wallet'] and f & W.FEATURE['pq'])
        self.assertFalse(f & W.FEATURE['external'], 'MD-13: no external key in this round')
        self.assertEqual(code(lambda: W.external_key_new({'kind': 0x0101, 'keyData': '0x'})), 'UAKindUnavailable')
        self.assertEqual(W.status_name(40), 'UAPqzSetMismatch')


class Handles(unittest.TestCase):
    def test_handle_freed_exactly_once(self):
        freed = []
        h = W._Handle(1234, freed.append)
        h.close()
        h.close()
        with h:
            pass
        del h
        self.assertEqual(freed, [1234])
        with W._Handle(99, freed.append):
            pass
        self.assertEqual(freed, [1234, 99])

    def test_use_after_close_never_reaches_the_library(self):
        w = W.Wallet.from_mnemonic(secret(MN['pq_kat']['words']))
        k = w.ua_key(0x0102)
        k.close()
        w.close()
        with self.assertRaises(ValueError):
            k.key_data()
        with self.assertRaises(ValueError):
            w.ua_key(0x0102)

    def test_close_waits_for_a_call_in_flight(self):
        freed = []
        h = W._Handle(7, freed.append)
        h._acquire()
        t = threading.Thread(target=h.close)
        t.start()
        t.join(0.2)
        self.assertTrue(t.is_alive() and not freed, 'close waits')
        h._release()
        t.join()
        self.assertEqual(freed, [7])


class Secrets(Case):
    def test_secret_buffer_wiped_after_call(self):
        """Each call that carries a secret allocates its buffers through the hook, and every one is zero after the call."""
        seen = []
        real = W._secret_buf

        def rec(n):
            buf = real(n)
            seen.append(buf)
            return buf

        def through(label, f):
            n = len(seen)
            out = f()
            with self.subTest(label):
                self.assertGreater(len(seen), n, 'no secret buffer')
                for buf in seen[n:]:
                    self.assertEqual(buf.raw, bytes(len(buf.raw)), 'not wiped')
            return out

        W._secret_buf = rec
        outs = []
        try:
            m = MN['pq_kat']
            w = self.keep(through('from_mnemonic', lambda: W.Wallet.from_mnemonic(secret(m['words']), secret(m['passphrase']))))
            v = through('seal_vault', lambda: w.seal_vault(secret('correct horse 9')))
            self.keep(through('open_vault', lambda: W.Wallet.open_vault(v, secret('correct horse 9'))))
            self.keep(through('import_native_key', lambda: w.import_native_key('evm', bytearray(range(1, 33)))))
            outs.append(through('export_pqz_leaf_raw', lambda: w.export_pqz_leaf_raw(0, 0)))
            kk = self.kem(KEMV['keys'][0], w=w)
            ct, e, ss = through('kem_encaps', lambda: W.kem_encaps(b(KEMV['keys'][0]['kemPk'])))
            outs += [ss, through('decaps', lambda: kk.decaps(ct, e))]
            mct, eph, c = through('seal', lambda: W.seal(kk.kem_pk(), 'test/p', b'aad', bytearray(b'plain secret')))
            outs.append(through('open', lambda: kk.open('test/p', b'aad', mct, eph, c)))
            r = SEAL['containers'][0]
            ok_ = self.kem(r['opener']['kem'])
            outs.append(through('open_container', lambda: ok_.open_container(r['container'], r['expect'], r.get('members'), r.get('accepted'))))
            sealed = through('aead_seal', lambda: W.aead_seal(1, bytearray(range(32)), bytes(12), b'', bytearray(b'data')))
            outs.append(through('aead_open', lambda: W.aead_open(1, bytearray(range(32)), bytes(12), b'', sealed)))
            outs.append(through('hkdf', lambda: W.hkdf_sha256(bytearray(b'ikm'), b'', b'', 32)))
            through('hmac', lambda: W.hmac_sha256(bytearray(b'key'), b'data'))
            zk = self.keep(w.zether_key(60, 0, 7))
            zb = through('zether seal cache', lambda: zk.seal_balance_cache(bytearray(b'{"b":1}')))
            outs.append(through('zether open cache', lambda: zk.open_balance_cache(zb)))
            qk = self.keep(w.pqz_key(0, 0))
            qb = through('pqz seal cache', lambda: qk.seal_balance_cache(bytearray(b'{"b":2}')))
            outs.append(through('pqz open cache', lambda: qk.open_balance_cache(qb)))
            v2 = through('rewrap', lambda: W.vault_rewrap_pin(v, secret('correct horse 9'), secret('battery staple 7')))
            through('enable_prf', lambda: W.vault_enable_prf(v2, secret('battery staple 7'), bytearray(range(32)), 'c', b's'))
            through('seal_label_vault', lambda: w.seal_label_vault('native-import:evm:0', secret('correct horse 9')))
            g, sb = W.Wallet.generate()
            self.keep(g)
            self.keep(sb)
            words = through('reveal', sb.reveal)
            outs.append(words)
            pos = sb.challenge()
            ws = bytes(words).split()
            self.assertTrue(through('verify', lambda: sb.verify([bytearray(ws[i - 1]) for i in pos])))
            outs.append(through('take', sb.take))
        finally:
            W._secret_buf = real
        for o in outs:
            self.assertIsInstance(o, bytearray)
            self.assertTrue(any(o))
            W.wipe(o)
            self.assertFalse(any(o))

    def test_a_str_secret_is_refused(self):
        with self.assertRaises(TypeError):
            W.Wallet.from_mnemonic(MN['pq_kat']['words'])
        self.assertEqual(code(lambda: self.w('pq_kat').unlock('{}', None, bytes(31))), 'UAKeyData', 'a PRF secret is 32 bytes')
        self.assertEqual(code(lambda: self.key('pq_kat', 0x0101).sign_ua(bytes(31), bytes(32))), 'UAKeyData', 'never an over-read')


class Keys(Case):
    def test_keys_json_ua_rows(self):
        falcon = W.features() & W.FEATURE['falcon']
        n = 0
        for r in KEYS['ua']:
            if r['kind'] in FALCON and not falcon:
                continue
            with self.subTest(r['name'], account=r['account'], index=r['index']):
                kd = self.key(r['mnemonic'], r['kind'], r['account'], r['index']).key_data()
                self.assertEqual(hx(kd), r['keyData'])
                if r['ua'] is not None:  # a MuSig2 participant key has no UA of its own
                    self.assertEqual(hx(ua.derive_ua(r['kind'], kd)), r['ua'], 'the own port agrees')
                n += 1
        self.assertGreaterEqual(n, 184)

    def test_keys_json_native_rows(self):
        for r in KEYS['native']:
            with self.subTest(r['network'], index=r['index'], coin=r['coinType']):
                self.assertEqual(hx(self.native(r['mnemonic'], r['network'], r['index'], r['coinType']).key_data()), '0x' + r['publicKey'].removeprefix('0x'))

    def test_keys_json_refusals(self):
        for r in KEYS['refusals']:
            with self.subTest(r['reason']):
                w = self.w(r['mnemonic'])
                f = (lambda: w.ua_key(r['kind'], r['account'], r['index'])) if r['what'] == 'ua' else \
                    (lambda: w.native_key(r['network'], r['index'], r['coinType']))
                self.assertEqual(code(f), 'UA' + r['error'])


class Sign(Case):
    def test_sign_json_ua_rows(self):
        falcon = W.features() & W.FEATURE['falcon']
        exact = 0
        for r in SIGN['ua']:
            if r['kind'] in FALCON and not falcon:
                continue
            with self.subTest(r['name'], purpose=r['purpose']):
                sig = self.key(r['mnemonic'], r['kind'], r['account'], r['index']).sign_ua(b(r['purposeTag']), b(r['digest']))
                if r['kind'] in DETERMINISTIC:
                    self.assertEqual(hx(sig), r['signature'])
                    exact += 1
                elif r['kind'] not in FALCON:
                    self.assertEqual(len(sig), len(b(r['signature'])))
        self.assertGreaterEqual(exact, 10)

    def test_sign_json_member_rows(self):
        for r in SIGN['member']:
            with self.subTest(r['name']):
                sig = self.key(r['mnemonic'], r['kind'], r['account'], r['index']).sign_member(b(r['structureUa']), b(r['structureUaMsg']))
                self.assertEqual(hx(sig) if r['kind'] in DETERMINISTIC else len(sig),
                                 r['signature'] if r['kind'] in DETERMINISTIC else len(b(r['signature'])))

    def test_sign_json_policy_rows(self):
        k = self.native('pq_kat')
        signed = refused = 0
        for r in SIGN['policy']:
            with self.subTest(r['id']):
                if 'refused' in r:
                    self.assertEqual(code(lambda: k.sign_typed(r['td'], r['expect'])), 'UAPolicyRefused')
                    refused += 1
                else:
                    self.assertEqual(k.sign_typed(r['td'], r['expect']), k.sign_digest_raw(b(r['digest'])))
                    signed += 1
        self.assertEqual((signed, refused), (10, 14))

    def test_sign_json_typed_any(self):
        k = self.native('pq_kat')
        for r in SIGN['typed']['generic']:
            with self.subTest(r['id']):
                self.assertEqual(k.sign_typed_any(r['td']), k.sign_digest_raw(b(r['digest'])))
        for r in SIGN['typed']['refusals']:
            with self.subTest(r['id']):
                self.assertEqual(code(lambda: k.sign_typed_any(r['td'])), 'UAArgument')

    def test_sign_json_tx_rows(self):
        for r in SIGN['tx']['rows']:
            with self.subTest(r['tx']['type']):
                s = r['signer']
                self.assertEqual(hx(self.native(s['mnemonic'], s['network'], s['index']).sign_transaction(r['tx'])), r['raw'])
        k = self.native('pq_kat')
        for r in SIGN['tx']['refusals']:
            with self.subTest(r['id']):
                self.assertEqual(code(lambda: k.sign_transaction(r['tx'])), 'UAArgument')

    def test_sign_json_webauthn(self):
        for r in SIGN['webauthn']['accepted']:
            ch = W.webauthn_challenge(b(r['purposeTag']), b(r['digest']))
            self.assertEqual(ch, b(r['expectedChallenge']))
            self.assertEqual(ch, ua.ua_message(0x0100, b(r['purposeTag']), b(r['digest'])), 'the own port agrees')
        rows = [(r, None) for r in SIGN['webauthn']['accepted']] + [(r, r['error']) for r in SIGN['webauthn']['refusals']]
        for r, err in rows:
            with self.subTest(r.get('case', 'accepted')):
                f = lambda: W.webauthn_assertion(b(r['keyData']), b(r['expectedChallenge']), b(r['authData']), b(r['clientDataJSON']),
                                                 b(r['r']), b(r['s']))
                if err:
                    self.assertEqual(code(f), 'UA' + err)
                else:
                    self.assertEqual(f(), b(r['assertion']))

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
                req = {'purpose': r['purposeTag'], 'digest': r['digest'], 'msig': m}
                if 'refused' in r:
                    self.assertEqual(code(lambda: W.uasig(req, keys)), r['refused'])
                    refused += 1
                else:
                    sig = json.loads(W.uasig(req, keys))
                    self.assertEqual((sig['keyData'], sig['signature']), ('0x', '0x'))
                    self.assertEqual(hx(member_sigs(sig['members'])), r['memberSigs'])
                    built += 1
        self.assertEqual((built, refused), (3, 4))

    def test_uasig_single_key_is_sign_ua(self):
        r = next(x for x in SIGN['ua'] if x['kind'] == 0x0101)
        k = self.key(r['mnemonic'], r['kind'])
        got = json.loads(W.uasig({'purpose': r['purposeTag'], 'digest': r['digest'], 'key': 0}, [k]))
        self.assertEqual(got, {'keyData': r['keyData'], 'signature': r['signature'], 'members': []})

    def test_raw_digest_and_key_proof(self):
        self.assertEqual(code(lambda: self.key('pq_kat', 0x0108).sign_digest_raw(bytes(32))), 'UARawDigestRefused')
        n = self.native('pq_kat')
        self.assertEqual(len(n.sign_digest_raw(bytes(32))), 65)
        self.assertEqual(len(n.sign_key_proof(b'challenge')), 65)
        self.assertEqual(code(lambda: self.key('pq_kat', 0x0101).sign_key_proof(b'challenge')), 'UAArgument')


class Kem(Case):
    def test_kem_json_keys(self):
        for r in KEMV['keys']:
            with self.subTest(kind=r['kind'], version=r['version']):
                self.assertEqual(hx(self.kem(r).kem_pk()), r['kemPk'])

    def test_kem_json_refusals(self):
        for r in KEMV['refusals']:
            if 'mnemonic' not in r or not isinstance(r['version'], int):
                continue  # the msig row: no wallet handle of 0x0120; 2^64: not a uint64
            with self.subTest(kind=r['kind']):
                k = self.key(r['mnemonic'], r['kind'], r['account'], r['index'])
                self.assertEqual(code(lambda: k.kem_key(r['version'])), 'UA' + r['error'])

    def test_kem_json_encaps_refusals_and_round_trip(self):
        for r in KEMV['encapsRefusals']:
            with self.subTest(r['id']):
                self.assertEqual(code(lambda: W.kem_encaps(b(r['kemPk']))), 'UA' + r['error'])
        kk = self.kem(KEMV['keys'][0])
        ct, e, ss = W.kem_encaps(b(KEMV['keys'][0]['kemPk']))
        self.assertEqual(kk.decaps(ct, e), ss)

    def test_kem_json_decaps(self):
        for r in KEMV['decaps']:
            if len(b(r['x25519Eph'])) != 32:
                continue  # a 31-byte E: the binding refuses it before the library (test_a_str_secret_is_refused)
            with self.subTest(r['id']):
                kk = self.kem(r['key'])
                f = lambda: kk.decaps(b(r['mlkemCt']), b(r['x25519Eph']))
                if r.get('error'):
                    self.assertEqual(code(f), 'UA' + r['error'])
                else:
                    self.assertEqual(f(), b(r['ss']))

    def test_kem_ephemeral(self):
        self.assertEqual(self.keep(W.KemKey.ephemeral()).kem_pk()[0], 1)


class Seal(Case):
    def opener(self, r):
        return self.kem(r['opener']['kem'])

    def test_seal_json_seal_rows(self):
        for r in SEAL['seal']:
            if 'kind' not in r['recipient']:
                continue  # an ephemeral recipient from a fixed seed: under `vectors` only
            with self.subTest(r['id']):
                kk = self.kem(r['recipient'])
                pt = kk.open(r['purpose'], b(r['aad']), b(r['mlkemCt']), b(r['x25519Eph']), b(r['ciphertext']))
                self.assertEqual(pt, b(r['pt']))
                mct, e, ct = W.seal(b(r['kemPk']), r['purpose'], b(r['aad']), b(r['pt']))
                self.assertEqual((len(mct), len(ct)), (W.KEM_CT_LEN, len(b(r['pt'])) + 16))
                self.assertEqual(kk.open(r['purpose'], b(r['aad']), mct, e, ct), b(r['pt']))

    def test_seal_json_refusals(self):
        base = next(r for r in SEAL['seal'] if r['id'] == SEAL['refusals']['base'])
        n = W.KEM_CT_LEN
        for r in SEAL['refusals']['rows']:
            wire = b(r.get('wire', base['wire']))
            if wire[:2] != b'\x01\x01':
                continue  # version or scheme 2: the named fields carry neither
            with self.subTest(r['id']):
                kk = self.kem(r.get('key', SEAL['refusals']['key']))
                aad = b(r['aad']) if 'aad' in r else b(base['aad'])
                f = lambda: kk.open(r.get('purpose', base['purpose']), aad, wire[2:2 + n], wire[2 + n:2 + n + 32], wire[2 + n + 32:])
                self.assertEqual(code(f), 'UA' + r['error'])

    def test_seal_json_argument_refusals(self):
        pk = b(SEAL['seal'][0]['kemPk'])
        for r in SEAL['argumentRefusals']:
            with self.subTest(r['id']):
                self.assertEqual(code(lambda: W.seal(pk, r['purpose'], b'', bytes(r['ptLength']))), 'UA' + r['error'])

    def test_seal_json_containers(self):
        n = 0
        for r in SEAL['containers']:
            if 'session' in r['opener']:
                continue  # a link container opens only through its session
            with self.subTest(r['id']):
                self.assertEqual(self.opener(r).open_container(r['container'], r['expect'], r.get('members'), r.get('accepted')), b(r['pt']))
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
                    def f():
                        w = W.Wallet.restore_backup(kk, r['container'], r['expect'], r.get('members'), r.get('accepted'))
                        w.close()
                else:
                    f = lambda: kk.open_container(r['container'], r['expect'], r.get('members'), r.get('accepted'))
                self.assertEqual(code(f), 'UA' + r['error'] if r.get('error') else '')
                n += 1
        self.assertEqual(n, 28)

    def test_open_container_msig_without_accepted_json_is_ContainerSender(self):
        r = next(x for x in SEAL['containers'] if x.get('accepted'))
        kk = self.opener(r)
        self.assertEqual(code(lambda: kk.open_container(r['container'], r['expect'], r.get('members'))), 'UAContainerSender')
        self.assertEqual(kk.open_container(r['container'], r['expect'], r.get('members'), r['accepted']), b(r['pt']))

    def current(self, c):
        """A wallet holding `c.ua` at backup generation `c.generation`, or None."""
        if c is None:
            return None
        mid = next(m for m in ('twelve_words', 'pq_kat') if hx(ua.derive_ua(0x0102, self.key(m, 0x0102).key_data())) == c['ua'])
        w = self.new_wallet(mid)
        k = self.key(None, 0x0102, w=w)
        rk = self.key('pq_kat', 0x0130).key_data()
        rec = W.Recipient(0x0130, rk, 0, b(KEMV['keys'][0]['kemPk']))
        for _ in range(c['generation']):
            w.backup_seal(k, [rec])
        self.assertEqual(json.loads(w.manifest_json())['backupGeneration'], c['generation'])
        return w

    def test_seal_json_replay_backup_rows(self):
        n = 0
        for r in SEAL['replay']:
            if r['kind'] != 'backup':
                continue  # link windows: a session starts now in a release build
            with self.subTest(r['id']):
                fn = W.Wallet.restore_backup_rollback if r.get('allowRollback') else W.Wallet.restore_backup
                cur = self.current(r['current'])
                if r.get('error'):
                    self.assertEqual(code(lambda: fn(self.opener(r), r['container'], r['expect'], current=cur)), 'UA' + r['error'])
                else:
                    got = fn(self.opener(r), r['container'], r['expect'], current=cur)
                    self.assertEqual(got is not None, r['install'], 'an equal generation installs nothing')
                    if got:
                        got.close()
                n += 1
        self.assertEqual(n, 6)

    def test_backup_seal_restores_a_wallet(self):
        w = self.new_wallet('twelve_words')
        sender = self.key(None, 0x0102, w=w)
        self.key(None, 0x0101, 0, 1, w=w)
        rk, pk = self.key('pq_kat', 0x0130).key_data(), b(KEMV['keys'][0]['kemPk'])
        cs = json.loads(w.backup_seal(sender, [W.Recipient(0x0130, rk, 0, pk), W.Recipient(0, b'', 0, pk, True)]))
        self.assertEqual(len(cs), 2)
        expect = {'purpose': 'scaas/backup/v1', 'sender': {'ua': hx(ua.derive_ua(0x0102, sender.key_data()))},
                  'recipient': {'ua': hx(ua.derive_ua(0x0130, rk)), 'version': 0}}
        out = self.keep(W.Wallet.restore_backup(self.kem(KEMV['keys'][0]), cs[0], expect))
        self.assertEqual(self.key(None, 0x0102, w=out).key_data(), sender.key_data())
        m = json.loads(out.manifest_json())
        self.assertEqual((m['backupGeneration'], len(m['entries'])), (1, 2))
        self.assertEqual(code(lambda: w.backup_seal(self.native('pq_kat'), [W.Recipient(0, b'', 0, pk, True)])), 'UAArgument')
        self.assertEqual(code(lambda: w.backup_seal(sender, [])), 'UAArgument', 'no recipient')

    def test_link_session_is_consumed(self):
        s = self.keep(W.LinkSession.new())
        pk = s.kem_pk()
        self.assertRegex(s.short_code(), r'^[0-9]{8}$')
        r = next(x for x in SEAL['containers'] if 'session' in x['opener'])
        expect = dict(r['expect'], recipient={'kemPkHash': hx(ua.keccak256(pk))})
        self.assertEqual(code(lambda: W.Wallet.from_link(s, r['container'], expect)), 'UAContainerReplay')
        self.assertEqual(code(lambda: W.Wallet.from_link(s, r['container'], expect)), 'UAKeyRevoked')
        self.assertEqual(code(s.kem_pk), 'UAKeyRevoked')

    def test_link_seal_round_trip(self):
        w = self.new_wallet('twelve_words')
        key = self.key(None, 0x0102, w=w)
        self.keep(w.import_native_key('evm', bytearray(range(1, 33))))
        sender_ua = hx(ua.derive_ua(0x0102, key.key_data()))
        for wrong in (False, True):
            s = self.keep(W.LinkSession.new())
            pk, sc = s.kem_pk(), s.short_code()
            if wrong:
                sc = '00000000' if sc != '00000000' else '00000001'
            c = w.link_seal(key, pk, sc)
            expect = {'purpose': 'scaas/link/v1', 'sender': {'ua': sender_ua}, 'recipient': {'kemPkHash': hx(ua.keccak256(pk))}}
            if wrong:
                self.assertEqual(code(lambda: W.Wallet.from_link(s, c, expect)), 'UASealOpen')
                continue
            out = self.keep(W.Wallet.from_link(s, c, expect))
            self.assertEqual(self.key(None, 0x0102, w=out).key_data(), key.key_data())
            self.assertEqual(json.loads(out.manifest_json())['imports'], json.loads(w.manifest_json())['imports'])
        pk = self.keep(W.LinkSession.new()).kem_pk()
        self.assertEqual(code(lambda: w.link_seal(self.key('pq_kat', 0x0102), pk, '12345678')), 'UAArgument', "another wallet's key")
        self.assertEqual(code(lambda: w.link_seal(key, pk[:-1], '12345678')), 'UAKemCheck')


class Vault(Case):
    @staticmethod
    def unlock_of(u):
        return (secret(u['pin']) if 'pin' in u else None), (bytearray(b(u['prfOutput'])) if 'prfOutput' in u else None)

    def test_vault_json_vaults(self):
        by_entropy = {m['entropy']: m['id'] for m in KEYS['mnemonics'] if not m['passphrase']}
        for r in VAULT['vaults']:
            with self.subTest(r['id']):
                w = self.keep(W.Wallet.open_vault(r['vault'], *self.unlock_of(r['unlock'])))
                self.assertEqual(self.key(None, 0x0102, w=w).key_data(), self.key(by_entropy[r['plaintext']], 0x0102).key_data())

    def test_vault_json_refusals(self):
        for r in VAULT['refusals']:
            with self.subTest(r['id']):
                self.assertEqual(code(lambda: W.Wallet.open_vault(r['vault'], *self.unlock_of(r['unlock'])).close()), 'UA' + r['error'])

    def test_exactly_one_unlock_secret(self):
        r = next(x for x in VAULT['vaults'] if 'prfOutput' in x['unlock'])
        prf = bytearray(b(r['unlock']['prfOutput']))
        pin_row = VAULT['vaults'][0]
        self.assertEqual(code(lambda: W.Wallet.open_vault(r['vault'])), 'UAArgument', 'neither')
        self.keep(W.Wallet.open_vault(r['vault'], secret('not the passphrase'), prf))  # both: PRF first
        self.assertEqual(code(lambda: W.Wallet.open_vault(pin_row['vault'], None, prf)), 'UAArgument', 'no PRF envelope')

    def test_seal_vault_rewrap_enable_prf(self):
        w = self.w('twelve_words')
        v = w.seal_vault(secret('correct horse 9'))
        self.assertEqual(code(lambda: w.seal_vault(secret('12345678'))), 'UAArgument', 'the new-passphrase policy')
        self.assertFalse(W.vault_needs_rewrap(v))
        v2 = W.vault_rewrap_pin(v, secret('correct horse 9'), secret('battery staple 7'))
        v3 = W.vault_enable_prf(v2, secret('battery staple 7'), bytearray(range(32)), 'cred-1', b'salt')
        want = self.key('twelve_words', 0x0102).key_data()
        for vault, pin, prf in ((v, 'correct horse 9', None), (v2, 'battery staple 7', None), (v3, None, bytearray(range(32)))):
            w2 = self.keep(W.Wallet.open_vault(vault, pin and secret(pin), prf))
            self.assertEqual(self.key(None, 0x0102, w=w2).key_data(), want)
        self.assertEqual(code(lambda: W.Wallet.open_vault(v2, secret('correct horse 9'))), 'UAVaultOpen')


class Custody(Case):
    def test_lock_revokes_and_unlock_does_not_revive(self):
        w = self.new_wallet('twelve_words')
        v = w.seal_vault(secret('correct horse 9'))
        k = self.key(None, 0x0101, w=w)
        tag = ua.purpose_tag('metatx')
        before = k.sign_ua(tag, bytes(32))
        w.lock()
        self.assertEqual(code(lambda: k.sign_ua(tag, bytes(32))), 'UAKeyRevoked')
        self.assertEqual(code(lambda: w.ua_key(0x0101)), 'UAWalletLocked')
        mp = w.memory_protection()
        self.assertEqual((mp.chunks, mp.locked, mp.no_dump), (0, 0, 0))
        w.unlock(v, secret('correct horse 9'))
        self.assertEqual(code(lambda: k.sign_ua(tag, bytes(32))), 'UAKeyRevoked', 'unlock does not revive')
        self.assertEqual(self.key(None, 0x0101, w=w).sign_ua(tag, bytes(32)), before)

    def test_imported_key_after_unlock(self):
        w = self.new_wallet('twelve_words')
        seed_v = w.seal_vault(secret('correct horse 9'))
        k = self.keep(w.import_native_key('evm', bytearray(range(1, 33))))
        before = k.sign_digest_raw(bytes(range(32)))
        label_v = w.seal_label_vault('native-import:evm:0', secret('correct horse 9'))
        w.lock()
        self.assertEqual(code(lambda: w.imported_key('evm', 0)), 'UAWalletLocked')
        w.unlock(seed_v, secret('correct horse 9'))
        self.assertEqual(code(lambda: w.imported_key('evm', 0)), 'UAArgument', 'not held before its vault opens')
        self.assertEqual(code(lambda: w.open_label_vault(label_v, secret('wrong horse 9'))), 'UAVaultOpen')
        w.open_label_vault(label_v, secret('correct horse 9'))
        self.assertEqual(self.keep(w.imported_key('evm', 0)).sign_digest_raw(bytes(range(32))), before)
        self.assertEqual(code(lambda: w.imported_key('cosmos', 0)), 'UAArgument', 'CLI-SGN-11')

    def test_unlock_with_another_wallets_vault_is_WalletMismatch(self):
        w = self.new_wallet('twelve_words')
        self.key(None, 0x0102, w=w)
        other = self.w('pq_kat').seal_vault(secret('correct horse 9'))
        w.lock()
        self.assertEqual(code(lambda: w.unlock(other, secret('correct horse 9'))), 'UAWalletMismatch')

    def test_child_handle_after_wallet_free_is_KEY_REVOKED(self):
        w = W.Wallet.from_mnemonic(secret(MN['pq_kat']['words']))
        k = self.keep(w.ua_key(0x0130))
        kk = self.keep(k.kem_key(0))
        n = self.keep(w.native_key('evm'))
        w.close()
        self.assertEqual(code(lambda: k.sign_ua(ua.purpose_tag('metatx'), bytes(32))), 'UAKeyRevoked')
        self.assertEqual(code(lambda: n.sign_digest_raw(bytes(32))), 'UAKeyRevoked')
        self.assertEqual(code(lambda: kk.decaps(bytes(W.KEM_CT_LEN), bytes(range(1, 33)))), 'UAKeyRevoked')
        self.assertEqual(len(k.key_data()), 1312, 'public data stays readable')

    def test_memory_protection(self):
        w = self.new_wallet('pq_kat')
        self.key(None, 0x0102, w=w)
        mp = w.memory_protection()
        self.assertGreaterEqual(mp.chunks, 1)
        if W.features() & W.FEATURE['mlock']:
            self.assertEqual(mp.no_dump, mp.chunks)

    def test_seed_backup_sequence(self):
        w, sb = W.Wallet.generate()
        self.keep(w)
        self.keep(sb)
        words = sb.reveal()
        ws = bytes(words).split()
        self.assertEqual(len(ws), 24)
        self.assertEqual(code(sb.reveal), 'UAArgument', 'shown once')
        pos = sb.challenge()
        self.assertTrue(1 <= pos[0] < pos[1] < pos[2] <= 24)
        self.assertIsNone(sb.take(), 'not before the words are confirmed')
        self.assertFalse(sb.verify([bytearray(b'x'), bytearray(b'y'), bytearray(b'z')]))
        pos = sb.challenge()
        self.assertTrue(sb.verify([bytearray(ws[i - 1]) for i in pos]))
        self.assertEqual(len(sb.take()), 32)
        self.assertIsNone(sb.take(), 'handed out once')
        w2 = self.keep(W.Wallet.from_mnemonic(words))
        self.assertEqual(self.key(None, 0x0102, w=w2).key_data(), self.key(None, 0x0102, w=w).key_data())

    def test_import_manifest_discover(self):
        w = self.new_wallet('pq_kat')
        self.assertEqual(len(self.keep(w.import_native_key('evm', bytearray(range(1, 33)))).key_data()), 33)
        self.assertEqual(code(lambda: w.import_native_key('evm', bytearray(31))), 'UAArgument')
        self.assertEqual(json.loads(w.manifest_json())['imports'], [{'network': 'evm', 'n': 0}])
        got = json.loads(w.discover_candidates(0x0102, 0, 3))
        row = next(r for r in KEYS['ua'] if r['mnemonic'] == 'pq_kat' and r['kind'] == 0x0102 and r['account'] == 0 and r['index'] == 0)
        self.assertEqual(([x['index'] for x in got], got[0]['ua']), ([0, 1, 2], row['ua']))


class Errors(Case):
    def test_error_strings_never_contain_an_input(self):
        secrets = [b'zebrasecretword', b'Pa55-word-Secret', b'SECRETvalue0xdead', b'deadbeefcafe1234']
        w = self.w('pq_kat')
        evm, kk = self.native('pq_kat'), self.kem(KEMV['keys'][0])
        qk, zk = self.keep(w.pqz_key(0, 0)), self.keep(w.zether_key(60, 0, 7))
        words = ' '.join(MN['pq_kat']['words'].split()[:23] + ['zebrasecretword'])
        td = {'types': {'EIP712Domain': []}, 'primaryType': 'SECRETvalue0xdead', 'domain': {}, 'message': {'v': 'SECRETvalue0xdead'}}
        calls = [
            lambda: W.Wallet.from_mnemonic(secret(words), secret('Pa55-word-Secret')),
            lambda: W.Wallet.open_vault(VAULT['vaults'][0]['vault'], secret('Pa55-word-Secret'), None, secret('zebrasecretword')),
            lambda: evm.sign_typed(td, {'check': 'Payment', 'account': '0xdeadbeefcafe1234', 'payee': 'Pa55-word-Secret'}),
            lambda: evm.sign_transaction({'type': 2, 'chainId': 'SECRETvalue0xdead'}),
            lambda: kk.open_container('{"v":"Pa55-word-Secret"}', {'purpose': 'zebrasecretword'}),
            lambda: qk.call('zebrasecretword', {}),
            lambda: qk.call('dec', {'ct': '0xdeadbeefcafe1234', 'window': 'SECRETvalue0xdead'}),
            lambda: zk.call('proveTransfer', {'key': {'mnemonic': 'zebrasecretword Pa55-word-Secret'}}),
            lambda: W.vault_rewrap_pin(VAULT['vaults'][0]['vault'], secret('Pa55-word-Secret'), secret('zebrasecretword')),
        ]
        for i, call in enumerate(calls):
            with self.subTest(i):
                with self.assertRaises(W.WalletError) as cm:
                    call()
                text = str(cm.exception).encode()
                for sec in secrets:
                    for j in range(len(sec) - 5):
                        self.assertNotIn(sec[j:j + 6], text, (sec, text))


class Crypto(unittest.TestCase):
    def test_aead_hkdf_hmac(self):
        self.assertEqual(W.hmac_sha256(bytearray(b'\x0b' * 20), b'Hi There').hex(),
                         'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7')  # RFC 4231 case 1
        self.assertEqual(bytes(W.hkdf_sha256(bytearray(b'\x0b' * 22), bytes(range(13)), bytes(range(0xf0, 0xfa)), 42)).hex(),
                         '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865')  # RFC 5869 A.1
        key, nonce = bytearray(range(32)), bytes(12)
        for alg in (W.AEAD_AES256_GCM, W.AEAD_AES256_GCM_SIV):
            ct = W.aead_seal(alg, key, nonce, b'aad', bytearray(b'plaintext'))
            self.assertEqual(W.aead_open(alg, key, nonce, b'aad', ct), b'plaintext')
            self.assertEqual(code(lambda: W.aead_open(alg, key, nonce, b'aad', ct[:-1] + bytes([ct[-1] ^ 1]))), 'UAAead')
        self.assertEqual(code(lambda: W.aead_seal(3, key, nonce, b'', bytearray(b'x'))), 'UAArgument')


class Zether(Case):
    def zw(self):
        w = self.keep(W.Wallet.from_mnemonic(secret(R33['mnemonic'])))
        return w

    def request(self, f):
        r = json.loads((ZV / f).read_text())['request']
        r.pop('key')
        r.pop('includeWitness')
        return r

    def test_r33_keys(self):
        w = self.zw()
        for r in R33['bls12381']['keys']:
            _, _, coin, account, use = r['path'].split('/')
            y, u = self.keep(w.zether_key(int(coin), int(account), int(use))).public()
            self.assertEqual((hx(y), hx(u)), (r['Y'], r['UA']), r['path'])
        self.assertEqual(code(lambda: w.zether_key(60, 0, 9)), 'UAArgument')

    def test_pop_prove_and_key_field(self):
        k = self.keep(self.zw().zether_key(60, 0, 7))
        pop = json.loads(k.call('pop', {'curve': 'bls12381'}))
        r = R33['bls12381']['keys'][0]['pop']
        self.assertEqual({f: pop[f] for f in ('popDigest', 'registrationDigest', 'uaMsg')},
                         {f: r[f] for f in ('popDigest', 'registrationDigest', 'uaMsg')})
        t = self.request('transfer_bls12381.json')
        # ARCH-POS-13 (T15c, T14b): no command of a release build decrypts a caller's ciphertext (the words commands: below)
        self.assertEqual(code(lambda: k.call('checkBalance', {'acc': t['acc'], 'balance': t['balance']})), 'UAArgument')
        self.assertEqual(code(lambda: k.call('proveTransfer', t)), 'UAArgument')
        self.assertEqual(code(lambda: k.call('pop', {'key': {'seed': '0x' + '11' * 64}})), 'UAArgument')
        self.assertEqual(code(lambda: k.call('proveTransfer', dict(t, includeWitness=True))), 'UAArgument')

    def test_words_commands_on_the_forge_rows(self):
        """T15g (ARCH-POS-13): the words commands on the forge rows (smartcontracts/vectors/zether/state.json; the holders are
        r33_keys.json's): each in COMMANDS, the balances the contract's; another holder's words refused before the key (ua-rs
        tests/facade_zether_state.rs counts the key's uses); every `vectors`-only raw form refused by the release library."""
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
        alice, bob = self.keep(w.zether_key(60, 0, 7)), self.keep(w.zether_key(60, 1, 7))
        self.assertEqual(json.loads(alice.call('balance', words('alice')))['amount'], str(row['alice']['balance']))
        self.assertEqual(json.loads(bob.call('pendingBalance', words('bob')))['amount'], str(row['bob']['pending']))
        self.assertEqual(code(lambda: bob.call('balance', words('alice'))), 'UAArgument', "another holder's words")
        for c in raw:
            self.assertEqual(code(lambda: alice.call(c, {})), 'UAArgument', c)

    def test_cache_box_rows(self):
        for r in ZJ['cacheBox']:
            k = self.keep(self.new_wallet(r['mnemonic']).zether_key(r['coin'], r['account'], r['use']))
            self.assertEqual(tuple(map(hx, k.public())), (r['Y'], r['UA']))
            pt = k.open_balance_cache(r['box'])
            self.assertEqual(hx(pt), r['plaintext'], r['id'])
            self.assertEqual(k.open_balance_cache(k.seal_balance_cache(pt)), pt, r['id'] + ': round trip')
        for r in ZJ['cacheRefusals']:
            k = self.keep(self.new_wallet(r['mnemonic']).zether_key(r['coin'], r['account'], r['use']))
            self.assertEqual(code(lambda: k.open_balance_cache(r['box'])), 'UAAead', r['id'])

    def test_zether_handle_after_lock_is_KEY_REVOKED(self):
        w = self.zw()
        k = self.keep(w.zether_key(60, 0, 7))
        y = k.public()
        w.lock()
        self.assertEqual(code(lambda: k.call('pop', {})), 'UAKeyRevoked')
        self.assertEqual(k.public(), y, 'public data stays readable')
        self.assertEqual(code(lambda: w.zether_key(60, 0, 7)), 'UAWalletLocked')


class Pqz(Case):
    REQ = {'proofSystemId': '0x' + PQZL_ID['n2304-kmax4096'], 'kind': 0x0131, 'ua': '0x' + '11' * 32}

    def test_set_and_check_set(self):
        f = W.features()
        self.assertTrue(f & W.FEATURE['pqz'] and f & W.FEATURE['pqz-set-n2304-kmax4096'])
        s = json.loads(W.pqz_set())
        self.assertEqual((s['set'], s['pkLen'], s['pqzlId']), ('n2304-kmax4096', 18432, '0x' + PQZL_ID['n2304-kmax4096']))
        W.pqz_check_set(s)
        self.assertEqual(code(lambda: W.pqz_check_set(dict(s, set='n2048-kmax1024'))), 'UAPqzSetMismatch')
        self.assertEqual(code(lambda: W.pqz_check_set(dict(s, extra=1))), 'UAArgument')

    def test_leaf_is_the_ua_pq_rule(self):
        m = MN['pq_kat']
        seed = hashlib.pbkdf2_hmac('sha512', m['words'].encode(), b'mnemonic' + m['passphrase'].encode(), 2048)
        prk = hmac.new(b'scaas.ua.pq.v1', seed, hashlib.sha256).digest()
        w = self.new_wallet('pq_kat')
        for a, i in ((0, 0), (1, 2)):
            want = hmac.new(prk, b'scaas.ua.pqz-mlwe.v1' + a.to_bytes(4, 'big') + i.to_bytes(4, 'big') + b'\x01', hashlib.sha256).digest()
            leaf = w.export_pqz_leaf_raw(a, i)
            self.assertEqual(leaf, want, (a, i))
            W.wipe(leaf)
            self.assertEqual(len(self.keep(w.pqz_key(a, i)).public()), 18432)
        self.assertEqual(code(lambda: w.export_pqz_leaf_raw(1 << 31, 0)), 'UAArgument')

    def test_pqz_key_versions_are_the_pq_kat_rows(self):
        """Group 3g C8 (T15o): ``pqz_key`` / ``export_pqz_leaf_raw`` at a key version give pq_kat.json's ``pqzSeeds``."""
        rows = json.loads((STATE / 'ua' / 'pq_kat.json').read_text())['pqzSeeds']
        w = self.new_wallet('pq_kat')
        pks = []
        for r in rows:
            leaf = w.export_pqz_leaf_raw(r['account'], r['index'], r['version'])
            self.assertEqual('0x' + bytes(leaf).hex(), r['seed32'], r['version'])
            W.wipe(leaf)
            pks.append(self.keep(w.pqz_key(r['account'], r['index'], r['version'])).public())
        self.assertEqual(pks[0], self.keep(w.pqz_key()).public(), 'version 0 is the default')
        self.assertEqual(len(set(pks)), 3, 'one key per version')

    def test_register_set_mismatch_and_key_field(self):
        k = self.keep(self.new_wallet('pq_kat').pqz_key())
        out = json.loads(k.call('proveRegister', self.REQ))
        self.assertEqual(b(out['stmt'])[96:], k.public())
        self.assertEqual(code(lambda: k.call('proveRegister', dict(self.REQ, proofSystemId='0x' + PQZL_ID['n2048-kmax1024']))),
                         'UAPqzSetMismatch')
        for f in ('key', 'seed32'):
            self.assertEqual(code(lambda: k.call('proveRegister', dict(self.REQ, **{f: {'seed32': '0x' + '11' * 32}}))), 'UAArgument', f)

    def test_enc_dec_and_cache_box(self):
        w = self.new_wallet('pq_kat')
        k = self.keep(w.pqz_key())
        e = json.loads(k.call('enc', {'pks': [hx(k.public())], 'values': [123456]}))
        # ARCH-POS-13 (T15c): a release build has no raw decrypt; a well-formed `dec` is an unknown command
        self.assertEqual(code(lambda: k.call('dec', {'ct': e['u'] + e['vs'][0][2:]})), 'UAArgument')
        box = k.seal_balance_cache(bytearray(b'{"v":1}'))
        self.assertEqual(k.open_balance_cache(box), b'{"v":1}')
        self.assertEqual(code(lambda: self.keep(w.pqz_key(0, 1)).open_balance_cache(box)), 'UAAead')

    def test_words_commands_on_the_forge_rows(self):
        """T15g (ARCH-POS-13): `balance` on a forge row (smartcontracts/vectors/pqz/n2304-kmax4096/state.json): in COMMANDS;
        the forge keys are mocked, so the words bind to no wallet key and are refused (UAArgument), with the other set's psid
        UAPqzSetMismatch, both before the key (ua-rs tests/facade_pqz_state.rs counts the key's uses); every `vectors`-only
        raw form refused by the release library."""
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
        k = self.keep(self.new_wallet('pq_kat').pqz_key())
        self.assertEqual(code(lambda: k.call('balance', words)), 'UAArgument')
        self.assertEqual(code(lambda: k.call('balance', dict(words, psid='0x' + PQZL_ID['n2048-kmax1024']))), 'UAPqzSetMismatch')
        for c in raw:
            self.assertEqual(code(lambda: k.call(c, {})), 'UAArgument', c)
        # T15i: words rows for wallet keys (smartcontracts/vectors/pqz/n2304-kmax4096/wallet_state.json, written by ua-rs
        # under `vectors`, gen_wallet_state.sh): each row's own handle decrypts its balance
        w = self.new_wallet('pq_kat')
        for r in json.loads((STATE / 'pqz' / 'n2304-kmax4096' / 'wallet_state.json').read_text())['rows']:
            q = self.keep(w.pqz_key(r['account'], r['index'], r['version']))
            self.assertEqual(json.loads(q.call('balance', r['request']))['value'], r['value'], r['name'])

    def test_no_oracle(self):
        """T15i (ARCH-POS-13; spec no-decryption-oracle §5): ua-rs tests/no_oracle.rs's harness through the C ABI. The 8·K
        crafted queries (`u` the unit polynomial at polynomial j, every `v` coefficient ⌈Δ/2⌉ + off, off 0 and -1, four windows;
        through a raw decrypt they recover s, ua-rs's positive control) in every bare shape (a ciphertext with and without a
        window, `T` with and without `p`, a statement, `u` / `v`) to every release command and to `dec`: each refused with one
        status. Control: the same handle and call path answer a well-formed `enc`."""
        st = json.loads((ROOT / 'pqz-core' / 'params' / 'sets' / 'n2304-kmax4096' / 'set.json').read_text())
        q, delta, polys = st['q'], st['delta'], st['k']
        release, raw = commands('pqz')
        self.assertIn('dec', raw)
        self.assertNotIn('dec', release)
        k = self.keep(self.new_wallet('pq_kat').pqz_key())
        self.assertEqual(len(json.loads(k.call('enc', {'pks': [hx(k.public())], 'values': [1]}))['vs']), 1, 'the call path answers')
        n = 0
        for j in range(polys):
            u = bytearray(8 * 64 * polys)
            u[8 * 64 * j + 7] = 1
            for w in range(4):
                for off in (0, -1):
                    v = (((delta + 1) // 2 + off) % q).to_bytes(8, 'big') * 16
                    ct = hx(bytes(u) + v)
                    for shape in ({'ct': ct}, {'ct': ct, 'window': w}, {'T': ct}, {'T': ct, 'p': 1}, {'stmt': ct},
                                  {'u': hx(u), 'v': hx(v)}):
                        req = json.dumps(shape)
                        for c in release + ['dec']:
                            self.assertEqual(code(lambda: k.call(c, req)), 'UAArgument', (c, j, w, off, list(shape)))
                    n += 1
        self.assertEqual(n, 8 * polys)

    def test_pqz_handle_after_lock_is_KEY_REVOKED(self):
        w = self.new_wallet('pq_kat')
        k = self.keep(w.pqz_key())
        pk = k.public()
        w.lock()
        self.assertEqual(code(lambda: k.call('proveRegister', self.REQ)), 'UAKeyRevoked')
        self.assertEqual(k.public(), pk)
        self.assertEqual(code(lambda: w.export_pqz_leaf_raw(0, 0)), 'UAWalletLocked')


if __name__ == '__main__':
    unittest.main()
