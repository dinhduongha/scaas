# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The ua-rs wallet through libscaas_ua_c (clients/ua-c, C ABI v6) by ctypes (spec 2026-11-05-ua-rs-sign §9.2, plan T13d).

The identity port (``scaas_ua``) stays this package's own code and the independent cross-check; signing, KEM, seal, vault,
backup, link and the Zether and PQZ facades are the library's. At load the library's ``scaas_ua_abi_version()`` must be 6 and
``scaas_ua_features()`` a build this binding knows (``LibraryMismatch`` otherwise).

Secrets: every buffer this module hands the library for a secret (mnemonic, passphrases, PRF secret, imported key, AEAD key,
plaintexts, shared secrets, revealed words, entropy, the PQZ leaf) is a ctypes buffer wiped in a ``finally``. Secret inputs are
bytes-like (a ``str`` cannot be wiped and is refused); secret outputs are ``bytearray``: wipe them with ``wipe()``.
Handles: each class owns one library handle, freed once by ``close()`` (or ``with``, or the garbage collector); ``close()``
waits for calls in flight on that handle. Library path: ``SCAAS_UA_C_LIB``, else clients/ua-c/target/release. UNAUDITED."""
import ctypes as C
import json
import os
import pathlib
import sys
import threading
from collections import namedtuple

from . import UAError

ABI_VERSION = 6
FEATURES = ('wallet', 'pq', 'falcon', 'zether', 'pqz', 'pqz-set-n2048-kmax1024', 'pqz-set-n2304-kmax4096',
            'pqz-set-n2560-kmax16384', 'pqz-set-n2816-kmax65536', 'external', 'mlock', 'vectors')
FEATURE = {n: 1 << i for i, n in enumerate(FEATURES)}
_SETS = sum(v for n, v in FEATURE.items() if n.startswith('pqz-set-'))
NETWORKS = ('evm', 'cosmos', 'hedera_ecdsa', 'hedera_ed25519', 'sui', 'stellar', 'ton', 'aptos', 'solana')
COIN_DEFAULT = 0xFFFFFFFF
AEAD_AES256_GCM, AEAD_AES256_GCM_SIV = 1, 2
KEM_PK_LEN, KEM_CT_LEN = 1601, 1568
MNEMONIC_MAX, ENTROPY_MAX = 256, 32
ZETHER_Y_LEN, ZETHER_USE_CONF, ZETHER_USE_VIEWING = 128, 7, 8
PQZ_OUT_MAX = 1_052_672
OK, ERR_KEY_DATA, ERR_ARGUMENT, ERR_BUFFER = 0, 1, 8, 9


class LibraryMismatch(RuntimeError):
    """The library is not ABI 6 or its feature bits are not a build this binding knows."""


class WalletError(UAError):
    """A status of the library: ``code`` is its name ("UASealOpen" ...), ``reason`` the library's detail (never an input)."""

    def __init__(self, status, code, reason=None):
        super().__init__(code, reason)
        self.status = status


def check_build(abi, features):
    """Refuses a library of another ABI or an unknown feature set (the load check), and any test build (bit ``vectors``,
    spec no-decryption-oracle §4.8, Codex C1)."""
    if abi != ABI_VERSION:
        raise LibraryMismatch(f'libscaas_ua_c ABI {abi}, this binding needs {ABI_VERSION}')
    if features & FEATURE['vectors']:
        raise LibraryMismatch('libscaas_ua_c is a test build (feature vectors): refused')
    need = FEATURE['wallet'] | FEATURE['pq']
    sets = features & _SETS
    if (features & need != need or features >> len(FEATURES) or sets & (sets - 1)
            or bool(sets) != bool(features & FEATURE['pqz'])):
        raise LibraryMismatch(f'libscaas_ua_c features {features:#x} are not a build this binding knows')


P, u16, u32, u64, sz, bl, st = C.c_void_p, C.c_uint16, C.c_uint32, C.c_uint64, C.c_size_t, C.c_bool, C.c_int32


class MemoryProtection(C.Structure):
    _fields_ = [('chunks', sz), ('locked', sz), ('no_dump', sz)]


class _Recipient(C.Structure):
    _fields_ = [('kind', u16), ('key_data', C.c_char_p), ('key_data_len', sz), ('version', u64), ('kem_pk', C.c_char_p), ('kem_pk_len', sz),
                ('ephemeral', bl)]


_SIGNATURES = [
    ('abi_version', u32, []), ('features', u64, []), ('status_name', C.c_char_p, [st]), ('last_error', C.c_char_p, []),
    ('wallet_generate', st, [P, P]), ('wallet_from_mnemonic', st, [P, P, P]), ('wallet_open_vault', st, [P, P, P, P, P]),
    ('wallet_unlock', st, [P, P, P, P, P]), ('wallet_seal_vault', st, [P, P, P, P]), ('wallet_lock', st, [P]),
    ('wallet_free', None, [P]), ('wallet_memory_protection', st, [P, P]), ('wallet_ua_key', st, [P, u16, u32, u32, P]),
    ('wallet_native_key', st, [P, u32, u32, u32, P]), ('wallet_import_native_key', st, [P, u32, P, sz, P]),
    ('wallet_imported_key', st, [P, u32, u32, P]), ('wallet_seal_label_vault', st, [P, P, P, P, P]),
    ('wallet_open_label_vault', st, [P, P, P, P]), ('wallet_manifest_json', st, [P, P, P]),
    ('wallet_discover_candidates', st, [P, u16, u32, u32, P, P]), ('wallet_backup_seal', st, [P, P, P, sz, P, P]),
    ('wallet_restore_backup', st, [P, P, P, P, P, P, P, P, P]),
    ('wallet_restore_backup_rollback', st, [P, P, P, P, P, P, P, P, P]),
    ('wallet_link_seal', st, [P, P, P, sz, P, P, P]), ('wallet_from_link', st, [P, P, P, P, P, P, P]),
    ('seed_backup_reveal', st, [P, P, P]), ('seed_backup_challenge', st, [P, P]), ('seed_backup_verify', st, [P, P, sz, P]),
    ('seed_backup_take', st, [P, P, P, P]), ('seed_backup_free', None, [P]),
    ('key_free', None, [P]), ('key_data', st, [P, P, P]), ('sign_ua', st, [P, P, P, P, P]), ('sign_member', st, [P, P, P, P, P]),
    ('sign_typed', st, [P, P, P, P, P]), ('sign_typed_any', st, [P, P, P, P]), ('sign_transaction', st, [P, P, P, P]),
    ('sign_key_proof', st, [P, P, sz, P, P]), ('sign_digest_raw', st, [P, P, P, P]), ('uasig', st, [P, P, sz, P, P]),
    ('external_key_new', st, [P, P, P]),
    ('kem_key', st, [P, u64, P]), ('kem_ephemeral', st, [P]), ('kem_free', None, [P]), ('kem_pk', st, [P, P]),
    ('kem_decaps', st, [P, P, sz, P, P]), ('kem_encaps', st, [P, sz, P, P, P]),
    ('seal', st, [P, sz, P, P, sz, P, sz, P, P, P, P, P]), ('open', st, [P, P, P, sz, P, sz, P, P, sz, P, P]),
    ('open_container', st, [P, P, P, P, P, P, P]),
    ('link_session_new', st, [P]), ('link_session_kem_pk', st, [P, P]), ('link_session_short_code', st, [P, P, P]),
    ('link_session_free', None, [P]),
    ('vault_needs_rewrap', st, [P, P]), ('vault_rewrap_pin', st, [P, P, P, P, P]), ('vault_enable_prf', st, [P, P, P, P, P, sz, P, P]),
    ('aead_seal', st, [u32, P, P, P, sz, P, sz, P, P]), ('aead_open', st, [u32, P, P, P, sz, P, sz, P, P]),
    ('hkdf_sha256', st, [P, sz, P, sz, P, sz, P, sz]), ('hmac_sha256', st, [P, sz, P, sz, P]),
    ('webauthn_challenge', st, [P, P, P]), ('webauthn_assertion', st, [P, sz, P, P, sz, P, sz, P, P, P, P]),
    ('wallet_zether_key', st, [P, u32, u32, u32, P]), ('zether_key_free', None, [P]), ('zether_public', st, [P, P, P]),
    ('zether_call', st, [P, P, P, P, P]), ('zether_seal_balance_cache', st, [P, P, sz, P, P]),
    ('zether_open_balance_cache', st, [P, P, P, P]),
    ('wallet_pqz_key', st, [P, u32, u32, P]), ('pqz_key_free', None, [P]), ('pqz_public', st, [P, P, P]),
    ('pqz_call', st, [P, P, P, P, P]), ('pqz_seal_balance_cache', st, [P, P, sz, P, P]), ('pqz_open_balance_cache', st, [P, P, P, P]),
    ('pqz_set', st, [P, P]), ('pqz_check_set', st, [P]), ('export_pqz_leaf_raw', st, [P, u32, u32, P]),
]

_lib = None
_load_lock = threading.Lock()
_abi_hook = None  # test hook: maps the library's ABI version before the check (load_refuses_wrong_abi_or_features)


def _default_path():
    name = {'win32': 'scaas_ua_c.dll', 'darwin': 'libscaas_ua_c.dylib'}.get(sys.platform, 'libscaas_ua_c.so')
    return os.environ.get('SCAAS_UA_C_LIB') or str(pathlib.Path(__file__).resolve().parents[2] / 'ua-c' / 'target' / 'release' / name)


def load(path=None):
    """Loads and checks the library (once; again with ``path``). Raises ``LibraryMismatch`` and keeps no library then."""
    global _lib
    with _load_lock:
        if _lib is not None and path is None:
            return _lib
        lib = C.CDLL(path or _default_path())
        for name, res, args in _SIGNATURES:
            f = getattr(lib, 'scaas_ua_' + name)
            f.restype, f.argtypes = res, args
        abi = lib.scaas_ua_abi_version()
        if _abi_hook is not None:
            abi = _abi_hook(abi)
        check_build(abi, lib.scaas_ua_features())
        _lib = lib
        return lib


def _c(name):
    return getattr(_lib if _lib is not None else load(), 'scaas_ua_' + name)


def abi_version():
    return _c('abi_version')()


def features():
    return _c('features')()


def status_name(status):
    return _c('status_name')(status).decode()


def _ok(status):
    if status != OK:
        raise WalletError(status, status_name(status), _c('last_error')().decode())


def _refuse(what):
    raise WalletError(ERR_KEY_DATA, 'UAKeyData', what)


# --- secrets ---

def _secret_buf(n):
    """Test hook (secret_buffer_wiped_after_call): every buffer that holds a secret comes from here and is wiped in a finally."""
    return C.create_string_buffer(max(n, 1))


def _wipe(buf):
    C.memset(buf, 0, C.sizeof(buf))


def wipe(b):
    """Zeroizes a ``bytearray`` this module returned (or any writable buffer)."""
    if len(b):
        C.memset((C.c_char * len(b)).from_buffer(b), 0, len(b))


class _Secrets:
    """The secret buffers of one call: inputs copied in, outputs copied out to a ``bytearray``; all wiped on exit."""

    def __init__(self):
        self.bufs = []

    def __enter__(self):
        return self

    def __exit__(self, *_):
        for b in self.bufs:
            _wipe(b)

    def buf(self, n):
        b = _secret_buf(n)
        self.bufs.append(b)
        return b

    def bytes_in(self, v, nul=False, n=None):
        """A copy of the secret ``v`` (bytes-like; NUL-terminated with ``nul``), or None."""
        if v is None:
            return None
        if isinstance(v, str):
            raise TypeError('a secret is bytes-like (a bytearray, wiped after use): a str cannot be wiped')
        k = len(v)
        if n is not None and k != n:
            _refuse(f'a {n}-byte secret')
        b = self.buf(k + nul)
        if k:  # no intermediate copy: bytes by pointer, a bytearray through its own buffer
            C.memmove(b, v if isinstance(v, bytes) else (C.c_char * k).from_buffer(v), k)
        return b

    def out(self, b, n):
        """A ``bytearray`` copy of the first ``n`` bytes of the secret buffer ``b``."""
        o = bytearray(n)
        if n:
            C.memmove((C.c_char * n).from_buffer(o), b, n)
        return o


def _fixed(v, n, what):
    if v is None or len(v) != n:
        _refuse(f'{what}: {n} bytes')
    return bytes(v)


def _text(v):
    """A public text input: str, bytes, or a JSON value (dumped); None stays None (NULL)."""
    if v is None or isinstance(v, bytes):
        return v
    return (v if isinstance(v, str) else json.dumps(v)).encode()


def _var(fn, *args, cap=4096):
    """A public variable output: one call into ``cap`` bytes, again at the size the library asks for (a size query runs the
    call again: a new signature, seal or vault)."""
    n = sz(cap)
    buf = C.create_string_buffer(cap)
    status = fn(*args, buf, C.byref(n))
    if status == ERR_BUFFER:
        buf = C.create_string_buffer(n.value)
        status = fn(*args, buf, C.byref(n))
    _ok(status)
    return buf.raw[:n.value]


def _str(fn, *args, cap=4096):
    return _var(fn, *args, cap=cap)[:-1].decode()  # *out_len counts the NUL


# --- handles ---

class _Handle:
    """One library handle: freed exactly once (``close``, ``with``, or the collector); ``close`` waits for calls in flight."""

    def __init__(self, ptr, free):
        self._p, self._free, self._busy, self._cv = ptr, free, 0, threading.Condition()

    def _acquire(self):
        with self._cv:
            if self._p is None:
                raise ValueError(f'{type(self).__name__} is closed')
            self._busy += 1
            return self._p

    def _release(self):
        with self._cv:
            self._busy -= 1
            self._cv.notify_all()

    def close(self):
        with self._cv:
            p, self._p = self._p, None
            while self._busy:
                self._cv.wait()
        if p is not None:
            self._free(p)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def __del__(self):
        if getattr(self, '_cv', None) is not None:
            self.close()


class _hold:
    """The pointers of handles (None stays NULL) for the length of one call."""

    def __init__(self, *handles):
        self.hs = handles

    def __enter__(self):
        got = []
        try:
            for h in self.hs:
                got.append(None if h is None else h._acquire())
        except BaseException:
            for h, _ in zip(self.hs, got):
                if h is not None:
                    h._release()
            raise
        return got

    def __exit__(self, *_):
        for h in self.hs:
            if h is not None:
                h._release()


def _new(cls, fn, *args):
    p = P()
    _ok(fn(*args, C.byref(p)))
    return cls(p.value)


def _network(n):
    return NETWORKS.index(n) if isinstance(n, str) else n


Recipient = namedtuple('Recipient', 'kind key_data version kem_pk ephemeral', defaults=(False,))
Recipient.__doc__ = """A backup recipient: the KEM key ``kem_pk`` of record ``version`` of the UA of (``kind``, ``key_data``), or an
ephemeral key (``ephemeral=True``, the other fields unread)."""


class Wallet(_Handle):
    def __init__(self, ptr):
        super().__init__(ptr, _c('wallet_free'))

    @classmethod
    def generate(cls):
        """A new 24-word wallet and its ``SeedBackup``."""
        w, b = P(), P()
        _ok(_c('wallet_generate')(C.byref(w), C.byref(b)))
        return cls(w.value), SeedBackup(b.value)

    @classmethod
    def from_mnemonic(cls, words, bip39_passphrase=None):
        with _Secrets() as s:
            return _new(cls, _c('wallet_from_mnemonic'), s.bytes_in(words, True), s.bytes_in(bip39_passphrase, True))

    @classmethod
    def open_vault(cls, vault_json, passphrase=None, prf32=None, bip39_passphrase=None):
        with _Secrets() as s:
            return _new(cls, _c('wallet_open_vault'), _text(vault_json), s.bytes_in(passphrase, True), s.bytes_in(prf32, n=32),
                        s.bytes_in(bip39_passphrase, True))

    def unlock(self, vault_json, passphrase=None, prf32=None, bip39_passphrase=None):
        with _Secrets() as s, _hold(self) as (w,):
            _ok(_c('wallet_unlock')(w, _text(vault_json), s.bytes_in(passphrase, True), s.bytes_in(prf32, n=32),
                                    s.bytes_in(bip39_passphrase, True)))

    def seal_vault(self, passphrase):
        with _Secrets() as s, _hold(self) as (w,):
            return _str(_c('wallet_seal_vault'), w, s.bytes_in(passphrase, True))

    def lock(self):
        with _hold(self) as (w,):
            _ok(_c('wallet_lock')(w))

    def memory_protection(self):
        mp = MemoryProtection()
        with _hold(self) as (w,):
            _ok(_c('wallet_memory_protection')(w, C.byref(mp)))
        return mp

    def ua_key(self, kind, account=0, index=0):
        with _hold(self) as (w,):
            return _new(Key, _c('wallet_ua_key'), w, kind, account, index)

    def native_key(self, network, index=0, coin_type=COIN_DEFAULT):
        with _hold(self) as (w,):
            return _new(Key, _c('wallet_native_key'), w, _network(network), index, COIN_DEFAULT if coin_type is None else coin_type)

    def import_native_key(self, network, secret):
        with _Secrets() as s, _hold(self) as (w,):
            sec = s.bytes_in(secret)
            return _new(Key, _c('wallet_import_native_key'), w, _network(network), sec, len(secret))

    def imported_key(self, network, n):
        with _hold(self) as (w,):
            return _new(Key, _c('wallet_imported_key'), w, _network(network), n)

    def seal_label_vault(self, label, passphrase):
        with _Secrets() as s, _hold(self) as (w,):
            return _str(_c('wallet_seal_label_vault'), w, _text(label), s.bytes_in(passphrase, True))

    def open_label_vault(self, vault_json, passphrase=None, prf32=None):
        with _Secrets() as s, _hold(self) as (w,):
            _ok(_c('wallet_open_label_vault')(w, _text(vault_json), s.bytes_in(passphrase, True), s.bytes_in(prf32, n=32)))

    def manifest_json(self):
        with _hold(self) as (w,):
            return _str(_c('wallet_manifest_json'), w)

    def discover_candidates(self, kind, account, gap):
        with _hold(self) as (w,):
            return _str(_c('wallet_discover_candidates'), w, kind, account, gap, cap=1 << 17)

    def backup_seal(self, sender, recipients):
        """One ``scaas/backup/v1`` container per recipient (a JSON array); raises the backup generation (once per call into
        the 4 MiB first buffer; a larger answer raises it again)."""
        rs = list(recipients)
        arr = (_Recipient * max(len(rs), 1))()
        keep = [(bytes(r.key_data or b''), bytes(r.kem_pk)) for r in rs]  # alive for the call
        for i, (r, (kd, pk)) in enumerate(zip(rs, keep)):
            arr[i] = _Recipient(r.kind, kd, len(kd), r.version, pk, len(pk), r.ephemeral)
        with _hold(self, sender) as (w, k):
            return _str(_c('wallet_backup_seal'), w, k, arr if rs else None, len(rs), cap=4 << 20)

    def link_seal(self, sender, session_kem_pk, short_code):
        pk = bytes(session_kem_pk)
        with _hold(self, sender) as (w, k):
            return _str(_c('wallet_link_seal'), w, k, pk, len(pk), _text(short_code), cap=1 << 20)

    def zether_key(self, coin, account, use=ZETHER_USE_CONF):
        with _hold(self) as (w,):
            return _new(ZetherKey, _c('wallet_zether_key'), w, coin, account, use)

    def pqz_key(self, account=0, index=0):
        with _hold(self) as (w,):
            return _new(PqzKey, _c('wallet_pqz_key'), w, account, index)

    def export_pqz_leaf_raw(self, account, index):
        """WARNING: the 32-byte PQZ leaf seed32 in the clear (``bytearray``): wipe it with ``wipe()`` after use."""
        with _Secrets() as s, _hold(self) as (w,):
            out = s.buf(32)
            _ok(_c('export_pqz_leaf_raw')(w, account, index, out))
            return s.out(out, 32)

    @staticmethod
    def _restore(fn, kem_key, container, expect, members, accepted, current, bip39_passphrase):
        out, installed = P(), bl()
        with _Secrets() as s, _hold(kem_key, current) as (kk, cur):
            _ok(_c(fn)(kk, _text(container), _text(expect), _text(members), _text(accepted), cur,
                       s.bytes_in(bip39_passphrase, True), C.byref(out), C.byref(installed)))
        return Wallet(out.value) if installed.value else None

    @staticmethod
    def restore_backup(kem_key, container, expect, members=None, accepted=None, current=None, bip39_passphrase=None):
        """The wallet a backup container carries, or None when ``current`` holds that generation already (an older one is
        ``UABackupRollback``)."""
        return Wallet._restore('wallet_restore_backup', kem_key, container, expect, members, accepted, current, bip39_passphrase)

    @staticmethod
    def restore_backup_rollback(kem_key, container, expect, members=None, accepted=None, current=None, bip39_passphrase=None):
        """``restore_backup`` that may install an older backup: only after the user confirmed the rollback."""
        return Wallet._restore('wallet_restore_backup_rollback', kem_key, container, expect, members, accepted, current,
                               bip39_passphrase)

    @staticmethod
    def from_link(session, container, expect, members=None, accepted=None, bip39_passphrase=None):
        """The wallet a link container carries to ``session`` (which it consumes)."""
        with _Secrets() as s, _hold(session) as (ls,):
            return _new(Wallet, _c('wallet_from_link'), ls, _text(container), _text(expect), _text(members), _text(accepted),
                        s.bytes_in(bip39_passphrase, True))


class SeedBackup(_Handle):
    def __init__(self, ptr):
        super().__init__(ptr, _c('seed_backup_free'))

    def reveal(self):
        """The recovery phrase, once (``bytearray``; wipe it)."""
        with _Secrets() as s, _hold(self) as (b,):
            out, n = s.buf(MNEMONIC_MAX), sz(MNEMONIC_MAX)
            _ok(_c('seed_backup_reveal')(b, out, C.byref(n)))
            return s.out(out, n.value - 1)

    def challenge(self):
        pos = (u32 * 3)()
        with _hold(self) as (b,):
            _ok(_c('seed_backup_challenge')(b, pos))
        return tuple(pos)

    def verify(self, answers):
        ok = bl()
        with _Secrets() as s, _hold(self) as (b,):
            words = [s.bytes_in(a, True) for a in answers]
            arr = (P * max(len(words), 1))(*[C.addressof(x) for x in words])
            _ok(_c('seed_backup_verify')(b, arr, len(words), C.byref(ok)))
        return ok.value

    def take(self):
        """The entropy once the words were confirmed (``bytearray``; wipe it), else None."""
        taken = bl()
        with _Secrets() as s, _hold(self) as (b,):
            out, n = s.buf(ENTROPY_MAX), sz(ENTROPY_MAX)
            _ok(_c('seed_backup_take')(b, out, C.byref(n), C.byref(taken)))
            return s.out(out, n.value) if taken.value else None


class Key(_Handle):
    """A UA key or a native key of a wallet."""

    def __init__(self, ptr):
        super().__init__(ptr, _c('key_free'))

    def key_data(self):
        with _hold(self) as (k,):
            return _var(_c('key_data'), k)

    def sign_ua(self, purpose32, digest32):
        with _hold(self) as (k,):
            return _var(_c('sign_ua'), k, _fixed(purpose32, 32, 'purpose'), _fixed(digest32, 32, 'digest'), cap=8192)

    def sign_member(self, structure_ua32, structure_ua_msg32):
        with _hold(self) as (k,):
            return _var(_c('sign_member'), k, _fixed(structure_ua32, 32, 'structure ua'),
                        _fixed(structure_ua_msg32, 32, 'structure ua_msg'), cap=8192)

    def sign_typed(self, typed_data, expect):
        with _hold(self) as (k,):
            return _var(_c('sign_typed'), k, _text(typed_data), _text(expect))

    def sign_typed_any(self, typed_data):
        with _hold(self) as (k,):
            return _var(_c('sign_typed_any'), k, _text(typed_data))

    def sign_transaction(self, tx):
        with _hold(self) as (k,):
            return _var(_c('sign_transaction'), k, _text(tx), cap=1 << 15)

    def sign_key_proof(self, challenge):
        c = bytes(challenge)
        with _hold(self) as (k,):
            return _var(_c('sign_key_proof'), k, c, len(c))

    def sign_digest_raw(self, digest32):
        with _hold(self) as (k,):
            return _var(_c('sign_digest_raw'), k, _fixed(digest32, 32, 'digest'))

    def kem_key(self, version=0):
        with _hold(self) as (k,):
            return _new(KemKey, _c('kem_key'), k, version)


def uasig(request, keys):
    """The ``UASig`` JSON of ``request`` (named fields; signing keys by position in ``keys``)."""
    keys = list(keys)
    with _hold(*keys) as ps:
        arr = (P * max(len(ps), 1))(*ps)
        return _str(_c('uasig'), _text(request), arr if ps else None, len(ps), cap=1 << 16)


def external_key_new(key_ref):
    """Reserved (phase 2): no build of this round has an external key (``UAKindUnavailable``)."""
    return _new(Key, _c('external_key_new'), _text(key_ref), None)


class KemKey(_Handle):
    def __init__(self, ptr):
        super().__init__(ptr, _c('kem_free'))

    @classmethod
    def ephemeral(cls):
        return _new(cls, _c('kem_ephemeral'))

    def kem_pk(self):
        out = C.create_string_buffer(KEM_PK_LEN)
        with _hold(self) as (kk,):
            _ok(_c('kem_pk')(kk, out))
        return out.raw

    def decaps(self, mlkem_ct, x25519_eph32):
        """The 32-byte shared secret (``bytearray``; wipe it)."""
        ct = bytes(mlkem_ct)
        with _Secrets() as s, _hold(self) as (kk,):
            ss = s.buf(32)
            _ok(_c('kem_decaps')(kk, ct, len(ct), _fixed(x25519_eph32, 32, 'x25519 key'), ss))
            return s.out(ss, 32)

    def open(self, purpose, aad, mlkem_ct, x25519_eph32, ct):
        """The plaintext of a seal (``bytearray``; wipe it)."""
        aad, mct, ct = bytes(aad), bytes(mlkem_ct), bytes(ct)
        n = max(len(ct) - 16, 0)
        with _Secrets() as s, _hold(self) as (kk,):
            pt, m = s.buf(n), sz(n)
            _ok(_c('open')(kk, _text(purpose), aad, len(aad), mct, len(mct), _fixed(x25519_eph32, 32, 'x25519 key'), ct, len(ct),
                           pt, C.byref(m)))
            return s.out(pt, m.value)

    def open_container(self, container, expect, members=None, accepted=None):
        """The plaintext of a sealed container accepted as ``expect`` says (``bytearray``; wipe it)."""
        args = (_text(container), _text(expect), _text(members), _text(accepted))
        with _Secrets() as s, _hold(self) as (kk,):
            m = sz(0)
            status = _c('open_container')(kk, *args, None, C.byref(m))  # the capacity is checked before decapsulation
            if status != ERR_BUFFER:
                _ok(status)
            pt = s.buf(m.value)
            _ok(_c('open_container')(kk, *args, pt, C.byref(m)))
            return s.out(pt, m.value)


def kem_encaps(kem_pk):
    """``(mlkem_ct, x25519_eph32, ss32)``: ``ss32`` is a ``bytearray`` (wipe it)."""
    pk = bytes(kem_pk)
    ct, e = C.create_string_buffer(KEM_CT_LEN), C.create_string_buffer(32)
    with _Secrets() as s:
        ss = s.buf(32)
        _ok(_c('kem_encaps')(pk, len(pk), ct, e, ss))
        return ct.raw, e.raw, s.out(ss, 32)


def seal(kem_pk, purpose, aad, pt):
    """``(mlkem_ct, x25519_eph32, ct)`` of a seal of ``pt`` to ``kem_pk`` (no sender authenticated)."""
    pk, aad = bytes(kem_pk), bytes(aad)
    with _Secrets() as s:
        p = s.bytes_in(pt)
        mct, nm, e = C.create_string_buffer(KEM_CT_LEN), sz(KEM_CT_LEN), C.create_string_buffer(32)
        ct, nc = C.create_string_buffer(len(pt) + 16), sz(len(pt) + 16)
        _ok(_c('seal')(pk, len(pk), _text(purpose), aad, len(aad), p, len(pt), mct, C.byref(nm), e, ct, C.byref(nc)))
        return mct.raw[:nm.value], e.raw, ct.raw[:nc.value]


class LinkSession(_Handle):
    def __init__(self, ptr):
        super().__init__(ptr, _c('link_session_free'))

    @classmethod
    def new(cls):
        return _new(cls, _c('link_session_new'))

    def kem_pk(self):
        out = C.create_string_buffer(KEM_PK_LEN)
        with _hold(self) as (ls,):
            _ok(_c('link_session_kem_pk')(ls, out))
        return out.raw

    def short_code(self):
        with _hold(self) as (ls,):
            return _str(_c('link_session_short_code'), ls, cap=16)


def vault_needs_rewrap(vault_json):
    out = bl()
    _ok(_c('vault_needs_rewrap')(_text(vault_json), C.byref(out)))
    return out.value


def vault_rewrap_pin(vault_json, old_passphrase, new_passphrase):
    with _Secrets() as s:
        return _str(_c('vault_rewrap_pin'), _text(vault_json), s.bytes_in(old_passphrase, True), s.bytes_in(new_passphrase, True))


def vault_enable_prf(vault_json, passphrase, prf32, credential_id, salt):
    salt = bytes(salt)
    with _Secrets() as s:
        return _str(_c('vault_enable_prf'), _text(vault_json), s.bytes_in(passphrase, True), s.bytes_in(prf32, n=32),
                    _text(credential_id), salt, len(salt))


def aead_seal(alg, key32, nonce12, aad, data):
    aad = bytes(aad)
    with _Secrets() as s:
        k, d = s.bytes_in(key32, n=32), s.bytes_in(data)
        return _var(_c('aead_seal'), alg, k, _fixed(nonce12, 12, 'nonce'), aad, len(aad), d, len(data), cap=len(data) + 16)


def aead_open(alg, key32, nonce12, aad, data):
    """The plaintext (``bytearray``; wipe it)."""
    aad, data = bytes(aad), bytes(data)
    n = max(len(data) - 16, 0)
    with _Secrets() as s:
        k, out, m = s.bytes_in(key32, n=32), s.buf(n), sz(n)
        _ok(_c('aead_open')(alg, k, _fixed(nonce12, 12, 'nonce'), aad, len(aad), data, len(data), out, C.byref(m)))
        return s.out(out, m.value)


def hkdf_sha256(ikm, salt, info, n):
    """``n`` bytes of HKDF-SHA256 (``bytearray``: key material, wipe it)."""
    salt, info = bytes(salt or b''), bytes(info or b'')
    with _Secrets() as s:
        i, out = s.bytes_in(ikm), s.buf(n)
        _ok(_c('hkdf_sha256')(i, len(ikm), salt, len(salt), info, len(info), out, n))
        return s.out(out, n)


def hmac_sha256(key, data):
    data, out = bytes(data), C.create_string_buffer(32)
    with _Secrets() as s:
        _ok(_c('hmac_sha256')(s.bytes_in(key), len(key), data, len(data), out))
    return out.raw


def webauthn_challenge(purpose32, digest32):
    out = C.create_string_buffer(32)
    _ok(_c('webauthn_challenge')(_fixed(purpose32, 32, 'purpose'), _fixed(digest32, 32, 'digest'), out))
    return out.raw


def webauthn_assertion(key_data, expected_challenge32, auth_data, client_data_json, r32, s32):
    kd, ad, cd = bytes(key_data), bytes(auth_data), bytes(client_data_json)
    return _var(_c('webauthn_assertion'), kd, len(kd), _fixed(expected_challenge32, 32, 'challenge'), ad, len(ad), cd, len(cd),
                _fixed(r32, 32, 'r'), _fixed(s32, 32, 's'))


class ZetherKey(_Handle):
    """A Zether key (``Wallet.zether_key``): ``x`` stays in the wallet's store."""

    def __init__(self, ptr):
        super().__init__(ptr, _c('zether_key_free'))

    def public(self):
        """``(Y, ua)``: 128 and 32 bytes."""
        y, ua = C.create_string_buffer(ZETHER_Y_LEN), C.create_string_buffer(32)
        with _hold(self) as (k,):
            _ok(_c('zether_public')(k, y, ua))
        return y.raw, ua.raw

    def call(self, cmd, request):
        """zether-prover's command ``cmd`` on ``request`` (named fields) with this key: its JSON answer."""
        with _hold(self) as (k,):
            return _str(_c('zether_call'), k, _text(cmd), _text(request), cap=1 << 20)

    def seal_balance_cache(self, entries):
        with _Secrets() as s, _hold(self) as (k,):
            return _str(_c('zether_seal_balance_cache'), k, s.bytes_in(entries), len(entries))

    def open_balance_cache(self, box):
        """The cache entries (``bytearray``; wipe it)."""
        return _open_box(self, 'zether_open_balance_cache', box)


def _open_box(h, fn, box):
    with _Secrets() as s, _hold(h) as (k,):
        m = sz(0)
        status = _c(fn)(k, _text(box), None, C.byref(m))
        if status != ERR_BUFFER:
            _ok(status)
        out = s.buf(m.value)
        _ok(_c(fn)(k, _text(box), out, C.byref(m)))
        return s.out(out, m.value)


class PqzKey(_Handle):
    """A PQZ key (``Wallet.pqz_key``): ``seed32`` stays in the wallet's store."""

    def __init__(self, ptr):
        super().__init__(ptr, _c('pqz_key_free'))

    def public(self):
        with _hold(self) as (k,):
            return _var(_c('pqz_public'), k, cap=32 << 10)

    def call(self, cmd, request):
        """PQZ command ``cmd`` on ``request`` with this key: its JSON answer. One call into ``PQZ_OUT_MAX`` bytes (a size
        query would prove again, and a proof's length varies)."""
        out, n = C.create_string_buffer(PQZ_OUT_MAX), sz(PQZ_OUT_MAX)
        with _hold(self) as (k,):
            _ok(_c('pqz_call')(k, _text(cmd), _text(request), out, C.byref(n)))
        return out.raw[:n.value - 1].decode()

    def seal_balance_cache(self, entries):
        with _Secrets() as s, _hold(self) as (k,):
            return _str(_c('pqz_seal_balance_cache'), k, s.bytes_in(entries), len(entries))

    def open_balance_cache(self, box):
        """The cache entries (``bytearray``; wipe it)."""
        return _open_box(self, 'pqz_open_balance_cache', box)


def pqz_set():
    """This build's PQZ parameter set (JSON ``{set, pkLen, pqzlId, pqzhId}``)."""
    return _str(_c('pqz_set'))


def pqz_check_set(deployed):
    """Raises ``UAPqzSetMismatch`` unless ``deployed`` (a token's ``PqzSet`` JSON) is this build's set."""
    _ok(_c('pqz_check_set')(_text(deployed)))
