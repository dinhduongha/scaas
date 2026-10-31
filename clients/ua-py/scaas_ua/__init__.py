"""SCaaS Universal Account identity layer (accounts.md §1.3–§1.6) for client systems: the kind table, ids, keyHash,
purpose tags, ua_msg, the portable PoP / KEM record / PQZ key record (typed EIP-712 records, typed-signing TS-D1 … TS-D4), the registry's UAAuth digest, member digests, canonical ids and key-data validation.
The same rules live in Solidity (UAKinds.sol), JS (clientkeys ua.js), Rust (scaas-ua), Go and C#;
smartcontracts/vectors/ua pins all six. secp256k1, P-256, ed25519 and bn254 G1 are integer arithmetic here; bn254 G2
and BLS12-381 use py_ecc. Public inputs only: nothing here is constant-time. UNAUDITED."""
import re
from collections import namedtuple

from Crypto.Hash import keccak as _keccak
from py_ecc import optimized_bls12_381 as _bls
from py_ecc import optimized_bn128 as _bn


class UAError(Exception):
    """An error whose ``code`` every implementation and the vector files share."""

    def __init__(self, code, reason=None):
        super().__init__(f'{code}: {reason}' if reason else code)
        self.code = code
        self.reason = reason


def keccak256(*parts):
    h = _keccak.new(digest_bits=256)
    for p in parts:
        h.update(bytes(p))
    return h.digest()


def _need(ok, reason):
    if not ok:
        raise UAError('UAKeyData', reason)


def _bytes(v):
    """Key data and raw ids are bytes-like only; ints, strs, lists and floats are refused, not coerced."""
    if isinstance(v, (bytes, bytearray, memoryview)):
        return bytes(v)
    raise UAError('UAKeyData', 'type')


# (number, name, native, lengths (empty = variable), keyHash group)
KINDS = (
    (0x0001, 'evm-eoa', True, (20,), None),
    (0x0002, 'evm-contract', True, (20,), None),
    (0x0003, 'hedera-native', True, (20,), None),
    (0x0010, 'solana-ed25519', True, (32,), None),
    (0x0011, 'stellar-account', True, (32,), None),
    (0x0012, 'soroban-contract', True, (32,), None),
    (0x0013, 'aptos-account', True, (32,), None),
    (0x0014, 'sui-address', True, (32,), None),
    (0x0015, 'cosmos-account', True, (20, 32), None),
    (0x0016, 'ton-wallet', True, (32,), None),
    (0x0017, 'near-account', True, (32,), None),
    (0x0018, 'algorand-address', True, (32,), None),
    (0x0100, 'webauthn-p256', False, (96,), 'p256'),
    (0x0101, 'p256', False, (64,), 'p256'),
    (0x0102, 'ed25519', False, (32,), 'ed25519'),
    (0x0103, 'bip340', False, (32,), 'secp256k1'),
    (0x0104, 'schnorr-bn254', False, (64,), 'bn254-g1'),
    (0x0105, 'schnorr-bls12381', False, (128,), 'bls12381-g1'),
    (0x0106, 'bls12381-minsig', False, (256,), 'bls12381-g2'),
    (0x0107, 'bls-bn254-minsig', False, (128,), 'bn254-g2'),
    (0x0110, 'musig2-secp256k1', False, (), 'secp256k1'),
    (0x0111, 'frost-secp256k1', False, (), 'secp256k1'),
    (0x0112, 'musig2-bn254', False, (), 'bn254-g1'),
    (0x0113, 'frost-bn254', False, (), 'bn254-g1'),
    (0x0120, 'msig', False, (), None),
    (0x0130, 'mldsa44', False, (1312,), 'mldsa44'),
    (0x0131, 'mldsa65', False, (1952,), 'mldsa65'),
    (0x0132, 'fndsa512', False, (897,), 'fndsa512'),
    (0x0133, 'slhdsa128s', False, (32,), 'slhdsa128s'),
    (0x0141, 'zether-bls12381', False, (128,), 'bls12381-g1'),
    (0x0108, 'secp256k1', False, (64,), 'secp256k1'),  # 2026-10-17, appended as in kinds.json
)
# Schemes are not kinds (UA-6 U14): 0x0142 is the PQZ key attribute of a PQ holder; it keeps its tag and keyHash group.
PQZ_KEY_LENGTHS = (16384, 18432, 20480, 22528)  # the PQZ parameter sets' public key lengths (PqzSet.PK)
SCHEMES = ((0x0142, 'pqz-mlwe', PQZ_KEY_LENGTHS, 'pqz-mlwe'),)
_BY = {k[0]: k for k in KINDS}
_SCHEME = {s[0]: s for s in SCHEMES}
GROUPS = ('p256', 'ed25519', 'secp256k1', 'bn254-g1', 'bls12381-g1', 'bls12381-g2', 'bn254-g2', 'mldsa44', 'mldsa65',
          'fndsa512', 'slhdsa128s', 'pqz-mlwe')
PURPOSES = ('pop', 'metatx', 'metatx-cancel', 'member', 'zether-auth', 'zether-owner', 'keyop', 'receiver-fee',
            'vp', 'vc-anchor', 'trade', 'kem', 'pqz-key')


def kind_info(kind):
    try:
        return _BY[kind]
    except KeyError:
        raise UAError('UAKindUnknown', f'0x{kind:04x}') from None


def _derived(kind):
    if kind in _SCHEME:
        raise UAError('UAKindNotDerived', _SCHEME[kind][1])
    k = kind_info(kind)
    if k[2]:
        raise UAError('UAKindNotDerived', k[1])
    return k


def _tagged(kind):
    """(name, group) of a scheme or a derived kind: tag / keyHash / message accept both; ids and key data kinds only."""
    if kind in _SCHEME:
        return _SCHEME[kind][1], _SCHEME[kind][3]
    k = _derived(kind)
    return k[1], k[4]


def _single_signing(kind):
    return 0x0100 <= kind <= 0x0108 or 0x0110 <= kind <= 0x0113 or 0x0130 <= kind <= 0x0133


def is_native(kind):
    return kind in _BY and _BY[kind][2]


def is_zether(kind):
    return kind == 0x0141


def is_signing(kind):
    return kind == 0x0120 or kind == 0x0141 or _single_signing(kind)


def is_pqz_holder(kind):
    """Kinds that may hold a PQZ key attribute: mldsa44, mldsa65, fndsa512 (an msig per msig_pqz_eligible)."""
    return 0x0130 <= kind <= 0x0132


def is_member(kind, hedera_native=False):
    return _single_signing(kind) or kind in (0x0001, 0x0002) or (hedera_native and kind == 0x0003)


def kind_tag_string(kind):
    return f'scaas.ua.{_tagged(kind)[0]}.v1'


def tag(kind):
    return keccak256(kind_tag_string(kind).encode())


def group_tag_string(group):
    if group not in GROUPS:
        raise ValueError(f'unknown keyHash group {group}')
    return f'scaas.ua.group.{group}.v1'


def group_tag(group):
    return keccak256(group_tag_string(group).encode())


MSG_TAG = keccak256(b'scaas.ua.msg.v1')


def purpose_tag(purpose, version=1):
    """Every purpose is v1; ``pop`` is also v2 (UA-8: the portable PoP)."""
    if purpose not in PURPOSES or not (version == 1 or (purpose, version) == ('pop', 2)):
        raise UAError('UAPurposeUnknown', purpose)
    return keccak256(f'scaas.ua.purpose.{purpose}.v{version}'.encode())


POP_TAG = purpose_tag('pop')  # v1, a registry constant (kinds.json); the portable PoP is POP_V2_TAG
POP_V2_TAG = purpose_tag('pop', 2)
KEM_SCHEME_MLKEM1024_X25519 = 1  # kemPk[0] (CTR-UA-32); 2 = ML-KEM-1024 + HQC + X25519 is reserved (UAKemScheme)
KEM_PK_LENGTH = 1601  # 0x01 ‖ ML-KEM-1024 ek ‖ X25519 pk (X-Wing order)
DOMAIN_TYPEHASH = keccak256(b'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)')
UAAUTH_TYPEHASH = keccak256(b'UAAuth(bytes32 ua,bytes32 purpose,bytes32 digest)')
NAME_HASH = keccak256(b'SCaaS UARegistry')


def _sized(b, n, what):
    b = bytes(b)
    if len(b) != n:
        raise ValueError(f'{what} must be {n} bytes')
    return b


def ua_of(kind, key_data):
    """``keccak256(TAG(kind) ‖ keyData)``; no validation (see derive_ua)."""
    _derived(kind)  # a scheme (0x0142) or a native kind has no derived id
    return keccak256(tag(kind), _bytes(key_data))


def in_native_space(ua_id):
    return _sized(ua_id, 32, 'id')[:12] == bytes(12)


def derive_ua(kind, key_data, hedera_native=False):
    """Validate, derive, refuse an id whose top 96 bits are zero (CTR-UA-03)."""
    validate_key_data(kind, key_data, hedera_native)
    ua = ua_of(kind, key_data)
    if in_native_space(ua):
        raise UAError('UAIdInNativeSpace', ua.hex())
    return ua


def native_id(kind, raw):
    k = kind_info(kind)
    if not k[2]:
        raise UAError('UAKindNotNative', k[1])
    raw = _bytes(raw)
    _need(len(raw) in k[3], 'length')
    return bytes(32 - len(raw)) + raw


def key_hash_of(kind, key_data):
    """``keccak256(GROUP(g) ‖ canonical pubkey)``, None for structures. Call on validated key data."""
    group = _tagged(kind)[1]
    if group is None:
        return None
    d = _bytes(key_data)
    lo, hi = {0x0100: (0, 32), 0x0101: (0, 32), 0x0108: (0, 32), 0x0110: (1, 33), 0x0111: (1, 33), 0x0112: (0, 64), 0x0113: (0, 64)}.get(kind, (0, len(d)))
    _need(len(d) >= hi, 'length')
    return keccak256(group_tag(group), d[lo:hi])


def ua_message(kind, purpose, digest):
    return keccak256(MSG_TAG, tag(kind), _sized(purpose, 32, 'purposeTag'), _sized(digest, 32, 'digest'))


def chain_key_hash(chain_id):
    return keccak256(f'evm:{int(chain_id)}'.encode())


def _word(n):
    return int(n).to_bytes(32, 'big')


# The portable EIP-712 domain (TS-D1): name and version only, no chainId / verifyingContract / salt (CTR-UA-07).
PORTABLE_DOMAIN_TYPE = 'EIP712Domain(string name,string version)'
PORTABLE_DOMAIN_NAME = 'SCaaS UA Portable'
PORTABLE_DOMAIN_VERSION = '1'
PORTABLE_DOMAIN_SEPARATOR = keccak256(keccak256(PORTABLE_DOMAIN_TYPE.encode()), keccak256(PORTABLE_DOMAIN_NAME.encode()),
                                      keccak256(PORTABLE_DOMAIN_VERSION.encode()))
_KEM_TYPE = 'UAKemRecord(bytes32 ua,uint64 version,uint8 scheme,bytes32 kemPkHash)'
_RECORD_TYPE = 'UAPortableRecord(bytes32 ua,uint16 kind,bytes32 pqzKeyHash,UAKemRecord kem)'
_PQZ_KEY_TYPE = 'UAPqzKey(bytes32 ua,bytes32 pqzKeyHash)'
# encodeType of each portable struct: primary, then the referenced types sorted by name
PORTABLE_TYPES = {
    'UAKemRecord': _KEM_TYPE,
    'UAPortableRecord': _RECORD_TYPE + _KEM_TYPE,
    'UARegistration': 'UARegistration(UAPortableRecord record,bytes32 pqzPopHash)' + _KEM_TYPE + _RECORD_TYPE,
    'UAPqzKey': _PQZ_KEY_TYPE,
    'UAPqzKeyRecord': 'UAPqzKeyRecord(UAPqzKey key,bytes32 pqzPopHash)' + _PQZ_KEY_TYPE,
}


def portable_typehash(name):
    return keccak256(PORTABLE_TYPES[name].encode())


def hash_struct(name, *words):
    """``keccak256(typehash(name) ‖ words)``: every portable field is a 32-byte word or a nested struct hash."""
    return keccak256(portable_typehash(name), *(_sized(w, 32, 'word') for w in words))


def _typed(struct_hash):
    """``keccak256(0x1901 ‖ DS_P ‖ structHash)``: what ``eth_signTypedData_v4`` returns for a portable record."""
    return keccak256(b'\x19\x01', PORTABLE_DOMAIN_SEPARATOR, struct_hash)


def kem_record_hash(ua, version, kem_pk):
    """``hashStruct(UAKemRecord{ua, version, scheme = kemPk[0], kemPkHash = keccak256(kemPk)})``: version 1 … 2^64 − 1,
    ``kem_pk`` = scheme byte ‖ key. No record (version 0, no key) is the zero record ``UAKemRecord{ua, 0, 0, 0}`` (TS-D2)."""
    pk = _bytes(kem_pk) if kem_pk is not None else b''
    if version == 0 and not pk:
        return hash_struct('UAKemRecord', ua, bytes(32), bytes(32), bytes(32))
    if not 1 <= version < 2**64:
        raise UAError('UAKemVersion', str(version))
    if pk and pk[0] != KEM_SCHEME_MLKEM1024_X25519:
        raise UAError('UAKemScheme', str(pk[0]))
    if len(pk) != KEM_PK_LENGTH:
        raise UAError('UAKemKeyLength', str(len(pk)))
    return hash_struct('UAKemRecord', ua, _word(version), _word(pk[0]), keccak256(pk))


def kem_record_digest(ua, version, kem_pk):
    """The typed ``UAKemRecord`` digest ``setKemKey`` signs (a real record: version 0 is UAKemVersion)."""
    if version == 0:
        raise UAError('UAKemVersion', '0')
    return _typed(kem_record_hash(ua, version, kem_pk))


def portable_record_hash(ua, kind, pqz_key_hash, kem_record_hash_):
    """``hashStruct(UAPortableRecord{ua, kind, pqzKeyHash, kem})``; ``kem_record_hash_`` = kem_record_hash (the zero record's when none)."""
    return hash_struct('UAPortableRecord', ua, _word(kind), pqz_key_hash, kem_record_hash_)


def portable_record_digest(ua, kind, pqz_key_hash, kem_record_hash_):
    """The typed ``UAPortableRecord``: what R_REG proves over at ``register`` / the first ``storePqzPop``."""
    return _typed(portable_record_hash(ua, kind, pqz_key_hash, kem_record_hash_))


def registration_digest(ua, kind, pqz_key_hash, kem_record_hash_, pqz_pop_hash):
    """The typed ``UARegistration{record, pqzPopHash}``: what the signer's pop signs under ``ua_message(kind, POP_V2, ·)``
    (and a native msig member signs itself, TS-D4)."""
    return _typed(hash_struct('UARegistration', portable_record_hash(ua, kind, pqz_key_hash, kem_record_hash_), pqz_pop_hash))


def kem_record_message(kind, ua, version, kem_pk):
    """What the UA signs for a KEM record: ``ua_message(kind, PURPOSE_KEM, kem_record_digest)``."""
    return ua_message(kind, purpose_tag('kem'), kem_record_digest(ua, version, kem_pk))


def _holds(kind, key_data):
    """A PQZ / KEM holder: a single-key PQ kind, or an msig whose key data is PQ-eligible (malformed -> UAKeyData)."""
    if is_pqz_holder(kind):
        return True
    return kind == 0x0120 and len(_bytes(key_data)) > 0 and msig_pqz_eligible(key_data)


def _pqz_key_hash_of(pqz_key):
    if len(_bytes(pqz_key)) not in PQZ_KEY_LENGTHS:
        raise UAError('UAKeyData', 'PQZ key length')
    return key_hash_of(0x0142, pqz_key)


def _proof_hash_of(pqz_pop, pqz_pop_hash):
    """Proof hash from the proof bytes and / or the hash (absent = 0; an empty or all-zero hash is absent); both given and
    different is UAPqzPopHash, and so is keccak256("") (an empty proof is no proof)."""
    proof = keccak256(_bytes(pqz_pop)) if pqz_pop is not None and len(pqz_pop) > 0 else None
    given = bytes(pqz_pop_hash) if pqz_pop_hash is not None and len(pqz_pop_hash) > 0 else None
    if given is not None and len(given) != 32:
        raise UAError('UAPqzPopHash', 'hash must be 32 bytes')
    if given is not None and not any(given):
        given = None
    if proof is not None and given is not None and proof != given:
        raise UAError('UAPqzPopHash', 'proof and hash differ')
    h = proof or given or bytes(32)
    if h == keccak256(b''):
        raise UAError('UAPqzPopHash', 'empty proof')
    return h


HolderPop = namedtuple('HolderPop', 'pqz_key_hash pqz_pop_hash kem_record_hash portable_record_digest registration_digest '
                                    'message member_digest')
HolderPop.__doc__ = """``kem_record_hash`` is hashStruct(UAKemRecord) (the zero record's when none), ``portable_record_digest`` the typed
UAPortableRecord, ``registration_digest`` the typed UARegistration. ``member_digest`` (msig only, else None) is
``member_digest(ua, message)``: what each derived member signs under ``member``; a native member signs
``registration_digest`` itself (eth_signTypedData_v4, TS-D4)."""


def holder_pop_message(kind, ua, key_data=b'', pqz_key=None, pqz_pop=None, pqz_pop_hash=None, kem=None):
    """The portable PoP of a registration (UA-8 P1, P2): a HolderPop. ``pqz_key`` with its proof ``pqz_pop`` (or only its hash
    ``pqz_pop_hash``) and the initial KEM record ``kem = (version >= 1, kem_pk)``; None / (0, b'') = absent. Only holders
    carry them (UAPqzHolder, UAKemHolder; an msig needs ``key_data`` to show it is PQ-eligible); a PQZ key always comes with
    its proof hash and only with it (UAPqzPopHash)."""
    if pqz_key is not None and len(pqz_key) == 0:
        pqz_key = None
    if kem is not None and kem[0] == 0 and (kem[1] is None or len(kem[1]) == 0):
        kem = None
    if (pqz_key is not None or kem is not None) and not _holds(kind, key_data):
        if pqz_key is not None:
            raise UAError('UAPqzHolder', f'0x{kind:04x} may not hold a PQZ key')
        raise UAError('UAKemHolder', f'0x{kind:04x} may not hold a KEM key')
    pop_hash = _proof_hash_of(pqz_pop, pqz_pop_hash)
    if (pqz_key is not None) != any(pop_hash):
        raise UAError('UAPqzPopHash', 'a PQZ key comes with its proof hash and only with it')
    kh = _pqz_key_hash_of(pqz_key) if pqz_key is not None else bytes(32)
    kr = kem_record_hash(ua, *(kem or (0, b'')))
    reg = registration_digest(ua, kind, kh, kr, pop_hash)
    msg = ua_message(kind, POP_V2_TAG, reg)
    return HolderPop(kh, pop_hash, kr, portable_record_digest(ua, kind, kh, kr), reg, msg,
                     member_digest(ua, msg) if kind == 0x0120 else None)


def pqz_reg_message(kind, ua, pqz_key, kem=None):
    """The message R_REG proves over: ``ua_message(0x0142, POP_V2, portable_record_digest(ua, kind, keyHash(pqz_key),
    kem_record_hash))``, ``kind`` the registering kind (TS-D3); ``kem`` None / (0, b'') = no KEM record."""
    kr = kem_record_hash(ua, *(kem or (0, b'')))
    return ua_message(0x0142, POP_V2_TAG, portable_record_digest(ua, kind, _pqz_key_hash_of(pqz_key), kr))


def pqz_key_digest(ua, pqz_key_hash):
    """The typed ``UAPqzKey{ua, pqzKeyHash}``: what a later PQZ key's R_REG proves over (no proof hash: no cycle)."""
    return _typed(hash_struct('UAPqzKey', ua, pqz_key_hash))


def pqz_key_record_digest(ua, pqz_key_hash, pqz_pop_hash):
    """The typed ``UAPqzKeyRecord{UAPqzKey{ua, pqzKeyHash}, pqzPopHash}``: what ``setPqzKey``'s signature signs under
    ``ua_message(kind, PURPOSE_PQZ_KEY, ·)`` (and a native msig member signs itself, TS-D4)."""
    return _typed(hash_struct('UAPqzKeyRecord', hash_struct('UAPqzKey', ua, pqz_key_hash), pqz_pop_hash))


PqzKeyRecord = namedtuple('PqzKeyRecord', 'pqz_key_hash pqz_pop_hash pqz_key_digest record_digest message pqz_reg_message '
                                          'member_digest')


def pqz_key_record_message(kind, ua, key_data, pqz_key, pqz_pop=None, pqz_pop_hash=None, already_set=False):
    """The signed, portable, write-once PQZ key record of ``setPqzKey`` (ruling A1-I1): a PqzKeyRecord. ``message`` is what the
    UA signs, ``pqz_reg_message`` what the key's R_REG proves over; holder rules of holder_pop_message; the key and its
    proof hash are both required. ``already_set``: the registration has a key (UAPqzKeySet)."""
    if not _holds(kind, key_data):
        raise UAError('UAPqzHolder', f'0x{kind:04x} may not hold a PQZ key')
    if already_set:
        raise UAError('UAPqzKeySet', 'write-once')
    kh = _pqz_key_hash_of(pqz_key)
    pop_hash = _proof_hash_of(pqz_pop, pqz_pop_hash)
    if not any(pop_hash):
        raise UAError('UAPqzPopHash', 'a PQZ key record needs its proof hash')
    kd = pqz_key_digest(ua, kh)
    rd = pqz_key_record_digest(ua, kh, pop_hash)
    tag = purpose_tag('pqz-key')
    msg = ua_message(kind, tag, rd)
    return PqzKeyRecord(kh, pop_hash, kd, rd, msg, ua_message(0x0142, tag, kd), member_digest(ua, msg) if kind == 0x0120 else None)


def is_portable_purpose(purpose_tag_bytes):
    """POP_V2, KEM, PQZ_KEY: the only purposes where a code-less native msig member signs the record's typed digest itself
    (eth_signTypedData_v4, 65-byte r ‖ s ‖ v; a contract member answers ERC-1271 over it; TS-D4)."""
    return bytes(purpose_tag_bytes) in (POP_V2_TAG, purpose_tag('kem'), purpose_tag('pqz-key'))


def _address_word(a):
    return bytes(12) + _sized(a, 20, 'registry')


def ua_auth_domain_separator(generation, chain_id, registry, chain_uid):
    return keccak256(DOMAIN_TYPEHASH, NAME_HASH, keccak256(str(int(generation)).encode()), int(chain_id).to_bytes(32, 'big'),
                     _address_word(registry), _sized(chain_uid, 32, 'chainUid'))


def ua_auth_digest(generation, chain_id, registry, chain_uid, ua, purpose, digest):
    """EIP-712 digest of ``UAAuth(ua, purpose, digest)`` under the registry's domain: what native signers sign,
    except that under the three portable purposes (``is_portable_purpose``) a code-less native msig member signs the
    record's typed digest instead (CTR-MTX-14, TS-D4)."""
    s = keccak256(UAAUTH_TYPEHASH, _sized(ua, 32, 'ua'), _sized(purpose, 32, 'purposeTag'), _sized(digest, 32, 'digest'))
    return keccak256(b'\x19\x01', ua_auth_domain_separator(generation, chain_id, registry, chain_uid), s)


def member_digest(structure_ua, ua_msg):
    return keccak256(_sized(structure_ua, 32, 'structureUa'), _sized(ua_msg, 32, 'uaMsg'))


_ID = re.compile(r'0x([0-9a-fA-F]{40}|[0-9a-fA-F]{64})')


def canonical_id(text):
    """Lower-case hex; a 32-byte id with the top 96 bits zero is written as its 20-byte native id (CTR-UA-03)."""
    m = _ID.fullmatch(text) if isinstance(text, str) else None
    if not m:
        raise UAError('UAIdFormat', repr(text))
    h = m.group(1).lower()
    return '0x' + (h[24:] if len(h) == 64 and h.startswith('0' * 24) else h)


def msig_pqz_eligible(key_data):
    """True when the msig members outside kinds 0x0130-0x0133 weigh less than its threshold (CTR-PQZ-12)."""
    d = _bytes(key_data)
    _need(len(d) >= 4 and len(d) == 4 + 36 * int.from_bytes(d[2:4], 'big'), 'length')
    classical = sum(int.from_bytes(d[o + 34:o + 36], 'big') for o in range(4, len(d), 36)
                    if not 0x0130 <= int.from_bytes(d[o:o + 2], 'big') <= 0x0133)
    return classical < int.from_bytes(d[:2], 'big')


def encode_msig(threshold, members):
    """``u16 threshold ‖ u16 count ‖ count × (u16 kind ‖ bytes32 id ‖ u16 weight)``; members as (kind, id, weight)."""
    out = threshold.to_bytes(2, 'big') + len(members).to_bytes(2, 'big')
    for kind, member_id, weight in members:
        out += kind.to_bytes(2, 'big') + _sized(member_id, 32, 'member id') + weight.to_bytes(2, 'big')
    return out


# ----- key-data validation (accounts.md §1.6 "Validation at registration") -----

SECP_P = 2**256 - 2**32 - 977
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
ED_P = 2**255 - 19
ED_D = (-121665 * pow(121666, -1, ED_P)) % ED_P
ED_SQRT_M1 = pow(2, (ED_P - 1) // 4, ED_P)
BN_P = _bn.field_modulus
BN_R = _bn.curve_order
BLS_P = _bls.field_modulus
BLS_R = _bls.curve_order


def _int(b):
    return int.from_bytes(b, 'big')


def _secp_xy(d):
    x, y = _int(d[:32]), _int(d[32:])
    _need(x < SECP_P and y < SECP_P, 'range')
    _need(y * y % SECP_P == (pow(x, 3, SECP_P) + 7) % SECP_P, 'curve')


def _secp_x(x):
    _need(x < SECP_P, 'range')
    rhs = (pow(x, 3, SECP_P) + 7) % SECP_P
    y = pow(rhs, (SECP_P + 1) // 4, SECP_P)
    _need(y * y % SECP_P == rhs, 'curve')


def _secp_compressed(b):
    _need(b[0] in (2, 3), 'prefix')
    _secp_x(_int(b[1:33]))


def _p256(xy):
    x, y = _int(xy[:32]), _int(xy[32:64])
    _need(x < P256_P and y < P256_P, 'range')
    _need((y * y - (x * x * x - 3 * x + P256_B)) % P256_P == 0, 'curve')


def _ed_add(p, q):
    """Affine twisted Edwards addition, a = −1 (complete for ed25519)."""
    (x1, y1), (x2, y2) = p, q
    t = ED_D * x1 * x2 * y1 * y2 % ED_P
    return ((x1 * y2 + x2 * y1) * pow(1 + t, -1, ED_P) % ED_P, (y1 * y2 + x1 * x2) * pow(1 - t, -1, ED_P) % ED_P)


def _ed25519(b):
    v = int.from_bytes(b, 'little')
    sign, y = v >> 255, v & ((1 << 255) - 1)
    _need(y < ED_P, 'range')
    x2 = (y * y - 1) * pow(ED_D * y * y + 1, -1, ED_P) % ED_P
    x = pow(x2, (ED_P + 3) // 8, ED_P)
    if (x * x - x2) % ED_P:
        x = x * ED_SQRT_M1 % ED_P
    _need((x * x - x2) % ED_P == 0, 'curve')
    _need(not (x == 0 and sign), 'sign')
    if x & 1 != sign:
        x = ED_P - x
    p = (x, y)
    for _ in range(3):
        p = _ed_add(p, p)
    _need(p != (0, 1), 'small-order')


def _bn_g1(b):
    x, y = _int(b[:32]), _int(b[32:64])
    _need(x < BN_P and y < BN_P, 'range')
    _need(x or y, 'identity')
    _need((y * y - x * x * x - 3) % BN_P == 0, 'curve')


def _bn_g2(b):
    xi, xr, yi, yr = (_int(b[32 * i:32 * i + 32]) for i in range(4))
    _need(max(xi, xr, yi, yr) < BN_P, 'range')
    _need(xi or xr or yi or yr, 'identity')
    pt = (_bn.FQ2([xr, xi]), _bn.FQ2([yr, yi]), _bn.FQ2.one())  # EIP-197: imaginary part first
    _need(_bn.is_on_curve(pt, _bn.b2), 'curve')
    _need(_bn.is_inf(_bn.multiply(pt, BN_R)), 'subgroup')


def _bls_fp(b):
    _need(b[:16] == bytes(16), 'padding')
    v = _int(b[16:64])
    _need(v < BLS_P, 'range')
    return v


def _bls_g1(b):
    x, y = _bls_fp(b[:64]), _bls_fp(b[64:128])
    _need(x or y, 'identity')
    pt = (_bls.FQ(x), _bls.FQ(y), _bls.FQ.one())
    _need(_bls.is_on_curve(pt, _bls.b), 'curve')
    _need(_bls.is_inf(_bls.multiply(pt, BLS_R)), 'subgroup')


def _bls_g2(b):
    x0, x1, y0, y1 = (_bls_fp(b[64 * i:64 * i + 64]) for i in range(4))
    _need(x0 or x1 or y0 or y1, 'identity')
    pt = (_bls.FQ2([x0, x1]), _bls.FQ2([y0, y1]), _bls.FQ2.one())  # EIP-2537: c0 first
    _need(_bls.is_on_curve(pt, _bls.b2), 'curve')
    _need(_bls.is_inf(_bls.multiply(pt, BLS_R)), 'subgroup')


def _u16(d, o):
    _need(len(d) >= o + 2, 'length')
    return (d[o] << 8) | d[o + 1]


def _musig2(d, check, size):
    n = _u16(d, size)
    _need(2 <= n <= 16, 'n')
    _need(len(d) == size + 2 + n * size, 'length')
    check(d[:size])
    for i in range(n):
        o = size + 2 + i * size
        check(d[o:o + size])
        if i:
            _need(d[o - size:o] < d[o:o + size], 'order')


def _frost(d, check, size, order):
    t, n = _u16(d, size), _u16(d, size + 2)
    _need(2 <= t <= n <= 16, 'threshold')
    per = (t + 1) * size + 32
    _need(len(d) == size + 4 + n * per, 'length')
    check(d[:size])
    for i in range(n):
        o = size + 4 + i * per
        for j in range(t + 1):  # t commitments, then R_i
            check(d[o + j * size:o + (j + 1) * size])
        _need(_int(d[o + (t + 1) * size:o + per]) < order, 'scalar')


def _msig(d, hedera_native):
    threshold, count = _u16(d, 0), _u16(d, 2)
    _need(1 <= count <= 16, 'count')
    _need(len(d) == 4 + 36 * count, 'length')
    total = 0
    for i in range(count):
        o = 4 + 36 * i
        kind, member_id, weight = _u16(d, o), d[o + 2:o + 34], _u16(d, o + 34)
        _need(is_member(kind, hedera_native), 'member-kind')
        _need(weight >= 1, 'weight')
        _need(is_native(kind) == (member_id[:12] == bytes(12)), 'member-id')
        if i:
            _need(d[o - 34:o - 2] < member_id, 'order')
        total += weight
    _need(1 <= threshold <= total, 'threshold')


def _fndsa(d):
    _need(d[0] == 0x09, 'header')
    bits = int.from_bytes(d[1:], 'big')
    for i in range(512):
        _need((bits >> (896 * 8 - 14 * (i + 1))) & 0x3FFF < 12289, 'coefficient')


def validate_key_data(kind, key_data, hedera_native=False):
    """Raises UAError('UAKeyData') unless key_data is the unique canonical encoding of a valid key or structure."""
    k = _derived(kind)
    d = _bytes(key_data)
    if k[3]:
        _need(len(d) in k[3], 'length')
    if kind == 0x0100:
        _p256(d[:64])
    elif kind == 0x0101:
        _p256(d)
    elif kind == 0x0102:
        _ed25519(d)
    elif kind == 0x0103:
        _secp_x(_int(d))
    elif kind == 0x0104:
        _bn_g1(d)
    elif kind in (0x0105, 0x0141):
        _bls_g1(d)
    elif kind == 0x0106:
        _bls_g2(d)
    elif kind == 0x0107:
        _bn_g2(d)
    elif kind == 0x0108:
        _secp_xy(d)
    elif kind == 0x0110:
        _musig2(d, _secp_compressed, 33)
    elif kind == 0x0111:
        _frost(d, _secp_compressed, 33, SECP_N)
    elif kind == 0x0112:
        _musig2(d, _bn_g1, 64)
    elif kind == 0x0113:
        _frost(d, _bn_g1, 64, BN_R)
    elif kind == 0x0120:
        _msig(d, hedera_native)
    elif kind == 0x0132:
        _fndsa(d)
    # mldsa44/65, slhdsa128s: the length is the whole check
