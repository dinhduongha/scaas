"""Shared helpers of the NEAR and Algorand vector generators (near-algorand plan Task 3).

Stdlib plus the `cryptography` package (ed25519 signing, and every ECDSA signature verified by it). Keccak-256 and
ECDSA signing (RFC 6979, low-s, recovery id) are written here, so the output is deterministic and runs under
`python3 -I` (pycryptodome is not needed). Keccak is checked against hashlib's SHA3 permutation, a known answer and
every `paymeta.json` row (EVM-computed); ECDSA against `cryptography`'s verifier and an independent key recovery.

Imported by `smartcontracts/near/scripts/gen_vectors.py` and `smartcontracts/algorand/scripts/gen_vectors.py`.
"""
import base64
import hashlib
import hmac
import json
import os
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils

REPO = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..'))
PAYMETA = os.path.join(REPO, 'smartcontracts', 'vectors', 'metatx', 'paymeta.json')
KINDS = os.path.join(REPO, 'smartcontracts', 'vectors', 'ua', 'kinds.json')
WEBAUTHN_SOFT = os.path.join(REPO, 'smartcontracts', 'evm', 'test', 'vectors', 'webauthn_soft.json')

LABEL = b'scaas.metaop.v1'
ZERO32 = bytes(32)
U128_MAX = 2**128 - 1
RP_ID = 'pay.scaas.test'
ORIGIN = 'https://pay.scaas.test'

# MetaOp.op (plan "Shared decisions", controller call 2026-10-28; codes 0–3 as built in the other families). `owner`
# = the tasks that define the op's parameter struct and add its `extra` vectors (NEAR task / Algorand task).
OP_CODES = [
    (0, 'pay', ['mtx_pay', 'mtx_pay_meta'], 'payer-chosen: zero in a plain pay; the relay-fee salt (CTR-MTX-27, §2 row 8)', 'T6 / T11'),
    (1, 'trade', ['mtx_trade'], 'sha256(encoding of Order)', 'T8 / T14'),
    (2, 'mandate_pay', ['mtx_mandate_pay'], 'sha256(encoding of the op parameters)', 'T7 / T13'),
    (3, 'revoke', ['mtx_revoke'], 'sha256(encoding of the op parameters)', 'T7 / T13'),
    (4, 'transfer', ['mtx_transfer'], 'payer-chosen (not a parameter binding)', 'T6 / T11'),
    (5, 'execute_transfer', ['mtx_execute_transfer'], 'payer-chosen (not a parameter binding)', 'T6 / T11'),
    (6, 'add_key', ['mtx_add_key'], 'sha256(encoding of the op parameters)', 'T5 / T12'),
    (7, 'remove_key', ['mtx_remove_key'], 'sha256(encoding of the op parameters)', 'T5 / T12'),
    (8, 'add_origin', ['mtx_add_origin'], 'sha256(encoding of the op parameters)', 'T5 / T12'),
    (9, 'remove_origin', ['mtx_remove_origin'], 'sha256(encoding of the op parameters)', 'T5 / T12'),
    (10, 'set_guardian', ['mtx_set_guardian'], 'sha256(encoding of the op parameters)', 'T5 / T12'),
    (11, 'start_recovery', ['mtx_start_recovery'], 'sha256(encoding of the op parameters)', 'T5 / T12'),
    (12, 'cancel_recovery', ['mtx_cancel_recovery'], 'sha256(encoding of the op parameters)', 'T5 / T12'),
    (13, 'mandate_open', ['mtx_mandate_open'], 'sha256(encoding of the op parameters)', 'T7 / T13'),
    (14, 'cancel', ['mtx_cancel'], 'sha256(encoding of the op parameters)', 'T8 / T14'),
    (15, 'invalidate_nonces', ['mtx_invalidate_nonces'], 'sha256(encoding of the op parameters)', 'T8 / T14'),
]
OP = {name: code for code, name, *_ in OP_CODES}


def op_codes(encoding):
    return [{'code': c, 'name': n, 'entries': e, 'extra': x.replace('encoding', encoding), 'owner': o}
            for c, n, e, x, o in OP_CODES]


def hx(b):
    return '0x' + b.hex()


def unhx(s):
    return bytes.fromhex(s[2:] if s.startswith('0x') else s)


def seed(name):
    return hashlib.sha256(name.encode()).digest()


def sha256(*parts):
    return hashlib.sha256(b''.join(parts)).digest()


def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


# ---------------------------------------------------------------- Keccak-256 (rate 136, pad 0x01)
_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
       0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
       0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M64 = 2**64 - 1


def _keccak_f(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[x - 1] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & _M64) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                r = _ROT[x][y]
                b[y][(2 * x + 3 * y) % 5] = ((a[x][y] << r) | (a[x][y] >> (64 - r))) & _M64 if r else a[x][y]
        a = [[b[x][y] ^ (~b[(x + 1) % 5][y] & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def _sponge(data, pad, rate=136):
    msg = bytearray(data) + bytes([pad])
    msg += bytes(-len(msg) % rate)
    msg[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(msg[off + 8 * i:off + 8 * i + 8], 'little')
        a = _keccak_f(a)
    return b''.join(a[i % 5][i // 5].to_bytes(8, 'little') for i in range(25))[:32]


def keccak256(*parts):
    return _sponge(b''.join(parts), 0x01)


# ---------------------------------------------------------------- CTR-MTX-26 / -27 derivations (EVM byte-for-byte)
def meta_pay_id(salt, meta):
    return keccak256(b'scaas.pay.meta', salt, keccak256(meta))


def pay_lane(p):
    return keccak256(b'scaas.pay.lane', p)


def relay_ref(network, target, call, salt):
    """`keccak256("scaas.relayfee" ‖ network ‖ target ‖ keccak256(call) ‖ salt)`, salt = the payment op's `extra`."""
    return keccak256(b'scaas.relayfee', network, target, keccak256(call), salt)


def paymeta_rows():
    """Every `paymeta.json` row with `payId` / `payLane` recomputed and asserted equal to the file."""
    rows = json.load(open(PAYMETA))
    for r in rows:
        pid = meta_pay_id(unhx(r['salt']), unhx(r['meta']))
        assert hx(pid) == r['payId'] and hx(pay_lane(pid)) == r['payLane'], r['name']
    return rows


# ---------------------------------------------------------------- UA ids (kinds.json)
KIND_WEBAUTHN_P256, KIND_ED25519, KIND_SECP256K1 = 0x0100, 0x0102, 0x0108
_KINDS = json.load(open(KINDS))


def ua_of(kind, key_data):
    """`keccak256(TAG(kind) ‖ keyData)`, TAG = keccak256 of the kind's tag string (kinds.json)."""
    k = next(k for k in _KINDS['kinds'] if k['kind'] == kind)
    assert hx(keccak256(k['tag'].encode())) == k['TAG']
    return keccak256(unhx(k['TAG']), key_data)


# ---------------------------------------------------------------- keys
class Ed:
    def __init__(self, name):
        self.name = name
        self.sk = ed25519.Ed25519PrivateKey.from_private_bytes(seed(name))
        self.pk = self.sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def sign(self, msg):
        sig = self.sk.sign(msg)
        self.sk.public_key().verify(sig, msg)
        return sig


class Curve:
    def __init__(self, p, a, b, n, gx, gy, crypto):
        self.p, self.a, self.b, self.n, self.G, self.crypto = p, a, b, n, (gx, gy), crypto

    def add(self, P, Q):
        if P is None:
            return Q
        if Q is None:
            return P
        p = self.p
        if P[0] == Q[0] and (P[1] + Q[1]) % p == 0:
            return None
        if P == Q:
            m = (3 * P[0] * P[0] + self.a) * pow(2 * P[1], -1, p) % p
        else:
            m = (Q[1] - P[1]) * pow(Q[0] - P[0], -1, p) % p
        x = (m * m - P[0] - Q[0]) % p
        return x, (m * (P[0] - x) - P[1]) % p

    def mul(self, k, P):
        R = None
        while k:
            if k & 1:
                R = self.add(R, P)
            P = self.add(P, P)
            k >>= 1
        return R


SECP256K1 = Curve(2**256 - 2**32 - 977, 0, 7, 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141,
                  0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,
                  0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8, ec.SECP256K1)
P256 = Curve(2**256 - 2**224 + 2**192 + 2**96 - 1, -3,
             0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
             0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
             0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
             0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5, ec.SECP256R1)


def _rfc6979_k(d, z, n):
    """RFC 6979 §3.2 with HMAC-SHA256 for a 256-bit order and a 32-byte hash."""
    x, h = d.to_bytes(32, 'big'), (int.from_bytes(z, 'big') % n).to_bytes(32, 'big')
    K, V = bytes(32), b'\x01' * 32
    K = hmac.new(K, V + b'\x00' + x + h, 'sha256').digest()
    V = hmac.new(K, V, 'sha256').digest()
    K = hmac.new(K, V + b'\x01' + x + h, 'sha256').digest()
    V = hmac.new(K, V, 'sha256').digest()
    while True:
        V = hmac.new(K, V, 'sha256').digest()
        k = int.from_bytes(V, 'big')
        if 1 <= k < n:
            return k
        K = hmac.new(K, V + b'\x00', 'sha256').digest()
        V = hmac.new(K, V, 'sha256').digest()


class Ecdsa:
    """A deterministic key on `curve`; `sign(z)` signs the 32-byte hash `z` itself (raw-digest form)."""

    def __init__(self, name, curve):
        self.name, self.c = name, curve
        self.d = int.from_bytes(seed(name), 'big') % curve.n
        self.Q = curve.mul(self.d, curve.G)
        self.key = self.Q[0].to_bytes(32, 'big') + self.Q[1].to_bytes(32, 'big')   # x ‖ y

    def sign(self, z):
        """(r ‖ s, v) with s low and v = the recovery id (parity of R.y, flipped with s)."""
        c, e = self.c, int.from_bytes(z, 'big') % self.c.n
        k = _rfc6979_k(self.d, z, c.n)
        R = c.mul(k, c.G)
        assert R[0] < c.n
        r = R[0]
        s = pow(k, -1, c.n) * (e + r * self.d) % c.n
        v = R[1] & 1
        if s > c.n // 2:
            s, v = c.n - s, v ^ 1
        assert s <= c.n // 2
        self.verify(z, r, s)
        assert recover(c, z, r, s, v) == self.key
        return r.to_bytes(32, 'big') + s.to_bytes(32, 'big'), v

    def verify(self, z, r, s):
        pub = ec.EllipticCurvePublicNumbers(self.Q[0], self.Q[1], self.c.crypto()).public_key()
        pub.verify(utils.encode_dss_signature(r, s), z, ec.ECDSA(utils.Prehashed(hashes.SHA256())))


def recover(c, z, r, s, v):
    """Public key x ‖ y from (z, r, s, v): Q = r⁻¹ (sR − zG)."""
    x = r
    y = pow((x * x * x + c.a * x + c.b) % c.p, (c.p + 1) // 4, c.p)
    if y & 1 != v:
        y = c.p - y
    e = int.from_bytes(z, 'big') % c.n
    sR = c.mul(s, (x, y))
    zG = c.mul(c.n - e, c.G) if e else None
    Q = c.mul(pow(r, -1, c.n), c.add(sR, zG))
    return Q[0].to_bytes(32, 'big') + Q[1].to_bytes(32, 'big')


def high_s(sig, v, curve):
    """The malleated (high-s) form of a low-s signature: every verifier must refuse it."""
    s = int.from_bytes(sig[32:], 'big')
    return sig[:32] + (curve.n - s).to_bytes(32, 'big'), v ^ 1


def passkey(key, digest, origin=ORIGIN, flags=5):
    """A WebAuthn assertion over challenge = b64url(digest) (NET-ALL-04): authenticatorData = rpIdHash ‖ flags ‖
    counter 0; P-256 over sha256(authData ‖ sha256(clientDataJSON)), low-s, RFC 6979."""
    ad = sha256(RP_ID.encode()) + bytes([flags]) + bytes(4)
    cdj = json.dumps({'type': 'webauthn.get', 'challenge': b64url(digest), 'origin': origin, 'crossOrigin': False},
                     separators=(',', ':')).encode()
    sig, _ = key.sign(sha256(ad, sha256(cdj)))
    # independent check: cryptography hashes the message itself
    pub = ec.EllipticCurvePublicNumbers(key.Q[0], key.Q[1], ec.SECP256R1()).public_key()
    pub.verify(utils.encode_dss_signature(int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big')),
               ad + sha256(cdj), ec.ECDSA(hashes.SHA256()))
    return {'kind': 'passkey', 'key': hx(key.key), 'rpId': RP_ID, 'rpIdHash': hx(sha256(RP_ID.encode())),
            'origin': origin, 'authenticatorData': hx(ad), 'clientDataJSON': cdj.decode(), 'sig': hx(sig),
            'sigHighS': hx(high_s(sig, 0, P256)[0])}


def webauthn_soft():
    """`webauthn_soft.json` (the EVM software-authenticator vector) re-encoded as key 64 ‖ sig 64 (low s), verified."""
    w = json.load(open(WEBAUTHN_SOFT))
    r, s = utils.decode_dss_signature(unhx(w['signatureDer']))
    s = min(s, P256.n - s)
    key = unhx(w['qx']) + unhx(w['qy'])
    ad, cdj = unhx(w['authenticatorData']), w['clientDataJSON'].encode()
    pub = ec.EllipticCurvePublicNumbers(int.from_bytes(key[:32], 'big'), int.from_bytes(key[32:], 'big'),
                                        ec.SECP256R1()).public_key()
    pub.verify(utils.encode_dss_signature(r, s), ad + sha256(cdj), ec.ECDSA(hashes.SHA256()))
    assert json.loads(cdj)['challenge'] == b64url(unhx(w['challenge']))
    return {'source': 'smartcontracts/evm/test/vectors/webauthn_soft.json', 'key': hx(key), 'rpId': w['rpId'],
            'rpIdHash': hx(sha256(w['rpId'].encode())), 'origin': w['origin'], 'challenge': w['challenge'],
            'authenticatorData': w['authenticatorData'], 'clientDataJSON': w['clientDataJSON'],
            'sig': hx(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}


def text(digest):
    """The signed text, NET-ALL-23 first build: `"scaas.metaop.v1:" ‖ hex(digest)`."""
    return LABEL + b':' + digest.hex().encode()


# ---------------------------------------------------------------- self-test of the primitives
def selftest_primitives():
    # Keccak: the permutation with SHA3's padding equals hashlib's SHA3-256; a known Keccak-256 answer
    for m in (b'', b'abc', bytes(range(256)) * 3):
        assert _sponge(m, 0x06) == hashlib.sha3_256(m).digest()
    assert keccak256(b'').hex() == 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
    paymeta_rows()
    # ua_of reproduces every kinds.json `valid` row of the three signing kinds used here
    rows = [r for r in _KINDS['valid'] if r['kind'] in (KIND_WEBAUTHN_P256, KIND_ED25519, KIND_SECP256K1)]
    assert rows
    for r in rows:
        assert hx(ua_of(r['kind'], unhx(r['keyData']))) == r['ua'], r
    # RFC 6979 A.2.5 (P-256, SHA-256, "sample"): k and r
    k = _rfc6979_k(0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721, sha256(b'sample'), P256.n)
    assert k == 0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60
    assert P256.mul(k, P256.G)[0] == 0xEFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716
    # ECDSA: the generators' points are on their curves and of order n
    for c in (SECP256K1, P256):
        x, y = c.G
        assert (y * y - x * x * x - c.a * x - c.b) % c.p == 0 and c.mul(c.n, c.G) is None


def emit(out, data, argv):
    """Write `out`, or with `--check` exit 1 when it is missing or differs (drift)."""
    text_ = json.dumps(data, indent=1, ensure_ascii=False) + '\n'
    if '--check' in argv:
        if not os.path.exists(out):
            sys.exit('%s missing: run the generator' % os.path.relpath(out, REPO))
        if open(out, encoding='utf-8').read() != text_:
            sys.exit('%s is stale: re-run the generator' % os.path.relpath(out, REPO))
        print('ok', os.path.relpath(out, REPO))
        return
    os.makedirs(os.path.dirname(out), exist_ok=True)
    open(out, 'w', encoding='utf-8').write(text_)
    print('wrote', os.path.relpath(out, REPO))
