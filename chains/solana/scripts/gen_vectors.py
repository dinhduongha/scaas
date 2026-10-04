#!/usr/bin/env python3
"""Sinh `programs/bamboo/tests/vectors.rs`: khoá cố định, payload/digest/văn bản/OCMS, chữ ký THẬT (ed25519 raw + OCMS,
passkey WebAuthn P-256 phần mềm, ECDSA tất định RFC 6979, low-S), PDA Account/lane/Mandate/Market/Fill, ATA cả hai
token program — do `dms_blockchain/lib/fam_solana.py` dựng. Vector chéo Python = program = adapter Rust.

    python3 chains/solana/scripts/gen_vectors.py [--check]
"""
import hashlib
import importlib
import json
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, '..', '..', '..', 'dms_blockchain', 'lib')
OUT = os.path.join(HERE, '..', 'programs', 'bamboo', 'tests', 'vectors.rs')
_pkg = types.ModuleType('sollib')
_pkg.__path__ = [LIB]            # nạp lib mà không chạy lib/__init__ (kéo Odoo)
sys.modules['sollib'] = _pkg
F = importlib.import_module('sollib.fam_solana')

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils  # noqa: E402

PROGRAM = 'BDo6exf1vzqX44BJc1WDf4Pw6sGZcxqmuVmQPfgUgS3d'     # chains/solana/keys/bamboo-dev.json (chỉ dev)
P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
RP_ID = 'pay.bamboo.test'
ORIGIN = 'https://pay.bamboo.test'


def seed(name):
    return hashlib.sha256(name.encode()).digest()


def ed(name):
    sk = ed25519.Ed25519PrivateKey.from_private_bytes(seed(name))
    return sk, sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def p256(name):
    sk = ec.derive_private_key(int.from_bytes(seed(name), 'big') % P256_N, ec.SECP256R1())
    return sk, sk.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)


def b58(b):
    return F.b58encode(b)


NETWORK = b58(seed('bamboo.solana.test-genesis'))
ALICE_SK, ALICE = ed('alice')
BOB_SK, BOB = ed('bob')
DELEGATE_SK, DELEGATE = ed('delegate')
LANE_SK, LANE = ed('lane0')
DAVE_SK, DAVE = p256('dave')
USD = b58(ed('mint-usd')[1])
EUR = b58(ed('mint-eur')[1])
ALICE_ACCOUNT = F.account_of(PROGRAM, ALICE)
DAVE_OWNER = F.p256_owner(DAVE)
DAVE_ACCOUNT = F.account_of(PROGRAM, DAVE_OWNER)
PAY_REF = bytes([1]) * 32
LANE_ID = bytes([0xa1]) * 32
VU = 1000
PAYLOAD = F.metaop_bytes(NETWORK, ALICE_ACCOUNT, USD, F.OP_PAY, ALICE, BOB, 100, PAY_REF, LANE_ID, 0, VU)
DIGEST = F.digest(PAYLOAD)
TEXT = F.text(DIGEST)
OCMS = F.ocms(ALICE, TEXT)
SIG_RAW = ALICE_SK.sign(TEXT)
SIG_OCMS = ALICE_SK.sign(OCMS)
MARKET = F.market_of(PROGRAM, USD, EUR)
ORDER_HASH = hashlib.sha256(b'order').digest()


def webauthn(sk, challenge, origin=ORIGIN, flags=5):
    ad = hashlib.sha256(RP_ID.encode()).digest() + bytes([flags]) + (7).to_bytes(4, 'big')
    cdj = json.dumps({'type': 'webauthn.get', 'challenge': F.b64url(challenge).decode(), 'origin': origin,
                      'crossOrigin': False}, separators=(',', ':')).encode()
    der = sk.sign(ad + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
    r, s = utils.decode_dss_signature(der)
    s = min(s, P256_N - s)
    return ad, cdj, r.to_bytes(32, 'big') + s.to_bytes(32, 'big')


DAVE_PAYLOAD = F.metaop_bytes(NETWORK, DAVE_ACCOUNT, USD, F.OP_PAY, DAVE_OWNER, BOB, 100, PAY_REF, LANE_ID, 0, VU)
DAVE_AD, DAVE_CDJ, DAVE_SIG = webauthn(DAVE_SK, F.digest(DAVE_PAYLOAD))
OPEN_CHALLENGE = hashlib.sha256(b'bamboo.open.v1' + F.key32(PROGRAM) + DAVE).digest()
OPEN_AD, OPEN_CDJ, OPEN_SIG = webauthn(DAVE_SK, OPEN_CHALLENGE)

VECTORS = [
    ('PROGRAM', PROGRAM), ('NETWORK', NETWORK),
    ('ALICE', b58(ALICE)), ('BOB', b58(BOB)), ('DELEGATE', b58(DELEGATE)), ('LANE', b58(LANE)),
    ('USD', USD), ('EUR', EUR),
    ('ALICE_ACCOUNT', ALICE_ACCOUNT),
    ('ALICE_LANE_PDA', F.lane_pda(PROGRAM, ALICE_ACCOUNT, LANE_ID)),
    ('ALICE_MANDATE', F.mandate_of(PROGRAM, ALICE_ACCOUNT, bytes([0x0d]) * 32)),
    ('MARKET', MARKET), ('FILL', F.fill_of(PROGRAM, MARKET, ORDER_HASH)),
    ('BOB_ATA_USD', F.ata(b58(BOB), USD)),
    ('ALICE_ACCOUNT_ATA_EUR_2022', F.ata(ALICE_ACCOUNT, EUR, F.TOKEN_2022)),
    ('PAYLOAD', PAYLOAD.hex()), ('DIGEST', DIGEST.hex()), ('TEXT', TEXT.decode()), ('OCMS', OCMS.hex()),
    ('SIG_RAW', SIG_RAW.hex()), ('SIG_OCMS', SIG_OCMS.hex()),
    ('BLOB_RAW', (bytes([F.KIND_RAW, 0]) + SIG_RAW).hex()),
    ('DAVE_PK', DAVE.hex()), ('DAVE_OWNER', DAVE_OWNER), ('DAVE_ACCOUNT', DAVE_ACCOUNT),
    ('DAVE_PAYLOAD', DAVE_PAYLOAD.hex()),
    ('DAVE_AUTH_DATA', DAVE_AD.hex()), ('DAVE_CDJ', DAVE_CDJ.decode()), ('DAVE_SIG', DAVE_SIG.hex()),
    ('DAVE_BLOB', F.passkey_blob(0, DAVE_SIG, DAVE_AD, DAVE_CDJ).hex()),
    ('OPEN_AUTH_DATA', OPEN_AD.hex()), ('OPEN_CDJ', OPEN_CDJ.decode()), ('OPEN_SIG', OPEN_SIG.hex()),
]


def render():
    lines = ['//! Sinh bởi `chains/solana/scripts/gen_vectors.py` — đừng sửa tay. Khoá = sha256(tên); network = sha256(',
             '//! "bamboo.solana.test-genesis"); payload: Alice trả Bob 100 USD, pay_ref 01…, lane a1…, nonce 0, hạn 1000.',
             '#![allow(dead_code)]', '']
    for name, value in VECTORS:
        lines.append('pub const %s: &str = %s;' % (name, json.dumps(value)))
    return '\n'.join(lines) + '\n'


if __name__ == '__main__':
    text = render()
    if '--check' in sys.argv:
        with open(OUT) as f:
            same = f.read() == text
        print('vectors.rs up to date' if same else 'vectors.rs differs from the generator')
        sys.exit(0 if same else 1)
    with open(OUT, 'w') as f:
        f.write(text)
    print('wrote', OUT)
