#!/usr/bin/env python3
"""Sinh `programs/scaas/tests/vectors.rs`: khoá cố định, payload/digest/văn bản/OCMS, chữ ký THẬT (ed25519 raw + OCMS,
passkey WebAuthn P-256 phần mềm, ECDSA tất định RFC 6979, low-S), PDA Account/lane/Mandate/Market/Fill, ATA cả hai
token program — do `dms_blockchain/lib/fam_solana.py` dựng. Vector chéo Python = program = adapter Rust.

    python3 smartcontracts/solana/scripts/gen_vectors.py [--check]
"""
import hashlib
import importlib
import json
import os
import sys
import types

HERE = os.path.dirname(os.path.abspath(__file__))
LIB = os.path.join(HERE, '..', '..', '..', '..', 'dms_blockchain', 'lib')
OUT = os.path.join(HERE, '..', 'programs', 'scaas', 'tests', 'vectors.rs')
_pkg = types.ModuleType('sollib')
_pkg.__path__ = [LIB]            # nạp lib mà không chạy lib/__init__ (kéo Odoo)
sys.modules['sollib'] = _pkg
F = importlib.import_module('sollib.fam_solana')

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, utils  # noqa: E402

PROGRAM = 'BDo6exf1vzqX44BJc1WDf4Pw6sGZcxqmuVmQPfgUgS3d'     # TEST_PROGRAM_ID: chỉ test/localnet (khoá đã công khai)
P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
RP_ID = 'pay.scaas.test'
ORIGIN = 'https://pay.scaas.test'


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


NETWORK = b58(seed('scaas.solana.test-genesis'))
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
OPEN_CHALLENGE = hashlib.sha256(b'scaas.open.v1' + F.key32(PROGRAM) + DAVE).digest()
OPEN_AD, OPEN_CDJ, OPEN_SIG = webauthn(DAVE_SK, OPEN_CHALLENGE)

def relay_fee_vectors():
    """CTR-MTX-27 `ref` của `relay_fee` (spec §7.2, hàng Solana): `call = target ‖ u8 n ‖ (pubkey ‖ is_signer ‖
    is_writable)×n ‖ data`, `ref = keccak256("scaas.relayfee" ‖ network ‖ target ‖ keccak256(call) ‖ salt)` với
    `salt = args.extra` (payer ký trong MetaOp), `lane = keccak256("scaas.pay.lane" ‖ ref)`. Chỉ hashlib + Keccak."""
    from Crypto.Hash import keccak

    def k(b):
        return keccak.new(digest_bits=256, data=b).digest()
    network = seed('scaas.solana.test-genesis')
    target, record = seed('relay_target'), seed('relay_target.record')
    data, salt = b'\x00hello', bytes([9]) * 32
    call = target + bytes([1]) + record + bytes([0, 1]) + data
    ref = k(b'scaas.relayfee' + network + target + k(call) + salt)
    out = [('RELAY_TARGET', target.hex()), ('RELAY_RECORD', record.hex()), ('RELAY_DATA', data.hex()),
           ('RELAY_SALT', salt.hex()), ('RELAY_CALL', call.hex()), ('RELAY_REF', ref.hex()),
           ('RELAY_LANE', k(b'scaas.pay.lane' + ref).hex())]
    # Static wrapper `relay_fee_invalidate_nonces_signed` (owner 2026-10-27): `call` = the inner entry as if sent
    # alone, target = scaas, its declared accounts (lane slot = marker, signer+writable; config, market, subject,
    # min_nonce writable, instructions sysvar, system), data = discriminator ‖ u64 min_nonce ‖ Auth (raw, key 0, precompile 2, entry 0).
    alphabet = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

    def b58d(s):
        n = 0
        for c in s.encode():
            n = n * 58 + alphabet.index(c)
        return n.to_bytes(32, 'big')
    program = b58d(PROGRAM)
    # the lane slot hashes as the router marker, PDA [b"relayfee"] of PROGRAM (pinned in tests/relay_fee.rs)
    metas = [(b58d('9wtnhXbQazahGQXbNLD5ZAERPfzmvFvC2mYwCRjPvT5t'), 1, 1), (seed('wrap.config'), 0, 0), (seed('wrap.market'), 0, 0),
             (seed('wrap.subject'), 0, 0), (seed('wrap.min_nonce'), 0, 1),
             (b58d('Sysvar1nstructions1111111111111111111111111'), 0, 0), (bytes(32), 0, 0)]
    wdata = (hashlib.sha256(b'global:invalidate_nonces_signed').digest()[:8] + (5).to_bytes(8, 'little')
             + bytes([0, 0, 2, 0]) + (0).to_bytes(4, 'little'))
    wcall = program + bytes([len(metas)]) + b''.join(key + bytes([s, w]) for key, s, w in metas) + wdata
    wsalt = bytes([0x0a]) * 32
    wref = k(b'scaas.relayfee' + network + program + k(wcall) + wsalt)
    return out + [('WRAP_CALL', wcall.hex()), ('WRAP_SALT', wsalt.hex()), ('WRAP_REF', wref.hex()),
                  ('WRAP_LANE', k(b'scaas.pay.lane' + wref).hex())]


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
] + relay_fee_vectors()


def render():
    lines = ['//! Sinh bởi `smartcontracts/solana/scripts/gen_vectors.py` — đừng sửa tay. Khoá = sha256(tên); network = sha256(',
             '//! "scaas.solana.test-genesis"); payload: Alice trả Bob 100 USD, pay_ref 01…, lane a1…, nonce 0, hạn 1000.',
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
