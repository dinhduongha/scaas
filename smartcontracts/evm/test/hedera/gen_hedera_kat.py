#!/usr/bin/env python3
"""Add the ed25519 fields to `test/vectors/hedera_kat.json` (the Hedera vector, NET-HED-03).

    WRITE_KAT=true forge test --match-contract HederaKatTest   # writes the struct, digest (salted MetaTransfer)
    python3 test/hedera/gen_hedera_kat.py                       # from smartcontracts/evm/: signs that digest

RFC 8032 ed25519 over the 32 digest bytes (exactly what HIP-632 `isAuthorizedRaw` checks), key from a fixed seed.
`HederaKatTest` checks the forge fields; scaas-node (`adapters::hedera` tests) checks digest and signature.
"""
import hashlib
import json
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'vectors', 'hedera_kat.json')
SEED = hashlib.sha256(b'scaas.hedera.kat.v1').digest()

with open(PATH) as f:
    kat = json.load(f)
digest = bytes.fromhex(kat['digest'][2:])
sk = Ed25519PrivateKey.from_private_bytes(SEED)
kat['ed25519_seed'] = '0x' + SEED.hex()
kat['ed25519_public_key'] = '0x' + sk.public_key().public_bytes_raw().hex()
kat['ed25519_signature'] = '0x' + sk.sign(digest).hex()
with open(PATH, 'w') as f:
    json.dump(kat, f, indent=2, sort_keys=True)
    f.write('\n')
print(PATH)
