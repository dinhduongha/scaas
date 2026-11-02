#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The vector of `ua8_attest_digest_vector` (ua-registry) and `attest_digest_vector` (scaas-node): `attest_digest` built here by
hand from the XDR definitions, stdlib only, so neither Rust implementation vouches for the other. usage: attest-digest-vector.py"""
import hashlib
import struct


def u32(n):
    return struct.pack(">I", n)


def symbol(s):
    return u32(15) + u32(len(s)) + s.encode() + bytes(-len(s) % 4)


def scbytes(b):
    return u32(13) + u32(len(b)) + b + bytes(-len(b) % 4)


def vec(items):
    return u32(16) + u32(1) + u32(len(items)) + b"".join(items)


def contract(h):
    return u32(18) + u32(1) + h


NETWORK, CONTRACT = bytes([0x11] * 32), bytes([0x22] * 32)  # the contract is CARCEIRC…EVQO, the tests' strkey of 0x22 × 32
ARGS = vec([u32(3) + u32(7), scbytes(bytes([1, 2])), u32(1)])  # U32(7), Bytes(0102), Void
for function in ("register", "set_kem_key"):
    xdr = vec([symbol("scaas_attest_v1"), scbytes(NETWORK), contract(CONTRACT), symbol(function), ARGS])
    print(function, hashlib.sha256(xdr).hexdigest())
