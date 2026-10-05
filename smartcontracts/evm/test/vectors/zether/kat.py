#!/usr/bin/env python3
"""Độc lập với Solidity: sinh vector KAT cho đặc tả 2026-10-03-zether-design.md §3, §4, §11.1.

Chạy (cần py_ecc>=8 cho hash_to_G1): python3 test/vectors/zether/kat.py   (từ smartcontracts/evm/). Ghi generators_*.json, transcript.json,
schnorr_*.json cạnh file này. Forge test (ZetherKat.t.sol) đọc lại và so từng byte với Solidity.
`--check`: không ghi gì, so file đã commit với bản sinh lại (exit 1 nếu lệch).
"""
import hashlib
import json
import os
import sys

from eth_hash.auto import keccak
from py_ecc import optimized_bn128 as bn
from py_ecc import optimized_bls12_381 as bls
from py_ecc.bls.hash_to_curve import hash_to_G1

HERE = os.path.dirname(os.path.abspath(__file__))

BN_P = 21888242871839275222246405745257275088696311157297823662689037894645226208583
BN_R = 21888242871839275222246405745257275088548364400416034343698204186575808495617
BLS_R = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
GEN_DST = b"BAMBOO-ZETHER-GEN-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_"


def be(x, n=32):
    return x.to_bytes(n, "big")


def hx(b):
    return "0x" + b.hex()


# ---------------------------------------------------------------- encodings
def enc_bn(pt):
    if pt is None or bn.is_inf(pt):
        return bytes(64)
    x, y = bn.normalize(pt)
    return be(int(x)) + be(int(y))


def enc_bls(pt):
    if bls.is_inf(pt):
        return bytes(128)
    x, y = bls.normalize(pt)
    return bytes(16) + be(int(x), 48) + bytes(16) + be(int(y), 48)


# ---------------------------------------------------------------- §4
def hash_to_scalar(seed, r):
    hi = int.from_bytes(keccak(seed + b"\x02"), "big")
    lo = int.from_bytes(keccak(seed + b"\x03"), "big")
    return (hi * 2**256 + lo) % r


def t_init():
    return keccak(b"BAMBOO-ZETHER-TRANSCRIPT-V1")


def t_absorb(st, label, data):
    lb = label.encode()
    return keccak(st + b"\x00" + bytes([len(lb)]) + lb + len(data).to_bytes(4, "big") + data)


def t_challenge(st, label, r):
    lb = label.encode()
    st = keccak(st + b"\x01" + bytes([len(lb)]) + lb)
    return st, hash_to_scalar(st, r)


# ---------------------------------------------------------------- §3
def map_to_g1_bn(prefix):
    ctr = 0
    while True:
        x = int.from_bytes(keccak(prefix + ctr.to_bytes(4, "big")), "big") % BN_P
        rhs = (x * x * x + 3) % BN_P
        y = pow(rhs, (BN_P + 1) // 4, BN_P)
        if y * y % BN_P == rhs:
            if y & 1:
                y = BN_P - y
            return be(x) + be(y)
        ctr += 1


def gen_msg(label, index):
    lb = label.encode()
    return bytes([len(lb)]) + lb + index.to_bytes(4, "big")


def gen_bn(label, index):
    return map_to_g1_bn(b"BAMBOO-ZETHER-GEN-BN254-V1" + gen_msg(label, index))


def gen_bls(label, index):
    return enc_bls(hash_to_G1(gen_msg(label, index), GEN_DST, hashlib.sha256))


def generators(curve):
    g = gen_bn if curve == "bn254" else gen_bls
    h, u = g("h", 0), g("U", 0)
    G = [g("G", i) for i in range(64)]
    H = [g("H", i) for i in range(64)]
    blob = h + u + b"".join(G) + b"".join(H)
    psid = keccak(
        b"bamboo/zether/sigma-bullets/bn254/n64-n64/v1" if curve == "bn254"
        else b"bamboo/zether/sigma-bullets/bls12-381/n64-n64/v1")  # n_v = n_b = 64 (RS-NV64-1)
    return {
        "curve": curve, "proofSystemId": hx(psid), "h": hx(h), "U": hx(u),
        "G": [hx(p) for p in G], "H": [hx(p) for p in H], "blobKeccak": hx(keccak(blob)),
    }


# ---------------------------------------------------------------- §11.1
def schnorr(curve, x, k, msg32):
    if curve == "bn254":
        r, enc, mul, G = BN_R, enc_bn, bn.multiply, bn.G1
    else:
        r, enc, mul, G = BLS_R, enc_bls, bls.multiply, bls.G1
    Y = enc(mul(G, x))
    R = enc(mul(G, k))
    e = hash_to_scalar(keccak(b"BAMBOO-ZETHER-SCHNORR-V1" + R + Y + msg32), r)
    z = (k + e * x) % r
    return {"x": hx(be(x)), "Y": hx(Y), "msg": hx(msg32), "k": hx(be(k)), "R": hx(R),
            "e": hx(be(e)), "z": hx(be(z)), "sig": hx(R + be(z))}


def transcript_cases():
    cases = []
    for curve, r in (("bn254", BN_R), ("bls12381", BLS_R)):
        st = t_init()
        ops, states, chals = [], [], []
        for kind, label, data in (
            ("absorb", "statement", bytes(range(200))),
            ("absorb", "sigma.commit", b""),
            ("challenge", "sigma.c", None),
            ("absorb", "bp.AS", (32).to_bytes(4, "big") + b"\x11" * 128),
            ("challenge", "bp.y", None),
            ("challenge", "bp.z", None),
        ):
            if kind == "absorb":
                st = t_absorb(st, label, data)
                ops.append({"absorb": label, "data": hx(data)})
            else:
                st, c = t_challenge(st, label, r)
                ops.append({"challenge": label})
                chals.append(hx(be(c)))
            states.append(hx(st))
        cases.append({"curve": curve, "init": hx(t_init()), "ops": ops, "states": states, "challenges": chals})
    seeds = [bytes(32), b"\xff" * 32, keccak(b"bamboo")]
    h2s = [{"seed": hx(s), "bn254": hx(be(hash_to_scalar(s, BN_R))),
            "bls12381": hx(be(hash_to_scalar(s, BLS_R)))} for s in seeds]
    return {"cases": cases, "hashToScalar": h2s}


def bls_non_subgroup():
    """Điểm trên y² = x³ + 4 nhưng NGOÀI subgroup bậc r (không clear cofactor)."""
    p = bls.field_modulus
    x = 5
    while True:
        rhs = (x ** 3 + 4) % p
        y = pow(rhs, (p + 1) // 4, p)
        if y * y % p == rhs:
            pt = (bls.FQ(x), bls.FQ(y), bls.FQ(1))
            if not bls.is_inf(bls.multiply(pt, BLS_R)):
                return enc_bls(pt)
        x += 1


def bn254_g2_pubkey(sk):
    """[sk]G2 trên bn254, thứ tự EIP-197: x_im, x_re, y_im, y_re."""
    x, y = bn.normalize(bn.multiply(bn.G2, sk))
    return be(int(x.coeffs[1])) + be(int(x.coeffs[0])) + be(int(y.coeffs[1])) + be(int(y.coeffs[0]))


CHECK = "--check" in sys.argv
STALE = []


def dump(name, obj):
    text = json.dumps(obj, indent=1) + "\n"
    path = os.path.join(HERE, name)
    if CHECK:
        with open(path) as f:
            if f.read() != text:
                STALE.append(name)
        return
    with open(path, "w") as f:
        f.write(text)


if __name__ == "__main__":
    dump("generators_bn254.json", generators("bn254"))
    dump("generators_bls12381.json", generators("bls12381"))
    dump("transcript.json", transcript_cases())
    msg = keccak(b"bamboo zether schnorr kat")
    dump("schnorr_bn254.json", schnorr("bn254", 0x1234567890abcdef, 0xfeedface, msg))
    dump("schnorr_bls12381.json", schnorr("bls12381", 0x1234567890abcdef, 0xfeedface, msg))
    dump("curve_misc.json", {"blsNonSubgroup": hx(bls_non_subgroup()),
                             "bn254G2Sk": hx(be(0xB15B254)), "bn254G2Pk": hx(bn254_g2_pubkey(0xB15B254))})
    if STALE:
        sys.exit("stale: " + ", ".join(STALE))
    print("ok")
