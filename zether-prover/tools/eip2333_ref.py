# Independent reference for EIP-2333 (and its bn254 variant), stdlib only.
import hashlib, hmac, sys

R_BLS = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001
R_BN = 21888242871839275222246405745257275088548364400416034343698204186575808495617

def extract(salt, ikm): return hmac.new(salt, ikm, hashlib.sha256).digest()
def expand(prk, info, L):
    out, t, i = b"", b"", 1
    while len(out) < L:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest(); out += t; i += 1
    return out[:L]

def hkdf_mod_r(ikm, salt0, r, key_info=b""):
    salt, sk = salt0, 0
    while sk == 0:
        salt = hashlib.sha256(salt).digest()
        okm = expand(extract(salt, ikm + b"\x00"), key_info + (48).to_bytes(2, "big"), 48)
        sk = int.from_bytes(okm, "big") % r
    return sk

def lamport(ikm, salt): return expand(extract(salt, ikm), b"", 255 * 32)

def child(parent, idx, salt0, r):
    salt = idx.to_bytes(4, "big"); ikm = parent.to_bytes(32, "big")
    l0 = lamport(ikm, salt); l1 = lamport(bytes(b ^ 0xff for b in ikm), salt)
    pk = b"".join(hashlib.sha256(c[i:i+32]).digest() for c in (l0, l1) for i in range(0, len(c), 32))
    return hkdf_mod_r(hashlib.sha256(pk).digest(), salt0, r)

def path(seed, comps, salt0, r):
    sk = hkdf_mod_r(seed, salt0, r)
    for c in comps: sk = child(sk, c, salt0, r)
    return sk

if __name__ == "__main__":
    BLS = (b"BLS-SIG-KEYGEN-SALT-", R_BLS); BN = (b"BAMBOO-ZETHER-BN254-v1", R_BN)
    # sanity: published EIP-2333 case 0
    s0 = bytes.fromhex("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04")
    assert path(s0, [0], *BLS) == 20397789859736650942317412262472558107875392172444076792671091975210932703118
    seeds = [("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04", 0),
             ("3141592653589793238462643383279502884197169399375105820974944592", 3141592653),
             ("0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00", 4294967295),
             ("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3", 42)]
    for s, i in seeds:
        sd = bytes.fromhex(s); m = path(sd, [], *BN)
        print(f'("{s}", "{m}", {i}, "{child(m, i, *BN)}"),')
    abandon = bytes.fromhex("408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840")
    print("bn254 m/254/60/0/7", hex(path(abandon, [254, 60, 0, 7], *BN)))
    print("bls m/12381/60/0/7", hex(path(abandon, [12381, 60, 0, 7], *BLS)))
