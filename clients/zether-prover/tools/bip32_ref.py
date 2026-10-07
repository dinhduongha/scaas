import hashlib, hmac
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
def add(a, b):
    if a is None: return b
    if b is None: return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0: return None
    l = (3*a[0]*a[0]*pow(2*a[1], -1, P)) % P if a == b else ((b[1]-a[1])*pow(b[0]-a[0], -1, P)) % P
    x = (l*l - a[0] - b[0]) % P
    return (x, (l*(a[0]-x) - a[1]) % P)
def mul(k, p=G):
    r = None
    while k:
        if k & 1: r = add(r, p)
        p = add(p, p); k >>= 1
    return r
def ser(p): return bytes([2 + (p[1] & 1)]) + p[0].to_bytes(32, "big")
def derive(seed, path):
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest(); k, c = int.from_bytes(I[:32], "big"), I[32:]
    for i in path:
        data = (b"\x00" + k.to_bytes(32, "big") if i >= 2**31 else ser(mul(k))) + i.to_bytes(4, "big")
        I = hmac.new(c, data, hashlib.sha512).digest(); k, c = (int.from_bytes(I[:32], "big") + k) % N, I[32:]
    return k
H = 2**31
twelve = hashlib.pbkdf2_hmac("sha512", (" ".join(["abandon"]*11 + ["about"])).encode(), b"mnemonic", 2048)
print("12w", hex(derive(twelve, [44+H, 60+H, H, 0, 0])))
s = bytes.fromhex("408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840")
print("24w", hex(derive(s, [44+H, 60+H, H, 0, 0])))
