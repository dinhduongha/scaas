"""Minimal Ethereum helpers in the Python stdlib (P6f e2e): Keccak-256, RLP, secp256k1 ECDSA (RFC 6979) and legacy
EIP-155 transaction signing. Used because inputs of 300+ KB exceed the 128 KiB single-argument limit of exec, so
`cast keccak` / `cast mktx` cannot take them; test chains only (the keys are throwaway). Self-check: python3 -I eth.py"""
import hashlib
import hmac

# Keccak-256 (FIPS 202 permutation, original padding 0x01)
_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
       0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
       0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M = (1 << 64) - 1


def _f(a):
    for rc in _RC:
        c = [a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4] for x in range(5)]
        d = [c[(x - 1) % 5] ^ (((c[(x + 1) % 5] << 1) | (c[(x + 1) % 5] >> 63)) & _M) for x in range(5)]
        a = [[a[x][y] ^ d[x] for y in range(5)] for x in range(5)]
        b = [[0] * 5 for _ in range(5)]
        for x in range(5):
            for y in range(5):
                r = _ROT[x][y]
                b[y][(2 * x + 3 * y) % 5] = ((a[x][y] << r) | (a[x][y] >> (64 - r))) & _M if r else a[x][y]
        a = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]
        a[0][0] ^= rc
    return a


def keccak256(data: bytes) -> bytes:
    rate = 136
    p = bytearray(data) + b"\x01" + b"\x00" * ((-len(data) - 1) % rate)
    p[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(p), rate):
        blk = p[off:off + rate]
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(blk[8 * i:8 * i + 8], "little")
        a = _f(a)
    return b"".join(a[i % 5][i // 5].to_bytes(8, "little") for i in range(4))


# RLP
def rlp(x):
    if isinstance(x, int):
        x = x.to_bytes((x.bit_length() + 7) // 8, "big") if x else b""
    if isinstance(x, bytes):
        if len(x) == 1 and x[0] < 0x80:
            return x
        return _len(len(x), 0x80) + x
    body = b"".join(rlp(i) for i in x)
    return _len(len(body), 0xC0) + body


def _len(n, off):
    if n < 56:
        return bytes([off + n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([off + 55 + len(b)]) + b


# secp256k1
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    if p[0] == q[0] and (p[1] + q[1]) % P == 0:
        return None
    if p == q:
        l = 3 * p[0] * p[0] * pow(2 * p[1], -1, P) % P
    else:
        l = (q[1] - p[1]) * pow(q[0] - p[0], -1, P) % P
    x = (l * l - p[0] - q[0]) % P
    return x, (l * (p[0] - x) - p[1]) % P


def _mul(k, p=G):
    r = None
    while k:
        if k & 1:
            r = _add(r, p)
        p = _add(p, p)
        k >>= 1
    return r


def address(key: int) -> str:
    x, y = _mul(key)
    return "0x" + keccak256(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[12:].hex()


def _k(key, h):  # RFC 6979 with SHA-256
    x, hb = key.to_bytes(32, "big"), (int.from_bytes(h, "big") % N).to_bytes(32, "big")
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + x + hb, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + x + hb, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        t = int.from_bytes(v, "big")
        if 1 <= t < N:
            return t
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def sign(key: int, h: bytes):
    k = _k(key, h)
    R = _mul(k)
    r = R[0] % N
    s = pow(k, -1, N) * (int.from_bytes(h, "big") + r * key) % N
    rec = R[1] & 1
    if s > N // 2:
        s, rec = N - s, rec ^ 1
    return r, s, rec


def legacy_tx(key: int, nonce: int, gas_price: int, gas: int, to, value: int, data: bytes, chain_id: int) -> bytes:
    """Signed legacy EIP-155 transaction (raw bytes); to = None creates a contract."""
    t = bytes.fromhex(to[2:]) if to else b""
    h = keccak256(rlp([nonce, gas_price, gas, t, value, data, chain_id, 0, 0]))
    r, s, rec = sign(key, h)
    return rlp([nonce, gas_price, gas, t, value, data, chain_id * 2 + 35 + rec, r, s])


if __name__ == "__main__":
    assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
    # the well-known key 1: address 0x7e5f4552091a69125d5dfcb7b8c2659029395bdf
    assert address(1) == "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    # EIP-155 example (chain 1, key 0x4646…46): the spec's signed transaction
    raw = legacy_tx(int("46" * 32, 16), 9, 20 * 10**9, 21000, "0x3535353535353535353535353535353535353535", 10**18, b"", 1)
    assert raw.hex() == ("f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc"
                         "2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"), raw.hex()
    print("eth.py: ok")
