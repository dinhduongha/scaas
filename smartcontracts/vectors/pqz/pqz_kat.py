#!/usr/bin/env python3
"""Independent PQZ KAT (pq-zether.md §4, §5, §7; P6e plan Task 4). Python 3 stdlib only (hashlib SHAKE, an own
Keccak-256 checked against hashlib's SHA3 permutation): no numpy, no third-party package, runs under `python3 -I`.

Implements everything of PQZL except the proofs: the matrix A (SHAKE128 "SCAAS-PQZ-A-V2"), CBD, KeyGen, Enc, Dec,
Add / Sub / Trivial, digits, the opTags and both proofSystemIds, every statement layout (build and parse, with the
canonical-encoding rules of the plan's D15 / R6), ctHash, authDigest, the bundle and opening encodings, entryRef.

  pqz_kat.py --check [vector.json ...]   self-test, then recompute every non-proof field of every vector file
                                         (default: every *.json next to this script); exit 1 on any drift
  pqz_kat.py --c-keys run.jsonl          compare the C core's keys KAT (pqz-core test/pqz_keys_kat.c output:
                                         SHAKE256, KeyGen, Enc, Dec) with this implementation; exit 1 on any drift

A vector file without a checker here is a failure: the generator (P6e Task 11) adds the file and its checker
together. Public data only: nothing here is constant-time.
"""
import glob
import hashlib
import json
import os
import sys

Q = 2**42 - 215
D = 64
K = 32
N = D * K  # 2048
DELTA = 2**26 - 1
B_S, B_E, B_2 = 36, 164, 64
B_FRESH = B_E * B_S + B_S * B_E + B_2  # 11,872 (§4.3)
PK_BYTES = 16384
V_BYTES = 128
CT_BYTES = PK_BYTES + V_BYTES
HEADER_BYTES = 640
HEADER = ["opTag", "proofSystemId", "chainId", "token", "registry", "fromUA", "toUA", "beneficiaryUA", "fee",
          "amount", "recipient", "sendCounter", "p", "validUntilBlock", "auditorOn", "plainUsed", "chainUid",
          "envelopeBinding", "salt", "memoHash"]  # §7.7, 32-byte words
DISC = ["opTag", "proofSystemId", "chainId", "chainUid", "token", "registry", "entryRef", "amount", "kind"]  # §7.9

# ---------------------------------------------------------------- Keccak-256 (rate 136, pad 0x01)
_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000, 0x000000000000808B,
       0x0000000080000001, 0x8000000080008081, 0x8000000000008009, 0x000000000000008A, 0x0000000000000088,
       0x0000000080008009, 0x000000008000000A, 0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M64 = 2**64 - 1


def _keccak_f(a):  # a[x][y], 64-bit lanes
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


def _sponge(data, pad, rate=136, out=32):
    msg = bytearray(data) + bytes([pad])
    msg += bytes(-len(msg) % rate)
    msg[-1] |= 0x80
    a = [[0] * 5 for _ in range(5)]
    for off in range(0, len(msg), rate):
        for i in range(rate // 8):
            a[i % 5][i // 5] ^= int.from_bytes(msg[off + 8 * i:off + 8 * i + 8], "little")
        a = _keccak_f(a)
    return b"".join(a[i % 5][i // 5].to_bytes(8, "little") for i in range(25))[:out]


def keccak256(*parts):
    return _sponge(b"".join(parts), 0x01)


def shake128(data, n):
    return hashlib.shake_128(data).digest(n)


def shake256(data, n):
    return hashlib.shake_256(data).digest(n)


# ---------------------------------------------------------------- ids, tags (§5, CTR-PQZ-09, P6e D2 / D3)
PQZL_ID = keccak256(b"scaas/pqz/lnp22/mlwe-d64k32-q42l4/v2")
PQZH_ID = keccak256(b"scaas/pqz/pqzh/ligero-fq-r431-keccak256-zk-proven/v1")
OP_NAMES = ["TRANSFER", "BURN", "REFRESH", "REGISTER", "DISCLOSE-SENDER", "DISCLOSE-RECEIVER", "DISCLOSE-AUDITOR"]
OP_TAG = {n: keccak256(b"SCAAS-PQZ-OP-" + n.encode() + b"-V1") for n in OP_NAMES}
OP_BYTE = {"TRANSFER": 1, "BURN": 2, "REFRESH": 2, "REGISTER": 3, "DISCLOSE-SENDER": 4, "DISCLOSE-RECEIVER": 5,
           "DISCLOSE-AUDITOR": 5}
STMT_BYTES = {"TRANSFER": 83072, "TRANSFER0": 66560, "BURN": 50048, "REFRESH": 50048, "REGISTER": 16480,
              "DISCLOSE-SENDER": 33184, "DISCLOSE-RECEIVER": 33184, "DISCLOSE-AUDITOR": 33184}


def word(x):
    """32-byte big-endian word from an int, or from bytes of length <= 32 (left-padded: addresses, 16-byte salt)."""
    if isinstance(x, int):
        return x.to_bytes(32, "big")
    assert len(x) <= 32
    return bytes(32 - len(x)) + bytes(x)


def entry_ref(chain_id, chain_uid, token, from_ua, send_counter):
    """keccak256(abi.encode(keccak256("SCAAS-PQZ-ENTRY-V1"), chainid, chainUid, token, fromUA, sendCounter))."""
    return keccak256(keccak256(b"SCAAS-PQZ-ENTRY-V1"), word(chain_id), word(chain_uid), word(token), word(from_ua),
                     word(send_counter))


def auth_digest(stmt):
    return keccak256(b"SCAAS-PQZ-AUTH-V1", keccak256(stmt))


def ct_hash(ct):
    assert len(ct) == CT_BYTES
    return keccak256(ct)


# ---------------------------------------------------------------- ring R_q = Z_q[X]/(X^64 + 1)
def _pack(cs):  # Kronecker substitution, 64-bit slots, non-negative coefficients
    return int.from_bytes(b"".join(c.to_bytes(8, "little") for c in cs), "little")


def _unpack(x, n):
    b = x.to_bytes(8 * n, "little")
    return [int.from_bytes(b[8 * i:8 * i + 8], "little") for i in range(n)]


def dot(big, small):
    """sum_j big[j] * small[j] in R_q; big: polys with coefficients in [0, q) (or their _pack), small: polys with
    coefficients in [-1, 1]. Slot sums stay below 32 * 64 * q < 2^64."""
    accp = accn = 0
    for a, s in zip(big, small):
        a = a if isinstance(a, int) else _pack(a)
        accp += a * _pack([c if c > 0 else 0 for c in s])
        accn += a * _pack([-c if c < 0 else 0 for c in s])
    p, n = _unpack(accp, 2 * D), _unpack(accn, 2 * D)
    return [(p[k] - p[k + D] - n[k] + n[k + D]) % Q for k in range(D)]


def polys(vec):  # 2048 coefficients -> 32 polys
    return [list(vec[D * i:D * i + D]) for i in range(K)]


def matrix_A():
    """A[i][j] from SHAKE128("SCAAS-PQZ-A-V2" || u8(i) || u8(j)): 8-byte BE words, low 42 bits, keep if < q."""
    A = []
    for i in range(K):
        row = []
        for j in range(K):
            n, cs = 8 * D + 64, []
            while len(cs) < D:
                st = shake128(b"SCAAS-PQZ-A-V2" + bytes([i, j]), n)
                cs = [v for v in (int.from_bytes(st[o:o + 8], "big") & (2**42 - 1) for o in range(0, n, 8)) if v < Q]
                n *= 2
            row.append(cs[:D])
        A.append(row)
    return A


_A = None
_AP = None


def A():
    global _A, _AP
    if _A is None:
        _A = matrix_A()
        _AP = [[_pack(p) for p in row] for row in _A]
    return _A


def a_bytes():
    return b"".join(enc_poly(p) for row in A() for p in row)  # A[0][0], A[0][1], ...: 32 x 32 x 512 B


def mul_A(s):  # A·s
    A()
    return [dot(_AP[i], s) for i in range(K)]


def mul_AT(r):  # A^T·r
    A()
    return [dot([_AP[j][i] for j in range(K)], r) for i in range(K)]


# ---------------------------------------------------------------- encodings
def enc_poly(p, n=D):
    return b"".join(c.to_bytes(8, "big") for c in p[:n])


def enc_vec(v):
    return b"".join(enc_poly(p) for p in v)


class NonCanonical(ValueError):
    pass


def dec_coeffs(b):
    cs = [int.from_bytes(b[o:o + 8], "big") for o in range(0, len(b), 8)]
    if any(c >= Q for c in cs):
        raise NonCanonical("coefficient >= q")
    return cs


def dec_vec(b):
    assert len(b) == PK_BYTES
    return polys(dec_coeffs(b))


# ---------------------------------------------------------------- §4.2 algorithms
def bits_lsb(stream):
    return "".join(format(x, "08b")[::-1] for x in stream)


def cbd(bits, pos, eta, n):
    """n coefficients CBD_eta from the bit string (LSB-first) at pos: a = sum of eta bits, b = the next eta, a - b."""
    out = []
    for _ in range(n):
        a = bits.count("1", pos, pos + eta)
        b = bits.count("1", pos + eta, pos + 2 * eta)
        out.append(a - b)
        pos += 2 * eta
    return out, pos


def sq(v):
    return sum(c * c for c in v)


def keygen_sample(seed32, max_ctr=64, bs=B_S, be=B_E):
    """(s, e, ctr): SHAKE256("SCAAS-PQZ-KEYGEN-V1" || seed32 || be4(ctr)), s <- CBD_1^2048 then e <- CBD_20^2048 from
    one stream; resample while ||s|| > 36 or ||e|| > 164; ctr >= 64 is an error."""
    assert len(seed32) == 32
    for ctr in range(max_ctr):
        bits = bits_lsb(shake256(b"SCAAS-PQZ-KEYGEN-V1" + seed32 + ctr.to_bytes(4, "big"), (2 * N + 40 * N) // 8))
        s, p = cbd(bits, 0, 1, N)
        e, _ = cbd(bits, p, 20, N)
        if sq(s) <= bs * bs and sq(e) <= be * be:
            return s, e, ctr
    raise ValueError("KeyGen: counter 64 reached")


def keygen(seed32, bs=B_S, be=B_E):
    """(pk bytes, s, e, ctr); pk = A·s + e. bs, be: the norm thresholds (lowered only to test the resample path)."""
    s, e, ctr = keygen_sample(seed32, bs=bs, be=be)
    t = mul_A(polys(s))
    pk = [[(t[i][k] + e[D * i + k]) % Q for k in range(D)] for i in range(K)]
    return enc_vec(pk), s, e, ctr


def enc_sample(seed_enc, n, max_ctr=64, bs=B_S, be=B_E, b2=B_2):
    """(r, e1, [e2_j], ctr) from SHAKE256("SCAAS-PQZ-ENC-V1" || seed_enc || be4(ctr)), one stream in that order."""
    assert len(seed_enc) == 32
    for ctr in range(max_ctr):
        bits = bits_lsb(shake256(b"SCAAS-PQZ-ENC-V1" + seed_enc + ctr.to_bytes(4, "big"),
                                 (2 * N + 40 * N + 40 * 16 * n) // 8))
        r, p = cbd(bits, 0, 1, N)
        e1, p = cbd(bits, p, 20, N)
        e2 = []
        for _ in range(n):
            x, p = cbd(bits, p, 20, 16)
            e2.append(x)
        if sq(r) <= bs * bs and sq(e1) <= be * be and all(sq(x) <= b2 * b2 for x in e2):
            return r, e1, e2, ctr
    raise ValueError("Enc: counter 64 reached")


def encrypt(pks, msgs, r, e1, e2):
    """u = A^T r + e1; v_j[i] = (pk_j^T r)[i] + e2_j[i] + Delta * m_j[i] mod q. pks: bytes; msgs: 16 digits each."""
    rp = polys(r)
    t = mul_AT(rp)
    u = enc_vec([[(t[i][k] + e1[D * i + k]) % Q for k in range(D)] for i in range(K)])
    vs = []
    for pk, m, x in zip(pks, msgs, e2):
        a = dot(dec_vec(pk), rp)
        vs.append(enc_poly([(a[i] + x[i] + DELTA * m[i]) % Q for i in range(16)], 16))
    return u, vs


def enc_seed(pks, msgs, seed_enc, bs=B_S, be=B_E, b2=B_2):
    """(u, [v_j], ctr) = Enc({(pk_j, m_j)}, seed_enc)."""
    r, e1, e2, ctr = enc_sample(seed_enc, len(pks), bs=bs, be=be, b2=b2)
    u, vs = encrypt(pks, msgs, r, e1, e2)
    return u, vs, ctr


def centre(x):
    x %= Q
    return x - Q if x > Q // 2 else x


def dec(s, ct):
    """(M[16], noise[16], value): w_i = centre(v_i - (u^T s)_i), M_i = round(w_i / Delta) (no ties: Delta odd)."""
    u, v = dec_vec(ct[:PK_BYTES]), dec_coeffs(ct[PK_BYTES:])
    a = dot(u, polys(s))
    M, noise = [], []
    for i in range(16):
        w = centre(v[i] - a[i])
        m = (2 * w + DELTA) // (2 * DELTA)
        M.append(m)
        noise.append(w - DELTA * m)
    return M, noise, sum(m * 16**i for i, m in enumerate(M))


def ct_add(a, b, sign=1):
    x, y = dec_coeffs(a), dec_coeffs(b)
    return b"".join(((p + sign * q) % Q).to_bytes(8, "big") for p, q in zip(x, y))


def ct_sub(a, b):
    return ct_add(a, b, -1)


def trivial(m):
    return bytes(PK_BYTES) + enc_poly([(DELTA * d) % Q for d in m], 16)


def digits(x):
    assert 0 <= x < 2**64
    return [(x >> (4 * i)) & 15 for i in range(16)]


# ---------------------------------------------------------------- statements (§7.2, §7.7, §7.9; plan D15 / R6)
def build_header(op, f):
    """f: dict of header fields (ints or bytes; missing = 0); opTag and proofSystemId from op and f['proofSystemId']
    (default PQZL)."""
    w = dict(f)
    w["opTag"] = OP_TAG[op]
    w.setdefault("proofSystemId", PQZL_ID)
    if "salt" in w and not isinstance(w["salt"], int):
        assert len(w["salt"]) == 16
    return b"".join(word(w.get(k, 0)) for k in HEADER)


def build_debit(op, f, pk_f, T, out, pk_t=None, pk_a=None):
    """TRANSFER: header || pk_f || pk_t || [pk_a] || T || out (out = u || v_t || v_f || [v_a]); BURN / REFRESH: header
    || pk_f || T || out (out = u || v_f). auditorOn follows pk_a (R6)."""
    if op == "TRANSFER":
        f = dict(f, auditorOn=1 if pk_a is not None else 0)
        body = pk_f + pk_t + (pk_a or b"") + T + out
        assert len(out) == PK_BYTES + (4 if pk_a is not None else 3) * V_BYTES - V_BYTES
    else:
        assert op in ("BURN", "REFRESH") and pk_t is None and pk_a is None and len(out) == CT_BYTES
        body = pk_f + T + out
    return build_header(op, f) + body


def build_register(message, pk, psid=PQZL_ID):
    return OP_TAG["REGISTER"] + psid + word(message) + pk


def build_disclose(op, f, pk, u, v):
    w = dict(f, opTag=OP_TAG[op])
    w.setdefault("proofSystemId", PQZL_ID)
    return b"".join(word(w.get(k, 0)) for k in DISC) + pk + u + v


def _scalar(b, name):  # a header word the relations read: < 2^64
    x = int.from_bytes(b, "big")
    if x >= 2**64:
        raise NonCanonical(name + " >= 2^64")
    return x


def parse(op_byte, stmt, ids=(PQZL_ID, PQZH_ID)):
    """Statement -> dict (op name, words, objects), or NonCanonical / ValueError for every D15 / R6 rule: length of
    the op (op 1 by length: 83,072 auditor on, 66,560 off), opTag of the op, a known proofSystemId, coefficients < q,
    fee / amount < 2^64, auditorOn equal to the length's value."""
    tag = stmt[:32]
    names = [n for n in OP_NAMES if OP_TAG[n] == tag and OP_BYTE[n] == op_byte]
    if not names:
        raise ValueError("opTag does not belong to op")
    op = names[0]
    if stmt[32:64] not in ids:
        raise ValueError("unknown proofSystemId")
    n = len(stmt)
    out = {"op": op}
    if op == "REGISTER":
        if n != STMT_BYTES[op]:
            raise ValueError("length")
        out["message"] = stmt[64:96]
        dec_vec(stmt[96:])
        out["pk"] = stmt[96:]
        return out
    if op.startswith("DISCLOSE"):
        if n != STMT_BYTES[op]:
            raise ValueError("length")
        for i, k in enumerate(DISC):
            out[k] = stmt[32 * i:32 * i + 32]
        _scalar(out["amount"], "amount")
        o = 32 * len(DISC)
        out["pk"], out["u"], out["v"] = stmt[o:o + PK_BYTES], stmt[o + PK_BYTES:o + 2 * PK_BYTES], stmt[o + 2 * PK_BYTES:]
        dec_coeffs(stmt[o:])
        return out
    aud = None
    if op == "TRANSFER":
        aud = {STMT_BYTES["TRANSFER"]: 1, STMT_BYTES["TRANSFER0"]: 0}.get(n)
        if aud is None:
            raise ValueError("length")
    elif n != STMT_BYTES[op]:
        raise ValueError("length")
    for i, k in enumerate(HEADER):
        out[k] = stmt[32 * i:32 * i + 32]
    _scalar(out["fee"], "fee")
    _scalar(out["amount"], "amount")
    a = int.from_bytes(out["auditorOn"], "big")
    if op == "TRANSFER" and a != aud:
        raise ValueError("auditorOn does not match the length")
    body = stmt[HEADER_BYTES:]
    dec_coeffs(body)
    keys = ["pk_f"] + (["pk_t"] + (["pk_a"] if aud else []) if op == "TRANSFER" else [])
    o = 0
    for k in keys:
        out[k], o = body[o:o + PK_BYTES], o + PK_BYTES
    out["T"], o = body[o:o + CT_BYTES], o + CT_BYTES
    out["u"], o = body[o:o + PK_BYTES], o + PK_BYTES
    vk = (["v_t", "v_f"] + (["v_a"] if aud else [])) if op == "TRANSFER" else ["v_f"]
    for k in vk:
        out[k], o = body[o:o + V_BYTES], o + V_BYTES
    assert o == len(body)
    return out


def bundle(salt16, u, v_t, v_a, to_ua):
    """R = salt(16) || u || v_t || v_a || toUA(32): 16,688 B, 16,560 B without v_a (CTR-PQZ-23)."""
    assert len(salt16) == 16
    return salt16 + u + v_t + (v_a or b"") + word(to_ua)


def opening(bundle_bytes, proof):
    """abi.encode(bytes bundle, bytes proof)."""
    def tail(b):
        return word(len(b)) + b + bytes(-len(b) % 32)
    t1 = tail(bundle_bytes)
    return word(64) + word(64 + len(t1)) + t1 + tail(proof)


def precompile_input(op_byte, stmt, proof):
    return bytes([op_byte]) + len(stmt).to_bytes(4, "big") + stmt + proof


# ---------------------------------------------------------------- self-test
def selftest(log):
    bad = []

    def ok(cond, what):
        (log if cond else bad.append)(("ok   " if cond else "FAIL ") + what)

    for n in (0, 1, 135, 136, 137, 300):
        m = bytes((7 * i + 1) & 255 for i in range(n))
        ok(_sponge(m, 0x06) == hashlib.sha3_256(m).digest(), f"Keccak-f permutation = hashlib sha3_256, {n} B")
    ok(keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470", "keccak256('')")
    ok(PQZL_ID.hex() == "2e07e6ed1fd303a08c89b3eab6e8423fdfb8f31202958dd682a0619313798c2f", "PQZL proofSystemId (D2)")
    ok(PQZH_ID.hex() == "0a47a7689250ba178a52ad5972cdd9153358c022cb694c08d2389e82de2fead4", "PQZH proofSystemId (D3)")
    plan = {"TRANSFER": "ef22f3d1", "BURN": "7383374d", "REFRESH": "f118f2df", "REGISTER": "69562a9c",
            "DISCLOSE-SENDER": "868cc07c", "DISCLOSE-RECEIVER": "d8356cfb", "DISCLOSE-AUDITOR": "d6019aa4"}
    for k, v in plan.items():
        ok(OP_TAG[k].hex().startswith(v), f"opTag {k} = {OP_TAG[k].hex()[:8]}...")
    log(f"     A digest keccak256(A bytes) = {keccak256(a_bytes()).hex()}")
    # KeyGen / Enc / Dec round trip, Add / Sub / Trivial, noise inside B_FRESH
    keys = [keygen(bytes([i]) * 32) for i in range(3)]
    for (pk, s, e, ctr), i in zip(keys, range(3)):
        ok(ctr == 0 and sq(s) <= B_S**2 and sq(e) <= B_E**2, f"KeyGen seed {i:02x}*32: ctr 0, norms")
    vals = [123456789, 2**64 - 1, 0]
    u, vs, _ = enc_seed([k[0] for k in keys], [digits(x) for x in vals], bytes(range(32)))
    for j in range(3):
        M, noise, val = dec(keys[j][1], u + vs[j])
        ok(val == vals[j] and M == digits(vals[j]) and max(map(abs, noise)) <= B_FRESH,
           f"Dec(Enc(m)) = m, recipient {j}, max |noise| {max(map(abs, noise))} <= {B_FRESH}")
    c = ct_add(u + vs[0], trivial(digits(5)))
    ok(dec(keys[0][1], c)[2] == vals[0] + 5, "Add with Trivial(5)")
    ok(dec(keys[0][1], ct_sub(c, trivial(digits(5))))[2] == vals[0], "Sub")
    # every statement form: build -> parse -> same objects; lengths; the D15 / R6 rejections
    pk, ct = keys[0][0], u + vs[0]
    out4, out3 = u + vs[0] + vs[1] + vs[2], u + vs[0] + vs[1]
    hdr = {"chainId": 7622, "token": bytes(range(20)), "fee": 7, "salt": bytes(range(16)), "sendCounter": 3}
    forms = {
        "TRANSFER": build_debit("TRANSFER", hdr, pk, ct, out4, pk_t=pk, pk_a=pk),
        "TRANSFER0": build_debit("TRANSFER", hdr, pk, ct, out3, pk_t=pk),
        "BURN": build_debit("BURN", dict(hdr, amount=9), pk, ct, ct),
        "REFRESH": build_debit("REFRESH", hdr, pk, ct, ct),
        "REGISTER": build_register(bytes(range(32)), pk),
        "DISCLOSE-SENDER": build_disclose("DISCLOSE-SENDER", {"amount": 5, "kind": 0}, pk, u, vs[0]),
        "DISCLOSE-RECEIVER": build_disclose("DISCLOSE-RECEIVER", {"amount": 5, "kind": 1}, pk, u, vs[0]),
        "DISCLOSE-AUDITOR": build_disclose("DISCLOSE-AUDITOR", {"amount": 5, "kind": 2}, pk, u, vs[0]),
    }
    for name, st in forms.items():
        op = name.rstrip("0")
        p = parse(OP_BYTE[op], st)
        ok(len(st) == STMT_BYTES[name] and p["op"] == op and p.get("pk", p.get("pk_f")) == pk, f"statement {name}")

    def rejects(st, op_byte, what, why):
        try:
            parse(op_byte, st)
            ok(False, f"reject: {what} (accepted)")
        except ValueError as x:
            ok(str(x) == why, f"reject: {what}: {x}")

    t = forms["TRANSFER"]
    rejects(t[:-1], 1, "length - 1", "length")
    rejects(t + b"\0", 1, "length + 1", "length")
    rejects(t[:448] + word(0) + t[480:], 1, "auditorOn 0 on the 83,072-byte form", "auditorOn does not match the length")
    rejects(forms["TRANSFER0"][:448] + word(1) + forms["TRANSFER0"][480:], 1, "auditorOn 1 on the 66,560-byte form",
            "auditorOn does not match the length")
    rejects(t[:448] + word(2) + t[480:], 1, "auditorOn 2", "auditorOn does not match the length")
    rejects(t[:256] + word(2**64) + t[288:], 1, "fee >= 2^64", "fee >= 2^64")
    rejects(t[:640] + Q.to_bytes(8, "big") + t[648:], 1, "coefficient = q", "coefficient >= q")
    rejects(t[:640] + (2**42).to_bytes(8, "big") + t[648:], 1, "coefficient = 2^42", "coefficient >= q")
    rejects(t, 2, "TRANSFER statement under op 2", "opTag does not belong to op")
    rejects(t[:32] + bytes(32) + t[64:], 1, "unknown proofSystemId", "unknown proofSystemId")
    d = forms["DISCLOSE-SENDER"]
    rejects(d[:224] + word(2**64) + d[256:], 4, "disclosure amount >= 2^64", "amount >= 2^64")
    # the resample path and the counter-64 error, with lowered thresholds (the real ones are never exceeded)
    ctrs = [keygen_sample(bytes([i]) * 32, bs=32, be=143)[2] for i in range(4)]
    ok(any(c >= 1 for c in ctrs), f"KeyGen resamples with ||s|| <= 32, ||e|| <= 143: counters {ctrs}")
    ctrs = [enc_sample(bytes([i]) * 32, 2, bs=32, be=143, b2=12)[3] for i in range(4)]
    ok(any(c >= 1 for c in ctrs), f"Enc resamples with 32 / 143 / 12: counters {ctrs}")
    for what, f in (("KeyGen", lambda: keygen_sample(bytes(32), bs=0)), ("Enc", lambda: enc_sample(bytes(32), 1, b2=0))):
        try:
            f()
            ok(False, f"{what}: counter 64 error")
        except ValueError as x:
            ok("counter 64" in str(x), f"{what}: counter 64 error")
    # bundle / opening sizes, entryRef / ctHash / authDigest shapes
    ok(len(bundle(bytes(16), u, vs[0], vs[2], 1)) == 16688 and len(bundle(bytes(16), u, vs[0], None, 1)) == 16560,
       "bundle 16,688 / 16,560 B")
    o = opening(b"\1" * 33, b"\2" * 5)
    ok(len(o) == 64 + 32 + 64 + 32 + 32 and o[:64] == word(64) + word(160), "opening = abi.encode(bytes, bytes)")
    log(f"     entryRef(7622, 1, token, 2, 0) = {entry_ref(7622, 1, bytes(range(20)), 2, 0).hex()}")
    return bad


# ---------------------------------------------------------------- --c-keys: the C core's keys KAT
def check_c_keys(path, log):
    bad = []
    pks = {}
    n = dict.fromkeys(["shake256", "keygen", "enc", "dec", "keygen_lowered", "enc_lowered", "keygen_resampled",
                       "enc_resampled", "ctr64_errors"], 0)
    for line in open(path):
        line = line.strip()
        if not line.startswith("{"):
            continue
        r = json.loads(line)
        if "shake256" in r:
            x = r["shake256"]
            n["shake256"] += 1
            if shake256(bytes.fromhex(x["in"]), x["outlen"]).hex() != x["out"]:
                bad.append(f"SHAKE256 in {len(x['in']) // 2} B, out {x['outlen']} B")
        elif "keygen" in r:
            x = r["keygen"]
            n["keygen"] += 1
            pk, s, e, ctr = keygen(bytes.fromhex(x["seed"]))
            pks[x["seed"]] = (pk, s)
            if x["rc"] != 0 or ctr != x["ctr"] or shake256(pk, 32).hex() != x["pk_shake256"]:
                bad.append(f"KeyGen seed {x['seed']}")
        elif "keygen_lowered" in r:  # test-hook thresholds: the resample path, or the counter-64 error (rc 4)
            x = r["keygen_lowered"]
            n["keygen_lowered"] += 1
            try:
                pk, s, e, ctr = keygen(bytes.fromhex(x["seed"]), bs=x["bs"], be=x["be"])
                if x["rc"] != 0 or ctr != x["ctr"] or shake256(pk, 32).hex() != x["pk_shake256"]:
                    bad.append(f"KeyGen lowered {x['bs']} / {x['be']} seed {x['seed']}")
                n["keygen_resampled"] += ctr >= 1
            except ValueError:
                if x["rc"] != 4:
                    bad.append(f"KeyGen lowered {x['bs']} / {x['be']}: C rc {x['rc']}, Python counter-64 error")
                n["ctr64_errors"] += 1
        elif "enc" in r or "enc_lowered" in r:
            low = "enc_lowered" in r
            x = r["enc_lowered" if low else "enc"]
            n["enc_lowered" if low else "enc"] += 1
            th = {k: x[k] for k in ("bs", "be", "b2")} if low else {}
            rec = [pks[sd] for sd in x["recipients"]]
            try:
                u, vs, ctr = enc_seed([p[0] for p in rec], [digits(v) for v in x["values"]],
                                      bytes.fromhex(x["seed_enc"]), **th)
            except ValueError:
                if not low or x["rc"] != 4:
                    bad.append(f"Enc seed_enc {x['seed_enc']}: C rc {x['rc']}, Python counter-64 error")
                n["ctr64_errors"] += 1
                continue
            if x["rc"] != 0 or ctr != x["ctr"] or shake256(u, 32).hex() != x["u_shake256"] or \
                    [v.hex() for v in vs] != x["v"]:
                bad.append(f"Enc seed_enc {x['seed_enc']}")
            n["enc_resampled"] += low and ctr >= 1
            for j, d in enumerate(x.get("dec", [])):  # Dec by each recipient
                M, noise, val = dec(rec[j][1], u + vs[j])
                if M != d["M"] or noise != d["noise"] or val != x["values"][j]:
                    bad.append(f"Dec seed_enc {x['seed_enc']} recipient {j}")
                n["dec"] += 1
        elif "roundtrip" in r or "before_init_rejected" in r or "lowered" in r:
            log(f"     C's own claim (not recomputed here): {line}")
            if r.get("fails", 0) != 0 or r.get("before_init_rejected", 6) != 6:
                bad.append(f"C reports: {line}")
    log(f"     C keys KAT {path}: {n}")
    if n["shake256"] < 10 or n["keygen"] < 20 or n["enc"] < 20 or n["dec"] < 40 or n["keygen_resampled"] < 1 \
            or n["enc_resampled"] < 1 or n["ctr64_errors"] < 2:
        bad.append(f"too few cases: {n}")
    return bad


# ---------------------------------------------------------------- vector files (P6e Task 11 adds their checkers)
CHECKERS = {}


def check_files(paths, log):
    bad = []
    for p in paths:
        name = os.path.basename(p)
        fn = CHECKERS.get(name) or CHECKERS.get(name.split("_")[0] + "_*")
        if fn is None:
            bad.append(f"{name}: no checker in pqz_kat.py")
            continue
        bad += [f"{name}: {b}" for b in fn(json.load(open(p)))]
        log(f"ok   {name}")
    return bad


def main(argv):
    log = print
    if len(argv) >= 2 and argv[0] == "--c-keys":
        bad = check_c_keys(argv[1], log)
    elif argv and argv[0] == "--check":
        bad = selftest(log)
        files = argv[1:] or sorted(glob.glob(os.path.join(os.path.dirname(os.path.abspath(__file__)), "*.json")))
        log(f"     vector files: {len(files)}")
        bad += check_files(files, log)
    else:
        print(__doc__)
        return 2
    for b in bad:
        print("FAIL", b)
    print("pqz_kat:", "FAIL" if bad else "ok")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
