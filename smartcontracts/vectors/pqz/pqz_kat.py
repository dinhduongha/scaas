#!/usr/bin/env python3
"""Independent PQZ KAT (pq-zero-knowledge.md §4, §5, §7; P6e plan Task 4). Python 3 stdlib only (hashlib SHAKE, an own
Keccak-256 checked against hashlib's SHA3 permutation): no numpy, no third-party package, runs under `python3 -I`.

Implements everything of PQZL except the proofs: the matrix A (SHAKE128 "SCAAS-PQZ-A-V2"), CBD, KeyGen, Enc, Dec,
Add / Sub / Trivial, digits, the opTags and the set's two proofSystemIds, every statement layout (build and parse, with the
canonical-encoding rules of the plan's D15 / R6), ctHash, authDigest, the bundle and opening encodings, entryRef.

  pqz_kat.py --check [vector.json ...]   self-test, then recompute every non-proof field of every vector file
                                         (default: every *.json next to this script); exit 1 on any drift
  pqz_kat.py --c-keys run.jsonl          compare the C core's keys KAT (pqz-core test/pqz_keys_kat.c output:
                                         SHAKE256, KeyGen, Enc, Dec) with this implementation; exit 1 on any drift

A vector file without a checker here is a failure: the generator (P6e Task 11) adds the file and its checker
together. Public data only: nothing here is constant-time.

Parameter set (owner 2026-10-21: one per build): PQZ_SET=<set> (default n2048-kmax1024, the v3 set, whose files are
next to this script); the set's constants come from pqz-core/params/sets/<set>/set.json (gen_set.py), its files from
<set>/ next to this script. PQZH files exist for every set whose set.json says pqzh (plan 5h Task 8c part 2: its preset,
MAX_PROOF_PQZH and MAX_INPUT from set.json too); a set without PQZH has PQZL files only.
"""
import glob
import hashlib
import hmac
import json
import math
import os
import sys

V3 = "n2048-kmax1024"
SET = os.environ.get("PQZ_SET", V3)
_HERE = os.path.dirname(os.path.abspath(__file__))
_S = json.load(open(os.path.join(_HERE, "..", "..", "..", "pqz-core", "params", "sets", SET, "set.json")))
VEC_DIR = _HERE if SET == V3 else os.path.join(_HERE, SET)  # the set's vector files
Q = _S["q"]  # v3: 2^42 - 215
D = 64
K = _S["k"]  # v3: 32
N = D * K  # v3: 2048
LOG2Q = _S["log2q"]  # the A expansion's width: values mod 2^LOG2Q, kept if < q (v3: 42)
DELTA = _S["delta"]  # v3: 2^26 - 1
K_MAX, M_BITS, E_BITS = _S["k_max"], _S["mbits"], _S["ebits"] - 1  # |e_T| < 2^E_BITS (v3: 1,024, 14, 24)
B_S, B_E, B_2 = _S["beta_s"], _S["beta_e"], _S["beta_2"]  # v3: 36, 164, 64
B_FRESH = B_E * B_S + B_S * B_E + B_2  # v3: 11,872 (§4.3)
HAS_PQZH = _S["pqzh"]
assert (_S["n"], _S["d"], B_FRESH, _S["lengths"]["pk"]) == (N, D, _S["b_fresh"], 512 * K) and Q % 16 == 9
PK_BYTES = 512 * K  # v3: 16,384
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
# the set's ids (plan 5h Task 8d: one per set and proof system): keccak256 of set.json's labels (set.toml pqzl_id /
# pqzh_id); the self-test compares them with gen_set.py's ids and refuses the retired ones
PQZL_ID = keccak256(_S["pqzl_label"].encode())
PQZH_ID = keccak256(_S["pqzh_label"].encode())
RETIRED_IDS = {"PQZL v2": "2e07e6ed1fd303a08c89b3eab6e8423fdfb8f31202958dd682a0619313798c2f",  # forgeable (lazer#28, F9)
               "PQZL v3": "8079d65b5e5c15e330f7e65c875776dfc1b0f6c93ced90c045e83865d116baef",  # .../mlwe-d64k32-q42l4/v3
               "PQZH v1": "0a47a7689250ba178a52ad5972cdd9153358c022cb694c08d2389e82de2fead4"}  # .../ligero-fq-r431-.../v1
OP_NAMES = ["TRANSFER", "BURN", "REFRESH", "REGISTER", "DISCLOSE-SENDER", "DISCLOSE-RECEIVER", "DISCLOSE-AUDITOR",
            "TRANSFER-MULTI"]
OP_TAG = {n: keccak256(b"SCAAS-PQZ-OP-" + n.encode() + b"-V1") for n in OP_NAMES}
OP_BYTE = {"TRANSFER": 1, "BURN": 2, "REFRESH": 2, "REGISTER": 3, "DISCLOSE-SENDER": 4, "DISCLOSE-RECEIVER": 5,
           "DISCLOSE-AUDITOR": 5, "TRANSFER-MULTI": 7}
STMT_BYTES = {"TRANSFER": 640 + 5 * PK_BYTES + 4 * V_BYTES, "TRANSFER0": 640 + 4 * PK_BYTES + 3 * V_BYTES,
              "BURN": 640 + 3 * PK_BYTES + 2 * V_BYTES, "REFRESH": 640 + 3 * PK_BYTES + 2 * V_BYTES, "REGISTER": 96 + PK_BYTES,
              "DISCLOSE-SENDER": 288 + 2 * PK_BYTES + V_BYTES, "DISCLOSE-RECEIVER": 288 + 2 * PK_BYTES + V_BYTES,
              "DISCLOSE-AUDITOR": 288 + 2 * PK_BYTES + V_BYTES}  # v3: 83,072 / 66,560 / 50,048 / 16,480 / 33,184
assert STMT_BYTES == _S["lengths"]["stmt"]


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
    coefficients in [-1, 1]. Slot sums stay below k * 64 * q < 2^64 (v3: 32 * 64 * q)."""
    accp = accn = 0
    for a, s in zip(big, small):
        a = a if isinstance(a, int) else _pack(a)
        accp += a * _pack([c if c > 0 else 0 for c in s])
        accn += a * _pack([-c if c < 0 else 0 for c in s])
    p, n = _unpack(accp, 2 * D), _unpack(accn, 2 * D)
    return [(p[k] - p[k + D] - n[k] + n[k + D]) % Q for k in range(D)]


def polys(vec):  # N coefficients -> K polys
    return [list(vec[D * i:D * i + D]) for i in range(K)]


def matrix_A():
    """A[i][j] from SHAKE128("SCAAS-PQZ-A-V2" || u8(i) || u8(j)): 8-byte BE words, low LOG2Q bits, keep if < q."""
    A = []
    for i in range(K):
        row = []
        for j in range(K):
            n, cs = 8 * D + 64, []
            while len(cs) < D:
                st = shake128(b"SCAAS-PQZ-A-V2" + bytes([i, j]), n)
                cs = [v for v in (int.from_bytes(st[o:o + 8], "big") & (2**LOG2Q - 1) for o in range(0, n, 8)) if v < Q]
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
    return b"".join(enc_poly(p) for row in A() for p in row)  # A[0][0], A[0][1], ...: K x K x 512 B


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


# header words the contract always writes as 0 for the form (§7.7 "toUA (0 for burn/refresh)", "amount (burn; else
# 0)", "recipient (burn; else 0)", "salt (burn/refresh 0)"; §7.5 refresh: amount = 0 and recipient = 0; a burn has no
# auditor); checked in HEADER order after the scalars, the salt form and auditorOn (P6e D15, controller 2026-10-14)
ZERO_WORDS = {"TRANSFER": ("amount", "recipient"), "BURN": ("toUA", "auditorOn", "salt"),
              "REFRESH": ("toUA", "amount", "recipient", "auditorOn", "salt")}


def _scalar(b, name):  # a header word the relations read: < 2^64
    x = int.from_bytes(b, "big")
    if x >= 2**64:
        raise NonCanonical(name + " >= 2^64")
    return x


def parse(op_byte, stmt, ids=(PQZL_ID, PQZH_ID)):
    """Statement -> dict (op name, words, objects), or NonCanonical / ValueError for every D15 / R6 rule: length of
    the op (op 1 by length: 83,072 auditor on, 66,560 off), opTag of the op, a known proofSystemId, coefficients < q,
    fee / amount < 2^64 (every debit form: the decoder is stricter than the relations, which read amount only for
    BURN), the salt word = 16 zero bytes || salt (CTR-PQZ-19; pqz-core only hashes it, the decoder enforces it),
    auditorOn equal to the length's value, and the words §7.7 / §7.5 fix to 0 (ZERO_WORDS: a transfer's amount and
    recipient, a burn's toUA / auditorOn / salt, a refresh's toUA / amount / recipient / auditorOn / salt)."""
    tag = stmt[:32]
    names = [n for n in OP_NAMES if OP_TAG[n] == tag and OP_BYTE[n] == op_byte]
    if not names:
        raise ValueError("opTag does not belong to op")
    op = names[0]
    if stmt[32:64] not in ids:
        raise ValueError("unknown proofSystemId")
    if op == "TRANSFER-MULTI":
        return parse_multi(stmt, stmt[32:64])
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
    if out["salt"][:16] != bytes(16):
        raise NonCanonical("salt word not 16 zero bytes || salt")
    a = int.from_bytes(out["auditorOn"], "big")
    if op == "TRANSFER" and a != aud:
        raise ValueError("auditorOn does not match the length")
    for k in HEADER:
        if k in ZERO_WORDS[op] and any(out[k]):
            raise NonCanonical(k + " must be 0")
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


# ---------------------------------------------------------------- op 7 R_TXM (P6-ANON plan §4, D6, R4, D3 / D20)
# legs per randomness group (r_g, e1_g, u_g), with or without the auditor (D4; S1's DDGR20 run: 80 hints give beta
# 446.0, owner-accepted 2026-10-15; pqz-core/pqzl/params/anon/hints-anon.txt)
LEGS_PER_GROUP = 4
# op 7 leg counts per id, either auditor mode (pqz-stmt built_legs; D20)
BUILT_LEGS = {PQZL_ID: (1, 2, 4, 8), PQZH_ID: (1, 2, 4)}
MULTI_HEADER = [{"toUA": "recipientsHash", "recipient": "M"}.get(k, k) for k in HEADER]


def groups(m):
    return -(-m // LEGS_PER_GROUP)


def multi_len(m, aud):
    """640 || pk_f || pk_0..pk_{M-1} || [pk_a] || T || u_0..u_{G-1} || v_0..v_{M-1} || v_f || [v_{a,0}..v_{a,M-1}]"""
    return HEADER_BYTES + (1 + m + aud) * PK_BYTES + CT_BYTES + groups(m) * PK_BYTES + \
        (m + 1 + aud * m) * V_BYTES


def recipients_hash(uas):
    """recipientsHash = keccak256 of the recipients' UAs in leg order, each a 32-byte word (12 zero bytes ||
    address)."""
    return keccak256(b"".join(word(a) for a in uas))


def build_multi(f, pk_f, pks, T, us, vs, v_f, pk_a=None, v_as=None):
    """Op 7 statement. f: header fields by MULTI_HEADER name (recipientsHash in word 192; M = len(pks) in word 320 and
    auditorOn from pk_a are set here); pks / us / vs / v_as: lists of objects."""
    m, aud = len(pks), pk_a is not None
    assert len(us) == groups(m) and len(vs) == m and (v_as is not None) == aud and (not aud or len(v_as) == m)
    w = dict(f, M=m, auditorOn=int(aud), opTag=OP_TAG["TRANSFER-MULTI"])
    w.setdefault("proofSystemId", PQZL_ID)
    return b"".join(word(w.get(k, 0)) for k in MULTI_HEADER) + pk_f + b"".join(pks) + (pk_a or b"") + T + \
        b"".join(us) + b"".join(vs) + v_f + b"".join(v_as or [])


def parse_multi(stmt, psid):
    """Op 7 after opTag and id (parse): header present, the auditorOn word (0 / 1) and the M word (one of
    BUILT_LEGS[id]) fix the length (R4; the length alone does not: (M = 1, on) and (M = 2, off) are both
    83,072 B), then fee / amount < 2^64, the salt form, amount = 0, coefficients < q."""
    if len(stmt) < HEADER_BYTES:
        raise ValueError("length")
    out = {"op": "TRANSFER-MULTI"}
    for i, k in enumerate(MULTI_HEADER):
        out[k] = stmt[32 * i:32 * i + 32]
    m, aud = int.from_bytes(out["M"], "big"), int.from_bytes(out["auditorOn"], "big")
    if aud not in (0, 1):
        raise ValueError("auditorOn does not match the length")
    if m not in BUILT_LEGS[psid]:
        raise ValueError("M not a built leg count")
    if len(stmt) != multi_len(m, aud):
        raise ValueError("length")
    out["legs"], out["auditor"] = m, aud
    _scalar(out["fee"], "fee")
    _scalar(out["amount"], "amount")
    if out["salt"][:16] != bytes(16):
        raise NonCanonical("salt word not 16 zero bytes || salt")
    if any(out["amount"]):
        raise NonCanonical("amount must be 0")
    body = stmt[HEADER_BYTES:]
    dec_coeffs(body)
    o = 0

    def take(k):
        nonlocal o
        o += k
        return body[o - k:o]
    out["pk_f"] = take(PK_BYTES)
    out["pks"] = [take(PK_BYTES) for _ in range(m)]
    if aud:
        out["pk_a"] = take(PK_BYTES)
    out["T"] = take(CT_BYTES)
    out["us"] = [take(PK_BYTES) for _ in range(groups(m))]
    out["vs"] = [take(V_BYTES) for _ in range(m)]
    out["v_f"] = take(V_BYTES)
    if aud:
        out["v_as"] = [take(V_BYTES) for _ in range(m)]
    assert o == len(body)
    return out


def enc_group_seed(seed_enc, g):
    """seed_enc_g of R_TXM group g (P6-ANON D13): seed_enc for g = 0, else SHAKE256("SCAAS-PQZ-ENC-GROUP-V1" ||
    seed_enc || be4(g))[0..32)."""
    return seed_enc if g == 0 else shake256(b"SCAAS-PQZ-ENC-GROUP-V1" + seed_enc + g.to_bytes(4, "big"), 32)


def enc_multi(pk_f, d_f, legs, pk_a, seed_enc):
    """The R_TXM encryption (P6-ANON §4, D13): group g (legs j with j // 4 = g) is one Enc from enc_group_seed(seed_enc,
    g) to its legs, then (g = 0) pk_f with d_f, then (pk_a given) pk_a once per leg of the group with that leg's digits.
    legs: [(pk_j, digits_j)]. -> dict: us, vs, v_f, v_as, and the witness parts rs, e1s, e2 (legs), e2_f, e2_a, ctrs."""
    o = {k: [] for k in ("us", "vs", "v_as", "rs", "e1s", "e2", "e2_a", "ctrs")}
    for g in range(groups(len(legs))):
        grp = legs[LEGS_PER_GROUP * g:LEGS_PER_GROUP * (g + 1)]
        n = len(grp)
        pks = [x[0] for x in grp] + ([pk_f] if g == 0 else []) + ([pk_a] * n if pk_a is not None else [])
        msgs = [x[1] for x in grp] + ([d_f] if g == 0 else []) + ([x[1] for x in grp] if pk_a is not None else [])
        r, e1, e2, ctr = enc_sample(enc_group_seed(seed_enc, g), len(pks))
        u, vs = encrypt(pks, msgs, r, e1, e2)
        a0 = n + (g == 0)
        o["us"].append(u), o["rs"].append(r), o["e1s"].append(e1), o["ctrs"].append(ctr)
        o["vs"] += vs[:n]
        o["e2"] += e2[:n]
        if g == 0:
            o["v_f"], o["e2_f"] = vs[n], e2[n]
        o["v_as"] += vs[a0:]
        o["e2_a"] += e2[a0:]
    return o


def hkdf_expand(prk, info, n):
    """HKDF-Expand-SHA256 (RFC 5869)."""
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out, i = out + t, i + 1
    return out[:n]


def memo_stream(key_seed, hw, salt, n):
    """the op 7 memo keystream (P6-ANON §5.4, CTR-PQZ-23): key = HKDF-SHA256(IKM key_seed, no salt, info "PQZ/memo/v1"
    || chainUid || token (20 bytes) || fromUA || be4(sendCounter) || salt) (32 B); ks = HKDF-Expand-SHA256(key,
    "PQZ/memo/ks/v1", n). hw: header words by MULTI_HEADER name. None if sendCounter >= 2^32."""
    ctr = int.from_bytes(hw["sendCounter"], "big")
    if ctr >= 2**32:
        return None
    prk = hmac.new(bytes(32), key_seed, hashlib.sha256).digest()
    key = hkdf_expand(prk, b"PQZ/memo/v1" + hw["chainUid"] + hw["token"][12:] + hw["fromUA"] + ctr.to_bytes(4, "big") +
                      salt, 32)
    return hkdf_expand(key, b"PQZ/memo/ks/v1", n)


def memo_seal(key_seed, hw, aud, legs):
    """memo = salt || ((u8(auditorOn) || u8(M) || (be8(a_j) || UA_j)_{j<M}) XOR ks) (18 + 40 M bytes); legs: [(a_j,
    UA_j word)]; salt = the low 16 bytes of the salt word."""
    plain = bytes([int(aud), len(legs)]) + b"".join(a.to_bytes(8, "big") + ua for a, ua in legs)
    salt = hw["salt"][16:]
    return salt + bytes(x ^ y for x, y in zip(plain, memo_stream(key_seed, hw, salt, len(plain))))


def memo_open(key_seed, hw, memo):
    """memo_seal backwards: (auditorOn, [(a_j, UA_j)]), or None for a length other than 18 + 40 M, an M byte that
    disagrees with it, or a flags byte other than 0 / 1 (pqz-ffi memo::open)."""
    if len(memo) < 58 or (len(memo) - 18) % 40:
        return None
    ks = memo_stream(key_seed, hw, memo[:16], len(memo) - 16)
    if ks is None:
        return None
    plain = bytes(x ^ y for x, y in zip(memo[16:], ks))
    if plain[0] > 1 or 18 + 40 * plain[1] != len(memo):
        return None
    return plain[0] == 1, [(int.from_bytes(plain[i:i + 8], "big"), plain[i + 8:i + 40]) for i in range(2, len(plain), 40)]


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
    ok(keccak256(b"scaas/pqz/lnp22/mlwe-d64k32-q42l4/v3").hex() == RETIRED_IDS["PQZL v3"], "keccak256 of the retired v3 label")
    ok(PQZL_ID.hex() == _S["pqzl_id"] and f"/mlwe-d64k{K}-q{LOG2Q}l4/" in _S["pqzl_label"],
       f"PQZL proofSystemId {_S['pqzl_label']} = {PQZL_ID.hex()[:8]}... (set.json)")
    ok(PQZH_ID.hex() == _S["pqzh_id"], f"PQZH proofSystemId {_S['pqzh_label']} = {PQZH_ID.hex()[:8]}... (set.json)")
    ok(not {PQZL_ID.hex(), PQZH_ID.hex()} & set(RETIRED_IDS.values()) and PQZL_ID != PQZH_ID, "ids not retired, distinct")
    plan = {"TRANSFER": "ef22f3d1", "BURN": "7383374d", "REFRESH": "f118f2df", "REGISTER": "69562a9c",
            "DISCLOSE-SENDER": "868cc07c", "DISCLOSE-RECEIVER": "d8356cfb", "DISCLOSE-AUDITOR": "d6019aa4",
            "TRANSFER-MULTI": "6f6a773a"}
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
        "BURN": build_debit("BURN", dict(hdr, amount=9, recipient=0xBEEF, salt=0), pk, ct, ct),
        "REFRESH": build_debit("REFRESH", dict(hdr, salt=0), pk, ct, ct),
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
    rejects(t[:448] + word(0) + t[480:], 1, f"auditorOn 0 on the {STMT_BYTES['TRANSFER']:,}-byte form",
            "auditorOn does not match the length")
    rejects(forms["TRANSFER0"][:448] + word(1) + forms["TRANSFER0"][480:], 1,
            f"auditorOn 1 on the {STMT_BYTES['TRANSFER0']:,}-byte form", "auditorOn does not match the length")
    rejects(t[:448] + word(2) + t[480:], 1, "auditorOn 2", "auditorOn does not match the length")
    rejects(t[:256] + word(2**64) + t[288:], 1, "fee >= 2^64", "fee >= 2^64")
    rejects(t[:576] + b"\1" + t[577:], 1, "salt word top byte set", "salt word not 16 zero bytes || salt")
    b = forms["BURN"]
    rejects(b[:591] + b"\x80" + b[592:], 2, "burn salt word byte 15 set", "salt word not 16 zero bytes || salt")
    rejects(b[:288] + word(2**64) + b[320:], 2, "burn amount >= 2^64", "amount >= 2^64")
    rejects(t[:288] + word(2**64) + t[320:], 1, "transfer amount >= 2^64 (decoder stricter than R_TX)", "amount >= 2^64")
    for form, at, name in (("TRANSFER", 288, "amount"), ("TRANSFER", 320, "recipient"), ("TRANSFER0", 320, "recipient"),
                           ("BURN", 192, "toUA"), ("BURN", 448, "auditorOn"), ("BURN", 576, "salt"),
                           ("REFRESH", 192, "toUA"), ("REFRESH", 288, "amount"), ("REFRESH", 320, "recipient"),
                           ("REFRESH", 448, "auditorOn"), ("REFRESH", 576, "salt")):
        st, w = forms[form], word(0x0101)  # low bytes only: the salt word keeps its 16-zero-byte form
        rejects(st[:at] + w + st[at + 32:], OP_BYTE[form.rstrip("0")], f"{form} {name} != 0", name + " must be 0")
    rejects(t[:640] + Q.to_bytes(8, "big") + t[648:], 1, "coefficient = q", "coefficient >= q")
    rejects(t[:640] + (2**LOG2Q).to_bytes(8, "big") + t[648:], 1, f"coefficient = 2^{LOG2Q}", "coefficient >= q")
    rejects(t, 2, "TRANSFER statement under op 2", "opTag does not belong to op")
    rejects(t[:32] + bytes(32) + t[64:], 1, "unknown proofSystemId", "unknown proofSystemId")
    d = forms["DISCLOSE-SENDER"]
    rejects(d[:224] + word(2**64) + d[256:], 4, "disclosure amount >= 2^64", "amount >= 2^64")
    # op 7 R_TXM: every built shape of both ids (fee 0 too), round trip, op 1's body at M = 1, every rule
    lens = {(m, a): multi_len(m, a) for m in (1, 2, 4, 8, 16) for a in (1, 0)}
    v3 = SET != V3 or (lens[1, 1] == 83072 and lens[1, 0] == 66560 and lens[2, 1] == 99712 and lens[2, 0] == 83072 and
                       lens[4, 1] == 132992 and lens[4, 0] == 116096 and lens[8, 1] == 215936 and lens[16, 0] == 363392)
    ok(v3 and lens[1, 1] == STMT_BYTES["TRANSFER"] and lens[1, 0] == STMT_BYTES["TRANSFER0"] and lens[2, 0] == lens[1, 1] and
       len(set(lens.values())) == 9,
       f"op 7 lengths (plan §4), distinct except (M = 1, on) = (M = 2, off) = {STMT_BYTES['TRANSFER']:,}")

    def multi(psid, m, aud, fee):
        f = dict(hdr, proofSystemId=psid, fee=fee, recipientsHash=recipients_hash(range(1, m + 1)))
        return build_multi(f, pk, [keys[j % 3][0] for j in range(m)], ct, [u] * groups(m),
                           [vs[j % 3] for j in range(m)], vs[1], pk_a=pk if aud else None,
                           v_as=[vs[2]] * m if aud else None)
    for psid, name in ((PQZL_ID, "PQZL"), (PQZH_ID, "PQZH")):
        for aud in (1, 0):
            for m in BUILT_LEGS[psid]:
                st = multi(psid, m, aud, 0 if m % 2 else 7)
                p = parse(7, st)
                back = build_multi({k: p[k] for k in MULTI_HEADER if k not in ("opTag", "M", "auditorOn")} |
                                   {"salt": p["salt"][16:]}, p["pk_f"], p["pks"], p["T"], p["us"], p["vs"], p["v_f"],
                                   pk_a=p.get("pk_a"), v_as=p.get("v_as"))
                ok(len(st) == multi_len(m, aud) and p["legs"] == m and back == st,
                   f"op 7 {name} M = {m} auditor {'on' if aud else 'off'}: build(parse(x)) = x")
    for aud in (1, 0):  # F6: M = 1 has op 1's body
        st = multi(PQZL_ID, 1, aud, 7)
        t1 = forms["TRANSFER" if aud else "TRANSFER0"]
        ok(st[HEADER_BYTES:] == build_debit("TRANSFER", hdr, pk, ct, u + vs[0] + vs[1] + (vs[2] if aud else b""),
                                              pk_t=keys[0][0], pk_a=pk if aud else None)[HEADER_BYTES:] and
           len(st) == len(t1), f"op 7 M = 1 body = op 1 body, auditor {'on' if aud else 'off'}")
    s2, s4, l4 = multi(PQZL_ID, 2, 1, 0), multi(PQZH_ID, 4, 0, 5), multi(PQZL_ID, 4, 0, 0)
    for st, op_byte, what, why in (
            (s2[:-1], 7, "length - 1", "length"), (s2 + b"\0", 7, "length + 1", "length"),
            (s2[:640] + bytes(multi_len(3, 1) - 640), 7, "M = 3 length, M word 2", "length"),
            (s2[:640] + bytes(multi_len(0, 1) - 640), 7, "M = 0 length, M word 2", "length"),
            (s2[:639], 7, "header cut", "length"),
            (s2[:320] + word(0) + s2[352:], 7, "M word 0", "M not a built leg count"),
            (s2[:320] + word(3) + s2[352:], 7, "M word 3", "M not a built leg count"),
            (s4[:320] + word(8) + s4[352:], 7, "PQZH M word 8 (not built)", "M not a built leg count"),
            (s2[:320] + word(16) + s2[352:], 7, "PQZL M word 16 (oversize only)", "M not a built leg count"),
            (s2[:320] + word(2**64 + 2) + s2[352:], 7, "M word high bits", "M not a built leg count"),
            (s2[:320] + word(4) + s2[352:], 7, "M word 4 on the M = 2 length", "length"),
            (s2[:448] + word(0) + s2[480:], 7, "auditorOn 0 on an auditor-on statement", "length"),
            (l4[:448] + word(1) + l4[480:], 7, "auditorOn 1 on an auditor-off statement", "length"),
            (s4[:448] + word(2) + s4[480:], 7, "auditorOn 2", "auditorOn does not match the length"),
            (s2[:288] + word(1) + s2[320:], 7, "amount 1", "amount must be 0"),
            (s2[:288] + word(2**64) + s2[320:], 7, "amount >= 2^64", "amount >= 2^64"),
            (s2[:256] + word(2**64) + s2[288:], 7, "fee >= 2^64", "fee >= 2^64"),
            (s2[:579] + b"\1" + s2[580:], 7, "salt word high half", "salt word not 16 zero bytes || salt"),
            (s2[:-8] + Q.to_bytes(8, "big"), 7, "coefficient = q in v_{a,M-1}", "coefficient >= q"),
            (s2[:32] + bytes(32) + s2[64:], 7, "unknown proofSystemId", "unknown proofSystemId"),
            (s2, 1, "op 7 statement under op 1", "opTag does not belong to op"),
            (t, 7, "op 1 statement under op 7", "opTag does not belong to op")):
        rejects(st, op_byte, f"op 7: {what}", why)
    one = multi(PQZL_ID, 1, 1, 0)
    two = parse(7, one[:320] + word(2) + one[352:448] + word(0) + one[480:])
    ok(two["legs"] == 2 and not two["auditor"] and two["pks"][1] == pk and two["v_f"] == vs[2],
       f"op 7 at {STMT_BYTES['TRANSFER']:,} B: the M / auditorOn words pick (1, on) or (2, off)")
    # the resample path and the counter-64 error, with lowered thresholds (the real ones are never exceeded)
    # lowered to about the mean norms (v3: 32 / 143 / 12): ceil(sqrt(n / 2)), floor(sqrt(10 n)), floor(sqrt(160))
    ls, le, l2 = math.isqrt(N // 2 - 1) + 1, math.isqrt(10 * N), math.isqrt(160)
    ctrs = [keygen_sample(bytes([i]) * 32, bs=ls, be=le)[2] for i in range(4)]
    ok(any(c >= 1 for c in ctrs), f"KeyGen resamples with ||s|| <= {ls}, ||e|| <= {le}: counters {ctrs}")
    ctrs = [enc_sample(bytes([i]) * 32, 2, bs=ls, be=le, b2=l2)[3] for i in range(4)]
    ok(any(c >= 1 for c in ctrs), f"Enc resamples with {ls} / {le} / {l2}: counters {ctrs}")
    for what, f in (("KeyGen", lambda: keygen_sample(bytes(32), bs=0)), ("Enc", lambda: enc_sample(bytes(32), 1, b2=0))):
        try:
            f()
            ok(False, f"{what}: counter 64 error")
        except ValueError as x:
            ok("counter 64" in str(x), f"{what}: counter 64 error")
    # bundle / opening sizes, entryRef / ctHash / authDigest shapes
    bl = (len(bundle(bytes(16), u, vs[0], vs[2], 1)), len(bundle(bytes(16), u, vs[0], None, 1)))
    ok(bl == (_S["lengths"]["bundle"], _S["lengths"]["bundle0"]) and (SET != V3 or bl == (16688, 16560)),
       f"bundle {bl[0]:,} / {bl[1]:,} B")
    o = opening(b"\1" * 33, b"\2" * 5)
    ok(len(o) == 64 + 32 + 64 + 32 + 32 and o[:64] == word(64) + word(160), "opening = abi.encode(bytes, bytes)")
    log(f"     entryRef(7622, 1, token, 2, 0) = {entry_ref(7622, 1, bytes(range(20)), 2, 0).hex()}")
    return bad


# ---------------------------------------------------------------- --c-keys: the C core's keys KAT
def check_c_keys(path, log):
    bad = []
    pks = {}
    n = dict.fromkeys(["shake256", "keygen", "enc", "dec", "keygen_lowered", "enc_lowered", "keygen_resampled",
                       "enc_resampled", "ctr64_errors", "enc_group_seed"], 0)
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
        elif "enc_group_seed" in r:  # P6-ANON D13: g = 0 -> seed_enc, else SHAKE256(tag || seed_enc || be4(g))[0..32)
            x = r["enc_group_seed"]
            n["enc_group_seed"] += 1
            se, g = bytes.fromhex(x["seed_enc"]), x["g"]
            want = se if g == 0 else shake256(b"SCAAS-PQZ-ENC-GROUP-V1" + se + g.to_bytes(4, "big"), 32)
            if want.hex() != x["out"]:
                bad.append(f"Enc group seed {x['seed_enc']} g {g}")
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
            or n["enc_resampled"] < 1 or n["ctr64_errors"] < 2 or n["enc_group_seed"] < 16:
        bad.append(f"too few cases: {n}")
    return bad


# ---------------------------------------------------------------- precompile decoder (pqz-stmt decode_input)
MAX_INPUT = _S["max_input"]  # D5: 393,216 at n2048-kmax1024; 524,288 at the other sets (plan 5h Task 8c part 2)
MAX_PROOF = {PQZL_ID: 98304, PQZH_ID: _S["max_proof_pqzh"]}  # PQZH: 262,144; n2560-kmax16384 327,680 (owner 2026-10-23)
REASON = {"length": "Length", "opTag does not belong to op": "OpTag", "unknown proofSystemId": "ProofSystemId",
          "fee >= 2^64": "Fee", "amount >= 2^64": "Amount", "salt word not 16 zero bytes || salt": "Salt",
          "auditorOn does not match the length": "AuditorOn", "coefficient >= q": "Coefficient",
          "M not a built leg count": "Legs"}


class Rejected(Exception):
    """args[0] = the reason under pqz-stmt's name (Reject variant; MustBeZero(field))."""


def decode_input(b):
    """u8(op) || be32(len) || stmt || proof -> (op, fields, stmt, proof), in pqz-stmt decode_input's order: length
    <= MAX_INPUT and framing (Input), op (Op; SELFTEST exactly 06 00000000), the statement rules of parse, then
    1 <= len(proof) <= MAX_PROOF(id) (ProofLength)."""
    if len(b) < 5 or len(b) > MAX_INPUT:
        raise Rejected("Input")
    op, n = b[0], int.from_bytes(b[1:5], "big")
    if n > len(b) - 5:
        raise Rejected("Input")
    stmt, proof = b[5:5 + n], b[5 + n:]
    if op == 6:
        if stmt:
            raise Rejected("Op")
        if proof:
            raise Rejected("ProofLength")
        return op, None, stmt, proof
    if not (1 <= op <= 5 or op == 7):
        raise Rejected("Op")
    try:
        f = parse(op, stmt)
    except ValueError as x:
        m = str(x)
        raise Rejected(REASON.get(m) or (f"MustBeZero({m[:-len(' must be 0')]})" if m.endswith(" must be 0") else m))
    if not 1 <= len(proof) <= MAX_PROOF[stmt[32:64]]:
        raise Rejected("ProofLength")
    return op, f, stmt, proof


# ---------------------------------------------------------------- vector files (P6e Task 11): one checker per file
# Everything but proof validity is recomputed here from seeds; proof validity is the generator's (pqz-ffi's pqz-vectors,
# the C verifiers and Ligero) and the wasm32 replay's. A file without a checker fails --check.
IDS = {"pqzl": PQZL_ID, "pqzh": PQZH_ID} if HAS_PQZH else {"pqzl": PQZL_ID}  # the ids with proofs in the set's files
STATEMENT_FILES = ["statement_transfer.json", "statement_burn.json", "statement_refresh.json",
                   "statement_register.json", "statement_disclose.json"]
# the set's PQZH preset (set.json pqzh_preset, from set.toml; n2048-kmax1024: THE preset of the D3 id; n2560-kmax16384:
# its n / k with t = 122), never read from
# the vectors; F_q elements of EB = ceil(LOG2Q / 8) bytes (6 at n2048-kmax1024 and n2304-kmax4096, 7 at n2560-kmax16384)
_P = _S.get("pqzh_preset") or {"n": 0, "k": 0, "t": 0, "ell": 0}
LIGERO = {"n": _P["n"], "k": _P["k"], "ell": _P["ell"], "t": _P["t"], "pow_bits": 16, "max_proof": MAX_PROOF[PQZH_ID]}
EB = (LOG2Q + 7) // 8
# the PQZH verifier's exact length bound per form at the set's preset (pqzh-ligero ligero.rs `limits_exact`; decisions.md
# CTR-PQZ-10, D5), per op 7 shape (M, auditorOn) (n2048-kmax1024: pqzh-ligero.md §15.2, H2)
_LIGERO_MAX = {
    "n2048-kmax1024": ((235470, 234744, 234744, 190458), {(1, 1): 235470, (1, 0): 234744, (2, 1): 235470, (2, 0): 235470,
                                                          (4, 1): 236196, (4, 0): 235470}),
    "n2304-kmax4096": ((251608, 251608, 251608, 207688), {(1, 1): 251608, (1, 0): 251608, (2, 1): 252328, (2, 0): 251608,
                                                          (4, 1): 253048, (4, 0): 252328}),
    "n2560-kmax16384": ((304266, 304266, 303412, 234238), {(1, 1): 304266, (1, 0): 304266, (2, 1): 304266,
                                                           (2, 0): 304266, (4, 1): 305120, (4, 0): 304266})}
_lm = _LIGERO_MAX.get(SET, ((0, 0, 0, 0), {}))
# (TRANSFER, TRANSFER0, BURN = REFRESH, REGISTER = the disclosures)
LIGERO_MAX = {"TRANSFER": _lm[0][0], "TRANSFER0": _lm[0][1], "BURN": _lm[0][2], "REFRESH": _lm[0][2],
              "REGISTER": _lm[0][3], "DISCLOSE-SENDER": _lm[0][3], "DISCLOSE-RECEIVER": _lm[0][3],
              "DISCLOSE-AUDITOR": _lm[0][3]}
_memo = {}


def memo(key, fn):
    if key not in _memo:
        _memo[key] = fn()
    return _memo[key]


def load(d, name):
    return memo(("file", d, name), lambda: json.load(open(os.path.join(d, name))))


def kec(b):  # keccak256 of large public bytes, cached (the pure-Python Keccak is the slow part of --check)
    return memo(("kec", b), lambda: keccak256(b))


def key(seed_hex):
    return memo(("key", seed_hex), lambda: keygen(bytes.fromhex(seed_hex)))


def enc_of(o):
    """(u, [v_j], (r, e1, e2, ctr)) of an Enc object {seed_enc, recipients, values}."""
    k = ("enc", o["seed_enc"], tuple(o["recipients"]), tuple(o["values"]))

    def f():
        smp = enc_sample(bytes.fromhex(o["seed_enc"]), len(o["recipients"]))
        u, vs = encrypt([key(x)[0] for x in o["recipients"]], [digits(v) for v in o["values"]], *smp[:3])
        return u, vs, smp
    return memo(k, f)


def fval(v):
    return v if isinstance(v, int) else bytes.fromhex(v)


def with_id(stmt, idb):
    return stmt[:32] + idb + stmt[64:]


def i8(v):
    return bytes(x & 255 for x in v)


def i16(v):
    return b"".join(x.to_bytes(2, "little", signed=True) for x in v)


def fnv(b):
    h = 2166136261
    for x in b:
        h = ((h ^ x) * 16777619) & 0xFFFFFFFF
    return f"{h:08x}"


def value(M):
    return sum(m * 16**i for i, m in enumerate(M))


def cmp(bad, what, got, want):
    if got != want:
        bad.append(f"{what}: {str(got)[:80]} != {str(want)[:80]}")


def key_wit(seed_hex):
    _, s, e, _ = key(seed_hex)
    return i8(s) + i16(e)


def build_stmt(r):
    """the statement bytes (PQZL id) of a statement-file row, from its header / words and objects."""
    form, ob = r["form"], r["objects"]
    if form == "REGISTER":
        return build_register(bytes.fromhex(r["words"]["message"]), key(ob["pk"]["keygen"])[0])
    if form.startswith("DISCLOSE"):
        u, vs, _ = enc_of(ob["ct"])
        return build_disclose(form, {k: fval(v) for k, v in r["words"].items()}, key(ob["pk"]["keygen"])[0], u,
                              vs[ob["ct"]["leg"]])
    f = {k: fval(v) for k, v in r["header"].items()}
    T = ob["T"]  # bytes (worstcase_noise.json's aggregate) or Enc + Trivial(plus_trivial)
    if not isinstance(T, bytes):
        uT, vT, _ = enc_of(T)
        T = ct_add(uT + vT[0], trivial(digits(T["plus_trivial"])))
    u, vs, _ = enc_of(ob["out"])
    pk_f = key(ob["pk_f"]["keygen"])[0]
    if form.startswith("TRANSFER"):
        pk_a = key(ob["pk_a"]["keygen"])[0] if "pk_a" in ob else None
        return build_debit("TRANSFER", f, pk_f, T, u + b"".join(vs), pk_t=key(ob["pk_t"]["keygen"])[0], pk_a=pk_a)
    return build_debit(form, f, pk_f, T, u + vs[0])


def build_wit(r):
    """the prover-API witness (pqz.h, R3) of a statement-file row, from the seeds."""
    form, ob = r["form"], r["objects"]
    if form in ("REGISTER", "DISCLOSE-RECEIVER", "DISCLOSE-AUDITOR"):
        return key_wit(ob["pk"]["keygen"])
    if form == "DISCLOSE-SENDER":
        rr, e1, e2, _ = enc_of(ob["ct"])[2]
        return i8(rr) + i16(e1) + i16(e2[ob["ct"]["leg"]])
    rr, e1, e2, _ = enc_of(ob["out"])[2]
    vals = ob["out"]["values"]
    w = key_wit(ob["pk_f"]["keygen"]) + i8(rr) + i16(e1) + b"".join(i16(x) for x in e2)
    return w + bytes(digits(vals[0])) + (bytes(digits(vals[1])) if form.startswith("TRANSFER") else b"")


def statement_rows(d):
    return {r["form"]: r for f in STATEMENT_FILES for r in load(d, f)["rows"]}


def check_matrix(j, d):
    bad = []
    a = a_bytes()
    for k, want in (("a_bytes", len(a)), ("a_keccak", kec(a).hex()), ("A_0_0_first8", A()[0][0][:8]),
                    ("A_0_0_last8", A()[0][0][56:]), (f"A_{K - 1}_{K - 1}_first8", A()[K - 1][K - 1][:8]),
                    (f"A_{K - 1}_{K - 1}_last8", A()[K - 1][K - 1][56:])):
        cmp(bad, k, j[k], want)
    return bad


def check_cbd(j, d):
    bad = []
    for r in j["rows"]:
        stream = bytes.fromhex(r["stream"])
        for p in r["parts"]:
            n = len(p["samples"])
            bits = bits_lsb(shake256(stream, (p["bit_offset"] + 2 * p["eta"] * n + 7) // 8))
            cmp(bad, f"{r['stream'][:40]} {p['what']}", cbd(bits, p["bit_offset"], p["eta"], n)[0], p["samples"])
    return bad + ([] if len(j["rows"]) >= 3 else ["too few rows"])


def check_keygen(j, d):
    bad = []
    for r in j["rows"]:
        pk, s, e, ctr = key(r["seed"])
        got = {"ctr": ctr, "pk_keccak": kec(pk).hex(), "pk_first4": dec_coeffs(pk[:32]), "s_sq": sq(s), "e_sq": sq(e)}
        for k, v in got.items():
            cmp(bad, f"seed {r['seed'][:8]} {k}", r[k], v)
    return bad


def check_enc(j, d):
    bad = []
    cts = []
    for i, r in enumerate(j["rows"]):
        u, vs, smp = enc_of(r)
        cmp(bad, f"row {i} ctr", r["ctr"], smp[3])
        cmp(bad, f"row {i} u_keccak", r["u_keccak"], kec(u).hex())
        cmp(bad, f"row {i} legs", len(r["legs"]), len(vs))
        for k, (leg, v) in enumerate(zip(r["legs"], vs)):
            M, _, val = dec(key(r["recipients"][k])[1], u + v)
            cmp(bad, f"row {i} leg {k}", (leg["v"], leg["M"], leg["value"]), (v.hex(), M, r["values"][k]))
            cmp(bad, f"row {i} leg {k} value", val, r["values"][k])
        cts.append(u + vs[0])
    tr = trivial(digits(j["trivial"]["value"]))
    cmp(bad, "trivial", j["trivial"]["ct_keccak"], kec(tr).hex())
    for o in j["ops"]:
        b = {"trivial 1000": trivial(digits(1000)), "row 5 leg 0": cts[5]}[o["b"]]
        assert o["a"] == "row 0 leg 0"
        c = ct_add(cts[0], b) if o["op"] == "add" else ct_sub(cts[0], b)
        M, _, val = dec(key(o["dec_key"])[1], c)
        cmp(bad, f"op {o['op']} {o['b']}", (o["ct_keccak"], o["M"], o["value"]), (kec(c).hex(), M, val))
    return bad


def check_statement(j, d):
    bad = []
    for r in j["rows"]:
        form = r["form"]
        st = build_stmt(r)
        cmp(bad, f"{form} stmt", r["stmt"], st.hex())
        cmp(bad, f"{form} stmt_bytes / op", (r["stmt_bytes"], r["op"]), (STMT_BYTES[form], OP_BYTE[form.rstrip("0")]))
        if form.startswith("DISCLOSE"):  # the disclosed ciphertext is the transfer's out (leg 0 = v_t, leg 2 = v_a)
            ct = dict(r["objects"]["ct"])
            leg = ct.pop("leg")
            cmp(bad, f"{form} ct = TRANSFER out, leg", (ct, leg), (statement_rows(d)["TRANSFER"]["objects"]["out"],
                                                                  2 if form == "DISCLOSE-AUDITOR" else 0))
        for n, idb in IDS.items():
            s = with_id(st, idb)
            parse(OP_BYTE[form.rstrip("0")], s)
            cmp(bad, f"{form} {n} stmt_keccak", r["stmt_keccak"][n], kec(s).hex())
            cmp(bad, f"{form} {n} auth_digest", r["auth_digest"][n], keccak256(b"SCAAS-PQZ-AUTH-V1", kec(s)).hex())
        if form.startswith("TRANSFER"):
            h = {k: fval(v) for k, v in r["header"].items()}
            cmp(bad, f"{form} entry_ref", r["entry_ref"],
                entry_ref(h["chainId"], h["chainUid"], h["token"], h["fromUA"], h["sendCounter"]).hex())
            f = parse(1, st)
            b = bundle(h["salt"], f["u"], f["v_t"], f.get("v_a"), h["toUA"])
            cmp(bad, f"{form} bundle", (r["bundle_bytes"], r["bundle_keccak"]), (len(b), kec(b).hex()))
    return bad


# ---------------------------------------------------------------- op 7 R_TXM vectors (P6-ANON S4, plan D15)
MULTI_FILE = "statement_transfer_multi.json"
# (case, M, auditorOn): every built shape (one real leg, its position varying by shape), a two-real-leg row, an
# all-decoy row, a group-boundary row (real legs 3 and 4: groups 0 and 1)
MULTI_CASES = [(f"M{m}-{'on' if a else 'off'}", m, a) for a in (1, 0) for m in (1, 2, 4, 8)] + \
    [("M2-off-two-real", 2, 0), ("M4-off-decoys", 4, 0), ("M8-on-boundary", 8, 1)]
# the PQZH verifier's exact length bound per op 7 shape at the set's preset (_LIGERO_MAX above)
LIGERO_MAX_MULTI = _lm[1]


def multi_rows(d):
    return {r["case"]: r for r in load(d, MULTI_FILE)["rows"]}


def multi_ids(m):
    return [n for n, idb in IDS.items() if m in BUILT_LEGS[idb]]


def multi_build(r):
    """(stmt (PQZL id), witness, memo, header words, enc) of a statement_transfer_multi.json row from its seeds: keys,
    T, the multi-group Enc, recipientsHash of objects.uas, the memo under memo.key_seed and its memoHash."""
    def f():
        ob, out = r["objects"], r["objects"]["out"]
        h = {k: fval(v) for k, v in r["header"].items()}
        pk_f = key(ob["pk_f"]["keygen"])[0]
        pks = [key(x["keygen"])[0] for x in ob["pks"]]
        pk_a = key(ob["pk_a"]["keygen"])[0] if "pk_a" in ob else None
        uT, vT, _ = enc_of(ob["T"])
        T = ct_add(uT + vT[0], trivial(digits(ob["T"]["plus_trivial"])))
        amounts = out["values"]
        e = enc_multi(pk_f, digits(out["value_f"]), [(pk, digits(a)) for pk, a in zip(pks, amounts)], pk_a,
                      bytes.fromhex(out["seed_enc"]))
        uas = [word(bytes.fromhex(x)) for x in ob["uas"]]
        h["recipientsHash"] = recipients_hash(uas)
        hw = {k: word(h.get(k, 0)) for k in MULTI_HEADER}
        mm = memo_seal(bytes.fromhex(r["memo"]["key_seed"]), hw, pk_a is not None, list(zip(amounts, uas)))
        h["memoHash"] = keccak256(mm)
        st = build_multi(h, pk_f, pks, T, e["us"], e["vs"], e["v_f"], pk_a=pk_a,
                         v_as=e["v_as"] if pk_a is not None else None)
        w = key_wit(ob["pk_f"]["keygen"]) + b"".join(i8(x) + i16(y) for x, y in zip(e["rs"], e["e1s"])) + \
            b"".join(i16(x) for x in e["e2"] + [e["e2_f"]] + e["e2_a"]) + \
            b"".join(bytes(digits(a)) for a in amounts + [out["value_f"]])
        return st, w, mm, hw, e, h, T
    return memo(("multi", json.dumps([r["header"], r["objects"], r["memo"]], sort_keys=True)), f)


def check_multi(j, d):
    bad = []
    seen = []
    for r in j["rows"]:
        case, m, a = r["case"], r["M"], r["auditorOn"]
        seen.append((case, m, a))
        st, w, mm, hw, e, h, T = multi_build(r)
        ob = r["objects"]
        cmp(bad, f"{case} stmt", r["stmt"], st.hex())
        cmp(bad, f"{case} form / op / bytes / M / auditorOn",
            (r["form"], r["op"], r["stmt_bytes"], len(ob["pks"]), len(ob["uas"]), len(ob["out"]["values"]), "pk_a" in ob),
            ("TRANSFER-MULTI", 7, multi_len(m, a), m, m, m, bool(a)))
        cmp(bad, f"{case} header recipientsHash / memoHash", (r["header"]["recipientsHash"], r["header"]["memoHash"]),
            (h["recipientsHash"].hex(), h["memoHash"].hex()))
        cmp(bad, f"{case} memo", (r["memo"]["memo"], r["memo"]["memo_bytes"]), (mm.hex(), 18 + 40 * m))
        legs = list(zip(ob["out"]["values"], [word(bytes.fromhex(x)) for x in ob["uas"]]))
        cmp(bad, f"{case} memo opens", memo_open(bytes.fromhex(r["memo"]["key_seed"]), hw, mm), (a == 1, legs))
        cmp(bad, f"{case} groups", r["objects"]["out"]["groups"],
            [{"seed_enc_g": enc_group_seed(bytes.fromhex(ob["out"]["seed_enc"]), g).hex(), "ctr": c}
             for g, c in enumerate(e["ctrs"])])
        _, _, bal = dec(key(ob["pk_f"]["keygen"])[1], T)
        cmp(bad, f"{case} debit: Dec(T) = value_f + sum + fee", bal,
            ob["out"]["value_f"] + sum(ob["out"]["values"]) + r["header"].get("fee", 0))
        cmp(bad, f"{case} ids", r["ids"], multi_ids(m))
        for n, idb in IDS.items():
            s = with_id(st, idb)
            try:
                p = parse(7, s)
                got = (p["legs"], p["auditor"])
            except ValueError as x:
                got = REASON.get(str(x), str(x))
            cmp(bad, f"{case} {n} parse", got, (m, a) if n in r["ids"] else "Legs")
        cmp(bad, f"{case} stmt_keccak ids", sorted(r["stmt_keccak"]), sorted(r["ids"]))
        cmp(bad, f"{case} auth_digest ids", sorted(r["auth_digest"]), sorted(r["ids"]))
        for n in r["ids"]:
            s = with_id(st, IDS[n])
            cmp(bad, f"{case} {n} stmt_keccak", r["stmt_keccak"][n], kec(s).hex())
            cmp(bad, f"{case} {n} auth_digest", r["auth_digest"][n], keccak256(b"SCAAS-PQZ-AUTH-V1", kec(s)).hex())
        cmp(bad, f"{case} entry_ref", r["entry_ref"],
            entry_ref(h["chainId"], h["chainUid"], h["token"], h["fromUA"], h["sendCounter"]).hex())
    cmp(bad, "cases", seen, MULTI_CASES)
    rows = multi_rows(d)
    for o in j["memo_open"]:
        r = rows[o["case"]]
        b = bytearray(multi_build(r)[2])
        for ed in o["edits"]:
            (k, v), = ed.items()
            if k == "resize":
                del b[v:]
                b += bytes(v - len(b))
            elif k == "flip":
                b[v[0]] ^= 1 << v[1]
            else:
                raise ValueError("edit " + k)
        got = memo_open(bytes.fromhex(o["key_seed"]), multi_build(r)[3], bytes(b))
        got = "none" if got is None else {"auditorOn": got[0], "legs": [[x, ua.hex()] for x, ua in got[1]]}
        cmp(bad, "memo_open " + o["name"], o["result"], got)
    if {type(o["result"]) for o in j["memo_open"]} != {str, dict}:
        bad.append("memo_open: need opened and refused memos")
    return bad


def proof_framing(idn, form, proof, params, row_max=None, bound=None):
    """what can be checked of a proof without verifying it: length within MAX_PROOF(id), PQZL ends in the coder's
    final 1-bit (last byte != 0), PQZH: test polynomials w, q, h canonical (EB-byte BE < q), the exact bound."""
    bad = []
    if not 1 <= len(proof) <= MAX_PROOF[IDS[idn]]:
        bad.append(f"{form}: proof length {len(proof)}")
    if idn == "pqzl" and proof[-1] == 0:
        bad.append(f"{form}: PQZL proof ends in a zero byte")
    if idn == "pqzh":
        cmp(bad, "PQZH params (the set's preset)", {k: params[k] for k in LIGERO}, LIGERO)
        k, ell = params["k"], params["ell"]
        ne = 4 * (2 * (2 * k - 1) + (2 * k - 1 - ell))
        if len(proof) <= 32 + EB * ne + 8 or any(int.from_bytes(proof[32 + EB * i:32 + EB * (i + 1)], "big") >= Q
                                                  for i in range(ne)):
            bad.append(f"{form}: PQZH test polynomials not canonical")
        if row_max is not None and not (len(proof) <= row_max == (bound or LIGERO_MAX[form]) <= LIGERO["max_proof"]):
            bad.append(f"{form}: max_proof_len {row_max}")
    return bad


def check_proofs(j, d):
    bad = []
    idn = "pqzl" if bytes.fromhex(j["proof_system_id"]) == PQZL_ID else "pqzh"
    cmp(bad, "file name", j["file"], f"proof_{idn}.json")
    if idn == "pqzl":
        cmp(bad, "params", j["params"], {"max_proof": MAX_PROOF[PQZL_ID]})
    srows = statement_rows(d)
    tx = bytes.fromhex(srows["TRANSFER"]["stmt"])
    f = parse(1, tx)
    h = srows["TRANSFER"]["header"]
    bnd = bundle(bytes.fromhex(h["salt"]), f["u"], f["v_t"], f["v_a"], bytes.fromhex(h["toUA"]))
    seen, seen_m = [], []
    for r in j["rows"]:
        form = r["form"]
        if form == "TRANSFER-MULTI":  # op 7 (P6-ANON S4)
            case = r["case"]
            seen_m.append(case)
            sr = multi_rows(d)[case]
            cmp(bad, f"{case} statement", (r["statement"], r["op"]), ({"file": MULTI_FILE, "case": case}, 7))
            st = with_id(bytes.fromhex(sr["stmt"]), IDS[idn])
            cmp(bad, f"{case} stmt_keccak", r["stmt_keccak"], kec(st).hex())
            w = multi_build(sr)[1]
            cmp(bad, f"{case} wit", (r["wit"], r["wit_keccak"]), (w.hex(), keccak256(w).hex()))
            proof = bytes.fromhex(r["proof"])
            cmp(bad, f"{case} proof", (r["proof_bytes"], r["proof_keccak"], r["proof_fnv"]),
                (len(proof), kec(proof).hex(), fnv(proof)))
            try:
                decode_input(precompile_input(7, st, proof))
            except Rejected as x:
                bad.append(f"{case}: the honest input is rejected: {x}")
            bad += proof_framing(idn, case, proof, j["params"], r.get("max_proof_len"),
                                 LIGERO_MAX_MULTI.get((sr["M"], sr["auditorOn"])))
            cmp(bad, f"{case} expect", r["expect"], True)
            continue
        sr = load(d, r["statement"]["file"])["rows"]
        sr = [x for x in sr if x["form"] == r["statement"]["form"] == form][0]
        st = with_id(bytes.fromhex(sr["stmt"]), IDS[idn])
        cmp(bad, f"{form} stmt_keccak", r["stmt_keccak"], kec(st).hex())
        w = build_wit(sr)
        cmp(bad, f"{form} wit", (r["wit"], r["wit_keccak"]), (w.hex(), keccak256(w).hex()))
        if form == "REGISTER":
            cmp(bad, "REGISTER rnd32 (self-test)", r["rnd32"], "53" * 32)
        proof = bytes.fromhex(r["proof"])
        cmp(bad, f"{form} proof", (r["proof_bytes"], r["proof_keccak"], r["proof_fnv"]),
            (len(proof), kec(proof).hex(), fnv(proof)))
        op = OP_BYTE[form.rstrip("0")]
        cmp(bad, f"{form} op", r["op"], op)
        try:
            decode_input(precompile_input(op, st, proof))
        except Rejected as x:
            bad.append(f"{form}: the honest input is rejected: {x}")
        bad += proof_framing(idn, form, proof, j["params"], r.get("max_proof_len"))
        if form.startswith("DISCLOSE"):
            o = opening(bnd, proof)
            cmp(bad, f"{form} opening", (r["opening_bytes"], r["opening_keccak"]), (len(o), kec(o).hex()))
        cmp(bad, f"{form} expect", r["expect"], True)
        seen.append(form)
    cmp(bad, "forms", sorted(seen), sorted(STMT_BYTES))
    cmp(bad, "op 7 cases", seen_m, [c for c, m, _ in MULTI_CASES if idn in multi_ids(m)])
    return bad


def apply_edits(r, stmts, proofs):
    """negative.json: the honest input of (form, id) with the row's edits (see the file's description)."""
    if r["form"] == "-":
        op, s, p = 0, b"", b""
    elif r["form"] == "TRANSFER-MULTI":
        op, s, p = 7, with_id(stmts[r["case"]], IDS[r["id"]]), proofs[r["case"], r["id"]]
    else:
        op, s, p = OP_BYTE[r["form"].rstrip("0")], with_id(stmts[r["form"]], IDS[r["id"]]), proofs[r["form"], r["id"]]
    s, p = bytearray(s), bytearray(p)
    lenf = raw = size = None
    for e in r["edits"]:
        (k, v), = e.items()
        if k == "op":
            op = v
        elif k == "proof_from":
            p = bytearray(proofs[v, r["id"]])
        elif k == "proof_set":
            b = bytes.fromhex(v[1])
            p[v[0]:v[0] + len(b)] = b
        elif k == "proof_copy":
            p[v[1]:v[1] + v[2]] = p[v[0]:v[0] + v[2]]
        elif k == "proof_swap":
            x = p[v[0]:v[0] + v[2]]
            p[v[0]:v[0] + v[2]] = p[v[1]:v[1] + v[2]]
            p[v[1]:v[1] + v[2]] = x
        elif k == "stmt_set":
            b = bytes.fromhex(v[1])
            s[v[0]:v[0] + len(b)] = b
        elif k in ("stmt_resize", "proof_resize"):
            x = s if k == "stmt_resize" else p
            del x[v:]
            x += bytes(v - len(x))
        elif k in ("stmt_flip", "proof_flip"):
            (s if k == "stmt_flip" else p)[v[0]] ^= 1 << v[1]
        elif k == "len_field":
            lenf = v
        elif k == "input_resize":
            size = v
        elif k == "raw":
            raw = bytes.fromhex(v)
        else:
            raise ValueError("edit " + k)
    b = raw if raw is not None else bytes([op]) + (len(s) if lenf is None else lenf).to_bytes(4, "big") + s + p
    if size is not None:
        b = b[:size] + bytes(max(0, size - len(b)))
    return b


def parse_opening(b):
    """pqz-stmt parse_opening: the one canonical abi.encode(bytes, bytes) -> (bundle, proof), else Rejected(Opening)."""
    def w(i):
        if i + 32 > len(b) or int.from_bytes(b[i:i + 32], "big") >= 2**64:
            raise Rejected("Opening")
        return int.from_bytes(b[i:i + 32], "big")

    def tail(at):
        n = w(at)
        start, padded = at + 32, at + 32 + -(-n // 32) * 32
        if padded > len(b) or any(b[start + n:padded]):
            raise Rejected("Opening")
        return b[start:start + n], padded
    if w(0) != 64:
        raise Rejected("Opening")
    bnd, nxt = tail(64)
    if w(32) != nxt:
        raise Rejected("Opening")
    proof, end = tail(nxt)
    if end != len(b):
        raise Rejected("Opening")
    return bnd, proof


def check_negative(j, d):
    bad = []
    stmts = {f: bytes.fromhex(r["stmt"]) for f, r in statement_rows(d).items()}
    stmts |= {c: bytes.fromhex(r["stmt"]) for c, r in multi_rows(d).items()}
    proofs = {(r.get("case", r["form"]), n): bytes.fromhex(r["proof"]) for n in IDS
              for r in load(d, f"proof_{n}.json")["rows"]}
    cmp(bad, "max_input", j["max_input"], MAX_INPUT)
    names = set()
    # every honest input (a multi case name has op 7)
    honest = {precompile_input(OP_BYTE.get(f.rstrip("0"), 7), with_id(stmts[f], IDS[n]), proofs[f, n]) for f, n in proofs}
    for r in j["rows"]:
        if r["name"] + r["id"] in names:
            bad.append("duplicate row " + r["name"])
        names.add(r["name"] + r["id"])
        # the id names the base input's system; a raw input (form "-") has none (8d part 1: a tamper of a raw row's id
        # went unnoticed)
        cmp(bad, r["name"] + " id", r["id"], "-" if r["form"] == "-" else r["id"] if r["id"] in IDS else "pqzl | pqzh")
        b = apply_edits(r, stmts, proofs)
        cmp(bad, r["name"] + " input", (r["input_bytes"], r["input_sha3"]), (len(b), hashlib.sha3_256(b).hexdigest()))
        try:
            decode_input(b)
            why = "verify"
            if b in honest:
                bad.append(r["name"] + ": the edits give an honest input")
        except Rejected as x:
            why = x.args[0]
        cmp(bad, f"{r['name']} ({r['id']}) reason", r["reason"], why)
        cmp(bad, f"{r['name']} ({r['id']}) expect", r["expect"], "revert" if len(b) > MAX_INPUT else "0")
    # the required coverage: every decoder reason (pqz-stmt Reject), verifier rejections, the revert, and per (form, id)
    # lengths +- 1, every other op byte, an unknown and the other id, the proof edits
    need = {"Op", "OpTag", "ProofSystemId", "Length", "Fee", "Amount", "Salt", "AuditorOn", "Coefficient", "Input",
            "ProofLength", "Legs", "verify"} | {f"MustBeZero({f})" for f in ("amount", "recipient", "toUA", "auditorOn", "salt")}
    got = {r["reason"] for r in j["rows"]}
    if need - got or "revert" not in {r["expect"] for r in j["rows"]}:
        bad.append(f"missing reasons: {sorted(need - got)}")
    for f in STMT_BYTES:
        op = OP_BYTE[f.rstrip("0")]
        want = [f"{f}: statement length - 1", f"{f}: statement length + 1", f"{f}: unknown proofSystemId (zero word)",
                f"{f}: the other system's proofSystemId", f"{f}: proof truncated by 1 byte",
                f"{f}: proof extended by 1 zero byte", f"{f}: proof byte 0 bit 0 flipped",
                f"{f}: proof middle byte bit 3 flipped", f"{f}: proof last byte bit 7 flipped"]
        want += [f"{f}: under op {o}" for o in range(1, 6) if o != op]
        for n in IDS:
            have = {r["name"] for r in j["rows"] if r["id"] == n}
            if set(want) - have:
                bad.append(f"{f} {n}: missing rows {sorted(set(want) - have)}")
    for c, m, a in MULTI_CASES[:8]:  # op 7 (P6-ANON S4): per built shape and id
        want = [f"{c}: {x}" for x in ("statement length - 1", "statement length + 1", "unknown proofSystemId (zero word)",
                                      "the other system's proofSystemId", "proof truncated by 1 byte",
                                      "proof extended by 1 zero byte", "proof byte 0 bit 0 flipped",
                                      "proof middle byte bit 3 flipped", "proof last byte bit 7 flipped")]
        want += [f"{c}: under op {o}" for o in range(7)]
        for n in multi_ids(m):
            have = {r["name"] for r in j["rows"] if r["id"] == n and r["form"] == "TRANSFER-MULTI" and r["case"] == c}
            if set(want) - have:
                bad.append(f"{c} {n}: missing rows {sorted(set(want) - have)}")
    # the disclosure opening codec (pqz-stmt parse_opening)
    tx = statement_rows(d)["TRANSFER"]
    f = parse(1, bytes.fromhex(tx["stmt"]))
    bnd = bundle(bytes.fromhex(tx["header"]["salt"]), f["u"], f["v_t"], f["v_a"], bytes.fromhex(tx["header"]["toUA"]))
    base = opening(bnd, proofs["DISCLOSE-SENDER", "pqzl"])
    for r in j["openings"]:
        b = bytearray(base)
        for e in r["edits"]:
            (k, v), = e.items()
            if k == "set":
                x = bytes.fromhex(v[1])
                b[v[0]:v[0] + len(x)] = x
            else:
                del b[v:]
                b += bytes(v - len(b))
        try:
            got = "ok" if parse_opening(bytes(b)) == (bnd, proofs["DISCLOSE-SENDER", "pqzl"]) else "different"
        except Rejected as x:
            got = x.args[0]
        cmp(bad, "opening " + r["name"], r["reason"], got)
    if sorted({r["reason"] for r in j["openings"]}) != ["Opening", "ok"]:
        bad.append("openings: need the canonical one and Opening rejections")
    return bad


def dft(a, W, stride=1):
    """evaluations at omega^0..omega^(n-1) (W = powers of omega, len n) of the polynomial with coefficients a:
    mixed-radix decimation in time over the radices of Ligero's domains (2, 19, 43, 431)."""
    n = len(a)
    if n == 1:
        return list(a)
    p = next(x for x in (2, 19, 43, 431) if n % x == 0)
    m = n // p
    subs = [dft(a[r::p], W, stride * p) for r in range(p)]
    N = len(W)
    return [sum(subs[r][k % m] * W[stride * r * k % N] for r in range(p)) % Q for k in range(n)]


def check_selftest(j, d):
    bad = []
    a_digest = kec(a_bytes())
    pk, s, e, _ = key(j["seed_key"])
    u, vs, _ = enc_of({"seed_enc": j["seed_enc"], "recipients": [j["seed_key"]], "values": [j["msg_value"]]})
    ct = u + vs[0]
    M, _, val = dec(s, ct)
    # a set without PQZH: no Ligero FFT (n 0, empty, not ok) and both PQZH results 0 (pqz-ffi selftest.rs)
    n = 1634 if HAS_PQZH else 0
    if n:
        om = pow(3, (Q - 1) // n, Q)
        W = [pow(om, i, Q) for i in range(n)]
        f = dft([(i * i * 0x9E3779B9 + 1) % Q for i in range(n)], W)
    else:
        f = []
    fb = b"".join(x.to_bytes(EB, "big") for x in f)  # EB-byte elements (6 at n2048-kmax1024, 7 at n2560-kmax16384)
    kat = keccak256(a_digest, kec(pk), kec(ct), bytes(M), kec(fb), bytes([HAS_PQZH]))
    for k, want in (("input", "0600000000"), ("message", keccak256(b"SCAAS-PQZ-SELFTEST-V1").hex()),
                    ("a_digest", a_digest.hex()), ("pk_keccak", kec(pk).hex()), ("ct_keccak", kec(ct).hex()),
                    ("M", M), ("fft", {"n": n, "keccak": kec(fb).hex(), "ok": HAS_PQZH}), ("kat_digest", kat.hex()),
                    ("results", [1, 0, int(HAS_PQZH), 0]), ("hash", keccak256(kat, bytes(j["results"])).hex()),
                    ("rnd32", "53" * 32)):
        cmp(bad, k, j[k], want)
    cmp(bad, "Dec value", val, j["msg_value"])
    cmp(bad, "a_digest = matrix.json", j["a_digest"], load(d, "matrix.json")["a_keccak"])
    reg = statement_rows(d)["REGISTER"]
    cmp(bad, "REGISTER statement = self-test's", (reg["words"]["message"], reg["objects"]["pk"]["keygen"]),
        (j["message"], j["seed_key"]))
    for n in IDS:
        row = [r for r in load(d, f"proof_{n}.json")["rows"] if r["form"] == "REGISTER"][0]
        cmp(bad, f"{n} register", j["register"][n]["proof_keccak"], row["proof_keccak"])
        cmp(bad, f"{n} results", [j["register"][n]["valid"], j["register"][n]["invalid"]], [1, 0])
    return bad


MARGIN_E = f"margin_2_{E_BITS}"  # the worst-case files' margin against the proven range 2^E_BITS (v3: margin_2_24)


def rot(x):  # coefficient-0 weights per poly: (x * y)[0] = sum_k rot(x)_k y_k in Z[X]/(X^64 + 1)
    return [x[i] if i % 64 == 0 else -x[i - i % 64 + 64 - i % 64] for i in range(N)]


def align_r(w, b=B_S * B_S):
    from fractions import Fraction
    c = sorted(((Fraction(-abs(w[k]), 2 * a + 1), k, a) for k in range(N) if w[k] for a in range(B_S)))
    r, left = [0] * N, b
    for _, k, a in c:
        if 2 * a + 1 <= left:
            left -= 2 * a + 1
            r[k] += 1 if w[k] > 0 else -1
    return r


def align_e1(z, gen, k, b=B_E * B_E):
    S = [i for i in range(N) if z[i]]
    L = 0
    while (L + 1) ** 2 * len(S) <= b:
        L += 1
    X = (b - L * L * len(S)) // (2 * L + 1)
    pr = shake256(b"SCAAS-PQZ-WORSTCASE-V1" + gen + k.to_bytes(4, "big"), 4 * N)
    e1 = [0] * N
    for rank, i in enumerate(sorted(S, key=lambda i: (int.from_bytes(pr[4 * i:4 * i + 4], "big"), i))):
        e1[i] = (-1 if z[i] > 0 else 1) * (L + (rank < X))
    return e1


def from_sparse(sp, n=N):
    v = [0] * n
    for poly, c, x in sp:
        v[64 * poly + c] = x
    return v


def ratio(a, b):  # as the generator writes it: truncated to 2 decimals
    return f"{a // b}.{a * 100 // b % 100:02d}"


def proofs_ok(bad, what, o, op, st):
    """both ids' proof objects of a statement (PQZL-id bytes): hashes, framing, the decoder accepts."""
    for n, idb in IDS.items():
        sn = with_id(st, idb)
        cmp(bad, f"{what} {n} stmt_keccak", o["stmt_keccak"][n], kec(sn).hex())
        proof = bytes.fromhex(o[n]["proof"])
        cmp(bad, f"{what} {n} proof", (o[n]["proof_bytes"], o[n]["proof_keccak"], o[n]["proof_fnv"]),
            (len(proof), kec(proof).hex(), fnv(proof)))
        try:
            decode_input(precompile_input(op, sn, proof))
        except Rejected as x:
            bad.append(f"{what} {n} rejected: {x}")
        bad += proof_framing(n, what, proof, dict(LIGERO))


def check_debit(bad, what, db, T):
    cmp(bad, f"{what} debit form / op / T", (db["form"], db["op"], db["objects"]["T"]),
        ("TRANSFER", 1, "the aggregate T above"))
    row = dict(db, objects=dict(db["objects"], T=T))
    st = build_stmt(row)
    cmp(bad, f"{what} debit stmt", (db["stmt"], db["stmt_bytes"]), (st.hex(), len(st)))
    wt = build_wit(row)
    cmp(bad, f"{what} debit wit", (db["wit"], db["wit_keccak"]), (wt.hex(), keccak256(wt).hex()))
    proofs_ok(bad, what + " debit", db, 1, st)


def check_bound(bad, j, b):
    """the worst case the verifier accepts: an attacker key at the norm bounds, credits at B_FRESH exactly."""
    s, e = from_sparse(b["receiver"]["s"]), from_sparse(b["receiver"]["e"])
    if not (sq(s) <= B_S**2 and sq(e) <= B_E**2 and all(abs(x) <= 1 for x in s[:64]) and abs(min(s)) <= 127):
        bad.append("bound receiver key outside R_REG's norms")
    t = mul_A(polys(s))
    pk = enc_vec([[(t[i][k] + e[D * i + k]) % Q for k in range(D)] for i in range(K)])
    _memo[("key", "receiver")] = (pk, s, e, 0)  # the label the statements' objects use
    cmp(bad, "bound pk", b["receiver"]["pk_keccak"], kec(pk).hex())
    rg = b["receiver"]["register"]
    reg = build_register(bytes.fromhex(rg["message"]), pk)
    cmp(bad, "bound register wit", rg["wit"], (i8(s) + i16(e)).hex())
    proofs_ok(bad, "bound register", rg, 3, reg)
    c = b["credit"]
    r, e1, e2 = from_sparse(c["r"]), from_sparse(c["e1"]), c["e2"]
    if not (sq(r) <= B_S**2 and sq(e1) <= B_E**2 and sq(e2) <= B_2**2 and len(e2) == 16):
        bad.append("bound credit vectors outside R_TX's norms")
    u, vs = encrypt([pk], [digits(c["value"])], r, e1, [e2])
    ct = u + vs[0]
    noise = dec(s, ct)[1]
    cmp(bad, "bound credit", (c["ct_keccak"], c["noise0"]), (kec(ct).hex(), noise[0]))
    cmp(bad, "bound credit noise = B_FRESH", c["noise0"], j["b_fresh"])
    sd = b["sender"]
    T_s = ct_add(enc_of(sd["T"])[0] + enc_of(sd["T"])[1][0], trivial(digits(sd["T"]["plus_trivial"])))
    pk_f, pk_a = key(sd["key"]["keygen"])[0], key(sd["auditor"]["keygen"])[0]
    u2, vs2 = encrypt([pk, pk_f, pk_a], [digits(x) for x in sd["out_values"]], r, e1, [e2, [0] * 16, [0] * 16])
    cmp(bad, "bound sender out = the credit", (u2 + vs2[0]).hex(), ct.hex())
    sw = key_wit(sd["key"]["keygen"]) + i8(r) + i16(e1) + i16(e2) + i16([0] * 32) + bytes(digits(sd["out_values"][0])) \
        + bytes(digits(sd["out_values"][1]))
    cmp(bad, "bound sender wit", (sd["wit"], sd["wit_keccak"]), (sw.hex(), keccak256(sw).hex()))
    cmp(bad, "bound sender rows", [x["credit"] for x in sd["rows"]], [0, j["credits_n"] - 1])
    for x in sd["rows"]:
        f = {k: fval(v) for k, v in sd["header"].items()}
        f["sendCounter"] = x["sendCounter"]
        st = build_debit("TRANSFER", f, pk_f, T_s, u2 + b"".join(vs2), pk_t=pk, pk_a=pk_a)
        cmp(bad, f"bound sender stmt {x['credit']}", x["stmt"], st.hex())
        proofs_ok(bad, f"bound sender {x['credit']}", x, 1, st)
    nc = j["credits_n"]
    T = ct_add(b"".join(x.to_bytes(8, "big") for x in [(nc * c) % Q for c in dec_coeffs(ct)]),
               trivial(digits(b["plain_used"])))
    M, tn, val = dec(s, T)
    mx = max(map(abs, tn))
    cmp(bad, "bound T", (b["T_keccak"], b["T_M"], b["T_noise"], b["max_abs_noise"]), (kec(T).hex(), M, tn, mx))
    cmp(bad, f"bound T noise = {nc:,} * B_FRESH", mx, nc * j["b_fresh"])
    cmp(bad, "bound value", val, (nc + 1) * c["value"])
    cmp(bad, "bound margins", (b[MARGIN_E], b["margin_mint"]), (ratio(2**E_BITS, mx), ratio(j["mint_threshold"], mx)))
    if not (mx < 2**E_BITS and max(M) < 2**M_BITS):
        bad.append(f"bound T outside the proven ranges: noise {mx}, M {max(M)}")
    check_debit(bad, "bound", b["debit"], T)


def check_illustrative(bad, j, b):
    pk, s, e, _ = key(b["receiver_seed"])
    gen, nc, credit = bytes.fromhex(b["generator_seed"]), j["credits_n"], b["credit_value"]
    cmp(bad, "illustrative credits", len(b["credits_ct_keccak"]), nc)
    w, z = rot(e), rot(s)
    r = align_r(w)
    e2 = [64] + [0] * 15
    rp = polys(r)
    ur = [c for p in mul_AT(rp) for c in p]
    a = dot(dec_vec(pk), rp)
    v1 = [(a[i] + e2[i] + DELTA * m) % Q for i, m in enumerate(digits(credit))]
    se1 = [0] * N
    e1sq = set()
    for k in range(nc):
        e1 = align_e1(z, gen, k)
        e1sq.add(sq(e1))
        se1 = [x + y for x, y in zip(se1, e1)]
        if k % 32 == 0 or k == nc - 1:  # ctHash on a sample (pure-Python Keccak); the aggregate T covers every credit
            ct = enc_vec(polys([(x + y) % Q for x, y in zip(ur, e1)])) + enc_poly(v1, 16)
            cmp(bad, f"credit {k} ctHash", b["credits_ct_keccak"][k], kec(ct).hex())
            if k == 0:
                cmp(bad, "credit noise0", dec(s, ct)[1][0], b["credit_noise0"])
    e10 = align_e1(z, gen, 0)
    cmp(bad, "credit_norms_sq", b["credit_norms_sq"], {"r": sq(r), "e1": e1sq.pop() if len(e1sq) == 1 else -1,
                                                       "e2": 4096})
    cmp(bad, "credit noise0 formula", b["credit_noise0"],
        sum(x * y for x, y in zip(w, r)) - sum(x * y for x, y in zip(z, e10)) + 64)
    cmp(bad, "credits_keccak", b["credits_keccak"],
        keccak256(b"".join(bytes.fromhex(h) for h in b["credits_ct_keccak"])).hex())
    uT = [(nc * x + y) % Q for x, y in zip(ur, se1)]
    vT = [(nc * x + DELTA * m) % Q for x, m in zip(v1, digits(b["plain_used"]))]
    T = enc_vec(polys(uT)) + enc_poly(vT, 16)
    M, noise, val = dec(s, T)
    mx = max(map(abs, noise))
    cmp(bad, "T", (b["T_keccak"], b["T_M"], b["T_noise"], b["max_abs_noise"]), (kec(T).hex(), M, noise, mx))
    cmp(bad, "T value", val, (nc + 1) * credit)
    cmp(bad, "margin", b[MARGIN_E], ratio(2**E_BITS, mx))
    if not (mx < 2**E_BITS and max(M) < 2**M_BITS):
        bad.append(f"T outside the proven ranges: noise {mx}, M {max(M)}")
    check_debit(bad, "illustrative", b["debit"], T)


def check_fee0(j, d):
    """fee = 0 (owner 2026-10-14): every debit form with a fee word, honest, both ids."""
    bad = check_statement(j, d)
    for r in j["rows"]:
        form = r["form"]
        cmp(bad, f"{form} fee / beneficiary", (r["header"].get("fee"), "beneficiaryUA" in r["header"]), (0, False))
        st = build_stmt(r)
        w = build_wit(r)
        cmp(bad, f"{form} wit", (r["wit"], r["wit_keccak"]), (w.hex(), keccak256(w).hex()))
        proofs_ok(bad, form, r, OP_BYTE[form.rstrip("0")], st)
    cmp(bad, "forms", sorted(r["form"] for r in j["rows"]), ["BURN", "REFRESH", "TRANSFER", "TRANSFER0"])
    return bad


def check_worstcase(j, d):
    bad = []
    cmp(bad, "constants", (j["k_max"], j["credits_n"], j["b_fresh"], j["e_T_range"], j["mint_threshold"]),
        (K_MAX, K_MAX - 1, B_FRESH, 2**E_BITS, DELTA - 2**E_BITS))
    check_bound(bad, j, j["bound"])
    check_illustrative(bad, j, j["illustrative"])
    return bad


CHECKERS = {MULTI_FILE: check_multi, "matrix.json": check_matrix, "cbd.json": check_cbd, "keygen.json": check_keygen, "enc.json": check_enc,
            "statement_*": check_statement, "proof_*": check_proofs, "negative.json": check_negative,
            "selftest.json": check_selftest, "fee0.json": check_fee0, "worstcase_noise.json": check_worstcase}


def check_files(paths, log):
    bad = []
    for p in paths:
        name = os.path.basename(p)
        fn = CHECKERS.get(name) or CHECKERS.get(name.split("_")[0] + "_*")
        if fn is None:
            bad.append(f"{name}: no checker in pqz_kat.py")
            continue
        try:
            j = json.load(open(p))
            b = [f"{name}: {x}" for x in fn(j, os.path.dirname(os.path.abspath(p)))]
        except Exception as x:  # a malformed or tampered file must fail, not crash the run
            j, b = {"file": name}, [f"{name}: checker raised {type(x).__name__}: {x}"]
        if j.get("file") != name:
            b.append(f"{name}: file field {j.get('file')}")
        bad += b
        log(("ok   " if not b else "FAIL ") + name)
    return bad


def main(argv):
    log = print
    if len(argv) >= 2 and argv[0] == "--c-keys":
        bad = check_c_keys(argv[1], log)
    elif argv and argv[0] == "--check":
        bad = selftest(log)
        files = argv[1:] or sorted(glob.glob(os.path.join(VEC_DIR, "*.json")))
        log(f"     parameter set {SET} (q = {Q}, n = {N}, K_MAX = {K_MAX:,}{', PQZH' if HAS_PQZH else ', no PQZH'})")
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
