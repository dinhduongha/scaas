"""Python model of the zether-msm merged-MSM verifier (snapshot 6fed9881) on BLS12-381 G1, with py_ecc.

Mirrors smartcontracts/evm/src/zether/ZetherVerifier.sol line by line (slots, `_term`, `_rho`, `_bpTranscript`,
`_bp1`, `_bp2`) and the EIP-2537 G1MSM precompile semantics (every input point: canonical encoding, on curve, in the
prime-order subgroup, whatever its scalar; a failure is a revert, modelled by `BadPoint`). Also a port of the test
prover (test/zether/helpers/ZetherProver.sol) so cheating witnesses can be proved, and statement builders.

Everything is exact arithmetic on the real curve; nothing here knows a discrete log of a NUMS generator.
"""
import json
import os
from Crypto.Hash import keccak
from py_ecc.optimized_bls12_381 import (
    G1, Z1, add, multiply, neg, normalize, is_inf, field_modulus as P, curve_order as R, FQ,
)

HERE = os.path.dirname(os.path.abspath(__file__))
PB = 128  # point bytes
NGEN = 130
SLOT_G, SLOT_HB, SLOT_U, SLOT_GI, SLOT_HI, SLOT_EXT = 0, 1, 2, 3, 67, 131
HEADER, FEE_AT, AMOUNT_AT = 512, 288, 352
MAX_RECIPIENTS = 16
N, K = 64, 6
BP_LEN = 16 * PB + 160


def kec(b: bytes) -> bytes:
    return keccak.new(digest_bits=256, data=b).digest()


PSID_LABEL = b"scaas/zether/sigma-bullets/bls12-381/n64-n64/v3"
PSID = kec(PSID_LABEL)
PSID_MULTI = kec(PSID_LABEL + b"/multi")
OP_TRANSFER = kec(b"SCAAS-ZETHER-OP-TRANSFER-V1")
OP_BURN = kec(b"SCAAS-ZETHER-OP-BURN-V1")
OP_MULTI_HASH = kec(b"SCAAS-ZETHER-OP-TRANSFER-MULTI-V1/HASH")
OP_MULTI_BUNDLE = kec(b"SCAAS-ZETHER-OP-TRANSFER-MULTI-V1/BUNDLE")


class BadPoint(Exception):
    """The G1MSM precompile errored: the Solidity reverts `BadPoint`."""


# ------------------------------------------------------------------ points

def enc(pt) -> bytes:
    if is_inf(pt):
        return bytes(PB)
    x, y = normalize(pt)
    return int(x).to_bytes(64, "big") + int(y).to_bytes(64, "big")


def _dec_fq(b64: bytes) -> int:
    if b64[:16] != bytes(16):
        raise BadPoint("padding")
    v = int.from_bytes(b64, "big")
    if v >= P:
        raise BadPoint("fq >= p")
    return v


_DEC_CACHE = {}
SUBGROUP_CHECK = True  # set False only to model a hypothetical MSM without the EIP-2537 subgroup check


def set_subgroup_check(on: bool):
    global SUBGROUP_CHECK
    SUBGROUP_CHECK = on
    _DEC_CACHE.clear()


def dec(b: bytes, subgroup: bool = True):
    """EIP-2537 G1 decoding. `subgroup=True` is G1MSM; `False` is G1ADD (on-curve only)."""
    subgroup = subgroup and SUBGROUP_CHECK
    key = (bytes(b), subgroup)
    if key in _DEC_CACHE:
        return _DEC_CACHE[key]
    if len(b) != PB:
        raise BadPoint("length")
    x, y = _dec_fq(b[:64]), _dec_fq(b[64:])
    if x == 0 and y == 0:
        return Z1
    if (y * y - (x * x * x + 4)) % P != 0:
        raise BadPoint("off curve")
    pt = (FQ(x), FQ(y), FQ(1))
    if subgroup and not is_inf(multiply(pt, R)):
        raise BadPoint("not in the r-subgroup")
    _DEC_CACHE[key] = pt
    return pt


def mul(pt, s: int):
    s %= R
    return Z1 if s == 0 else multiply(pt, s)


def msm_pts(points, scalars):
    acc = Z1
    for pt, s in zip(points, scalars):
        s %= R
        if s:
            acc = add(acc, multiply(pt, s))
    return acc


def msm_precompile(pts: bytes, sc) -> bytes:
    """G1Bls12381.msm: k pairs; every point decoded with the subgroup check (scalar 0 too); returns 128 bytes."""
    k = len(sc)
    if k == 0 or len(pts) != k * PB:
        raise BadPoint("BadLength")
    points = [dec(pts[i * PB:(i + 1) * PB]) for i in range(k)]
    return enc(msm_pts(points, sc))


def g1add_precompile(a: bytes, b: bytes) -> bytes:
    return enc(add(dec(a, False), dec(b, False)))


def is_zero(b: bytes) -> bool:
    return b == bytes(len(b))


# order-3 point (0, 2): on y^2 = x^3 + 4, outside the r-subgroup (ZetherMsmCorpus._lowOrder)
LOW_ORDER = (0).to_bytes(64, "big") + (2).to_bytes(64, "big")


# ------------------------------------------------------------------ transcript

T_INIT = kec(b"SCAAS-ZETHER-TRANSCRIPT-V1")


def absorb(st: bytes, label: str, data: bytes) -> bytes:
    lb = label.encode()
    return kec(st + b"\x00" + bytes([len(lb)]) + lb + len(data).to_bytes(4, "big") + data)


def hash_to_scalar(seed: bytes) -> int:
    hi = int.from_bytes(kec(seed + b"\x02"), "big")
    lo = int.from_bytes(kec(seed + b"\x03"), "big")
    return ((hi << 256) + lo) % R


def challenge(st: bytes, label: str):
    lb = label.encode()
    st2 = kec(st + b"\x01" + bytes([len(lb)]) + lb)
    return st2, hash_to_scalar(st2)


def rho_of(st_c: bytes, proof: bytes) -> int:
    """ZetherCurve._rho: fork of the state after `sigma.c`, absorbing the whole proof."""
    _, rho = challenge(absorb(st_c, "fold.proof", proof), "fold.rho")
    return rho


def be32(v: int) -> bytes:
    return (v % (1 << 256)).to_bytes(32, "big")


def word(b: bytes, off: int) -> int:
    return int.from_bytes(b[off:off + 32], "big")


def set_word(b: bytearray, off: int, v: int):
    b[off:off + 32] = be32(v)


def inv(a: int) -> int:
    return pow(a, R - 2, R)  # Fermat, as the contract's MODEXP; inv(0) = 0


# ------------------------------------------------------------------ generators

def load_gens(path=os.path.join(HERE, "../../test/vectors/zether/generators_bls12381.json")) -> bytes:
    j = json.load(open(path))
    blob = b"".join(bytes.fromhex(p[2:]) for p in [j["h"], j["U"], *j["G"], *j["H"]])
    assert len(blob) == NGEN * PB, len(blob)
    assert keccak.new(digest_bits=256, data=blob).hexdigest() == j["blobKeccak"][2:], "blobKeccak"
    return blob


G_BYTES = enc(G1)
assert G_BYTES.hex().startswith("00000000000000000000000000000000" "17f1d3a73197d7942695638c4fa9ac0f")


class Gens:
    def __init__(self, blob: bytes):
        self.blob = blob
        self.g = G1
        self.h = dec(blob[0:PB])
        self.u = dec(blob[PB:2 * PB])
        self.gs = [dec(blob[(2 + i) * PB:(3 + i) * PB]) for i in range(64)]
        self.hs = [dec(blob[(66 + i) * PB:(67 + i) * PB]) for i in range(64)]
        self.hb_bytes = blob[0:PB]


# ------------------------------------------------------------------ the verifier (new, merged)

class Verdict:
    def __init__(self, ok, why="", revert=False, **kw):
        self.ok, self.why, self.revert = ok, why, revert
        self.__dict__.update(kw)

    def __repr__(self):
        return f"Verdict(ok={self.ok}, revert={self.revert}, why={self.why!r})"


class Fold:
    """The caller side: `Ctx` of ZetherVerifierBase (f, pts, weight, rho) plus the recorded equations."""

    def __init__(self, statement: bytes, proof: bytes, sigma_len: int, pts: bytes):
        self.s, self.pr = statement, proof
        st = absorb(T_INIT, "statement", statement)
        st = absorb(st, "sigma.commit", proof[:sigma_len])
        st, self.c = challenge(st, "sigma.c")
        self.st = st
        self.rho = rho_of(st, proof)
        self.w = 1
        self.sAt = SLOT_EXT + sigma_len // PB
        self.pts = pts
        self.f = [0] * (SLOT_EXT + len(pts) // PB)
        self.eqs = []  # (slots, scalars) in fold order, for diagnostics

    def term(self, slot, w, s):
        self.f[slot] = (self.f[slot] + (w * s) % R) % R

    def eq(self, slots, scalars):
        for sl, sc in zip(slots, scalars):
            self.term(sl, self.w, sc)
        self.eqs.append((list(slots), [x % R for x in scalars]))
        self.w = (self.w * self.rho) % R

    def e5(self, zb, zx, slots):
        self.eq([SLOT_G] + list(slots),
               [(zb + self.c * word(self.s, FEE_AT)) % R, zx, (-zx) % R, (R - self.c) % R, self.c, R - 1])

    def sp(self, i):
        return self.s[HEADER + i * PB:HEADER + (i + 1) * PB]

    def pf(self, i):
        return self.pr[i * PB:(i + 1) * PB]

    def ps(self, nPts, i):
        v = word(self.pr, nPts * PB + 32 * i)
        return v, v < R

    def lp(self, j, k):
        o = HEADER + 6 * PB + 32 + (4 * j + k) * PB
        return self.s[o:o + PB]


def _negS(a):
    return 0 if a == 0 else R - a


def _sigma_transfer(x: Fold):
    z = []
    for i in range(6):
        v, ok = x.ps(10, i)
        if not ok:
            return False, f"z[{i}] >= r"
        z.append(v)
    if is_zero(x.sp(6)) or is_zero(x.sp(0)) or is_zero(x.sp(1)) or x.sp(0) == x.sp(1):
        return False, "D_out/Y_f/Y_t is O or Y_f == Y_t"
    nc = R - x.c
    s, a = x.sAt, SLOT_EXT
    x.eq([SLOT_G, s, a + 2], [z[0], nc, R - 1])                        # E1
    x.eq([SLOT_G, s + 6, a + 3], [z[2], nc, R - 1])                    # E2
    x.eq([SLOT_G, s + 1, s + 5, a + 4], [z[1], z[2], nc, R - 1])       # E3
    x.eq([SLOT_G, s, s + 7, a + 5], [z[1], z[2], nc, R - 1])           # E4
    x.e5(z[3], z[0], [s + 4, s + 6, s + 3, s + 7, a + 6])              # E5
    if is_zero(x.sp(2)):
        if not is_zero(x.sp(8)) or not is_zero(x.pf(7)):
            return False, "auditor off but C_aud or A_aud != O"
    else:
        x.eq([SLOT_G, s + 2, s + 8, a + 7], [z[1], z[2], nc, R - 1])   # E6
    x.eq([SLOT_G, SLOT_HB, a, a + 8], [z[1], z[4], nc, R - 1])         # E7
    x.eq([SLOT_G, SLOT_HB, a + 1, a + 9], [z[3], z[5], nc, R - 1])     # E8
    return True, ""


def _sigma_burn(x: Fold):
    z = []
    for i in range(3):
        v, ok = x.ps(4, i)
        if not ok:
            return False, f"z[{i}] >= r"
        z.append(v)
    if is_zero(x.sp(0)):
        return False, "Y_f is O"
    nc = R - x.c
    s, a = x.sAt, SLOT_EXT
    x.eq([SLOT_G, s, a + 1], [z[0], nc, R - 1])                                           # E1
    debit = (word(x.s, AMOUNT_AT) + word(x.s, FEE_AT)) % R
    x.eq([SLOT_G, s + 2, s + 1, a + 2], [(z[1] + x.c * debit) % R, z[0], nc, R - 1])      # E5
    x.eq([SLOT_G, SLOT_HB, a, a + 3], [z[1], z[2], nc, R - 1])                            # E8
    return True, ""


def _lpf(j, k):
    return SLOT_EXT + 6 + 5 * j + k


def _sigma_multi(x: Fold, m: int):
    z = []
    for i in range(4 + 3 * m):
        v, ok = x.ps(6 + 5 * m, i)
        if not ok:
            return False, f"z[{i}] >= r"
        z.append(v)
    if is_zero(x.sp(0)) or is_zero(x.sp(4)):
        return False, "Y_f or D_out is O"
    nc = R - x.c
    s, a = x.sAt, SLOT_EXT
    x.eq([SLOT_G, s, a + 1], [z[0], nc, R - 1])          # E1
    x.eq([SLOT_G, s + 4, a + 2], [z[1], nc, R - 1])      # E2
    aud = not is_zero(x.sp(1))
    yf = x.sp(0)
    if aud:  # _distinctAud
        seen_c, seen_d = set(), set()
        for j in range(m):
            cj, dj = x.lp(j, 2), x.lp(j, 3)
            if cj in seen_c or dj in seen_d:
                return False, "legs share C_aud or D_aud"
            seen_c.add(cj)
            seen_d.add(dj)
    lps = lambda j, k: x.sAt + 6 + 4 * j + k
    for j in range(m):
        zv, zt = z[4 + 3 * j], z[6 + 3 * j]
        yt = x.lp(j, 0)
        if is_zero(yt) or yt == yf:
            return False, f"leg {j}: Y_t is O or == Y_f"
        x.eq([SLOT_G, lps(j, 0), lps(j, 1), _lpf(j, 1)], [zv, z[1], nc, R - 1])     # E3_j
        if not aud:
            if not (zt == 0 and is_zero(x.lp(j, 2)) and is_zero(x.lp(j, 3))
                    and is_zero(x.pf(6 + 5 * j + 2)) and is_zero(x.pf(6 + 5 * j + 3))):
                return False, f"leg {j}: auditor off but z_t/C_aud/D_aud/A_aud/A_Daud not zero"
        else:
            if is_zero(x.lp(j, 3)):
                return False, f"leg {j}: D_aud is O"
            x.eq([SLOT_G, x.sAt + 1, lps(j, 2), _lpf(j, 2)], [zv, zt, nc, R - 1])  # E6_j
            x.eq([SLOT_G, lps(j, 3), _lpf(j, 3)], [zt, nc, R - 1])                 # E6'_j
        x.eq([SLOT_G, SLOT_HB, _lpf(j, 0), _lpf(j, 4)], [zv, z[5 + 3 * j], nc, R - 1])  # E7_j
    zvs = sum(z[4 + 3 * j] for j in range(m)) % R
    x.eq([SLOT_G, s, s + 5, a + 3], [zvs, z[1], nc, R - 1])     # E4
    x.e5(z[2], z[0], [s + 3, s + 4, s + 2, s + 5, a + 4])       # E5
    x.eq([SLOT_G, SLOT_HB, a, a + 5], [z[2], z[3], nc, R - 1])  # E8
    return True, ""


# --- the inner-product verifier side (ZetherInnerProductBase._fold etc.)

class BP:
    pass


def _bp_transcript(st: bytes, b: BP):
    pr = b.pr
    b.sc = []
    for i in range(5):
        v = word(pr, b.sOff + 32 * i)
        if v >= R:
            return False, st, "bp scalar >= r"
        b.sc.append(v)
    st = absorb(st, "bp.AS", N.to_bytes(4, "big") + pr[0:2 * PB])
    st, b.y = challenge(st, "bp.y")
    st, b.z = challenge(st, "bp.z")
    st = absorb(st, "bp.T", pr[2 * PB:4 * PB])
    st, b.x = challenge(st, "bp.x")
    st = absorb(st, "bp.t", pr[b.sOff:b.sOff + 96])
    st, b.w = challenge(st, "bp.w")
    if 0 in (b.y, b.z, b.x, b.w):
        return False, st, "zero bp challenge"
    b.u = []
    for j in range(K):
        st = absorb(st, "ipa.LR", pr[(4 + 2 * j) * PB:(6 + 2 * j) * PB])
        st, uj = challenge(st, "ipa.u")
        if uj == 0:
            return False, st, "zero ipa challenge"
        b.u.append(uj)
    return True, st, ""


def _s_vector(b: BP):
    s = [0] * N
    b.uInv = [inv(u) for u in b.u]
    s[0] = 1
    for j in range(K):
        s[0] = s[0] * b.uInv[j] % R
    for i in range(1, N):
        lg = i.bit_length() - 1
        uj = b.u[K - 1 - lg]
        s[i] = s[i - (1 << lg)] * uj * uj % R
    return s


def _bp1(b: BP, fold: dict, v_slot: int):
    w = b.wt
    z2 = b.z * b.z % R
    sumY = sum(pow(b.y, i, R) for i in range(N)) % R
    delta = ((b.z - z2) * sumY - z2 * b.z * ((1 << N) - 1)) % R
    terms = [(SLOT_G, (b.sc[2] - delta) % R), (SLOT_HB, b.sc[0]), (v_slot, _negS(z2)),
             (b.at + 2, _negS(b.x)), (b.at + 3, _negS(b.x * b.x % R))]
    for sl, sc in terms:
        b.f[sl] = (b.f[sl] + w * sc) % R
    fold["eqs"].append(([t[0] for t in terms], [t[1] for t in terms]))
    b.wt = w * b.rho % R


def _bp2(b: BP, fold: dict):
    w = b.wt
    a = b.at
    s = _s_vector(b)
    z2 = b.z * b.z % R
    yInv = inv(b.y)
    terms = [(a, 1), (a + 1, b.x)]
    yInvI, twoI = 1, 1
    for i in range(N):
        t = (b.z + b.sc[3] * s[i]) % R
        terms.append((SLOT_GI + i, _negS(t)))
        t = (z2 * twoI - b.sc[4] * s[N - 1 - i]) % R
        t = (b.z + yInvI * t) % R
        terms.append((SLOT_HI + i, t))
        yInvI = yInvI * yInv % R
        twoI = twoI * 2 % R
    terms.append((SLOT_HB, _negS(b.sc[1])))
    terms.append((SLOT_U, b.w * ((b.sc[2] - b.sc[3] * b.sc[4]) % R) % R))
    for j in range(K):
        terms.append((a + 4 + 2 * j, b.u[j] * b.u[j] % R))
        terms.append((a + 5 + 2 * j, b.uInv[j] * b.uInv[j] % R))
    for sl, sc in terms:
        b.f[sl] = (b.f[sl] + w * sc) % R
    fold["eqs"].append(([t[0] for t in terms], [t[1] for t in terms]))
    b.wt = w * b.rho % R


def verify_fold(st: bytes, rho: int, weight: int, points: bytes, scalars, commitments, range_proofs: bytes,
                gens_blob: bytes, eqs=None) -> Verdict:
    """ZetherInnerProductBase._fold. `eqs` (optional) receives the range-proof equations appended."""
    b = BP()
    b.rho, b.wt, b.at = rho, weight, len(scalars)
    b.sOff = 16 * PB
    m = len(commitments)
    if b.rho == 0 or len(range_proofs) != m * BP_LEN or len(points) + SLOT_EXT * PB != b.at * PB:
        return Verdict(False, "fold shape (rho = 0 / range proof length / points vs scalars)")
    b.f = list(scalars) + [0] * (16 * m)
    pts = bytearray(len(b.f) * PB)
    pts[0:PB] = G_BYTES
    pts[SLOT_HB * PB:(SLOT_HB + NGEN) * PB] = gens_blob
    pts[SLOT_EXT * PB:SLOT_EXT * PB + len(points)] = points
    fold = {"eqs": eqs if eqs is not None else []}
    for k in range(m):
        b.pr = range_proofs[k * BP_LEN:(k + 1) * BP_LEN]
        ok, st, why = _bp_transcript(st, b)
        if not ok:
            return Verdict(False, f"BP {k}: {why}")
        pts[b.at * PB:(b.at + 16) * PB] = b.pr[:16 * PB]
        _bp1(b, fold, commitments[k])
        _bp2(b, fold)
        b.at += 16
    try:
        out = msm_precompile(bytes(pts), b.f)
    except BadPoint as e:
        return Verdict(False, f"revert BadPoint: {e}", revert=True, pts=bytes(pts), f=b.f, eqs=fold["eqs"])
    return Verdict(is_zero(out), "" if is_zero(out) else "fold sum != O", pts=bytes(pts), f=b.f, sum=out,
                   eqs=fold["eqs"], st=st)


def verify_range(st: bytes, V: bytes, proof: bytes, gens_blob: bytes) -> Verdict:
    """ZetherInnerProductBase.verifyRange."""
    if len(V) != PB:
        return Verdict(False, "V length")
    return verify_fold(st, rho_of(st, V + proof), 1, V, [0] * (SLOT_EXT + 1), [SLOT_EXT], proof, gens_blob)


def _finish(x: Fold, v_slots, off: int, gens_blob: bytes) -> Verdict:
    vd = verify_fold(x.st, x.rho, x.w, x.pts, x.f, v_slots, x.pr[off:], gens_blob, eqs=x.eqs)
    vd.ctx = x
    return vd


def verify_transfer(statement: bytes, proof: bytes, gens_blob: bytes) -> Verdict:
    if len(statement) != HEADER + 9 * PB or len(proof) != 42 * PB + 512:
        return Verdict(False, "lengths")
    if statement[0:32] != OP_TRANSFER or statement[32:64] != PSID:
        return Verdict(False, "opTag / proofSystemId")
    x = Fold(statement, proof, 10 * PB, proof[0:10 * PB] + statement[HEADER:])
    if x.c == 0:
        return Verdict(False, "c = 0")
    ok, why = _sigma_transfer(x)
    if not ok:
        return Verdict(False, why, ctx=x)
    return _finish(x, [SLOT_EXT, SLOT_EXT + 1], 10 * PB + 192, gens_blob)


def _multi_legs(statement: bytes, proof: bytes) -> int:
    mAt = HEADER + 6 * PB
    if len(statement) < mAt + 32:
        return 0
    m = word(statement, mAt)
    if m == 0 or m > MAX_RECIPIENTS or len(statement) != mAt + 32 + 4 * PB * m:
        return 0
    if statement[0:32] not in (OP_MULTI_HASH, OP_MULTI_BUNDLE):
        return 0
    if statement[32:64] != PSID_MULTI:
        return 0
    if len(proof) != (6 + 5 * m) * PB + (4 + 3 * m) * 32 + (m + 1) * BP_LEN:
        return 0
    return m


def verify_transfer_multi(statement: bytes, proof: bytes, gens_blob: bytes) -> Verdict:
    m = _multi_legs(statement, proof)
    if m == 0:
        return Verdict(False, "multi shape")
    mAt = HEADER + 6 * PB
    sigma = (6 + 5 * m) * PB
    pts = proof[0:sigma] + statement[HEADER:mAt] + statement[mAt + 32:]
    x = Fold(statement, proof, sigma, pts)
    if x.c == 0:
        return Verdict(False, "c = 0")
    ok, why = _sigma_multi(x, m)
    if not ok:
        return Verdict(False, why, ctx=x)
    v = [_lpf(j, 0) for j in range(m)] + [SLOT_EXT]
    return _finish(x, v, sigma + (4 + 3 * m) * 32, gens_blob)


def verify_burn(statement: bytes, proof: bytes, gens_blob: bytes) -> Verdict:
    if len(statement) != HEADER + 3 * PB or len(proof) != 20 * PB + 256:
        return Verdict(False, "lengths")
    if statement[0:32] != OP_BURN or statement[32:64] != PSID:
        return Verdict(False, "opTag / proofSystemId")
    x = Fold(statement, proof, 4 * PB, proof[0:4 * PB] + statement[HEADER:])
    if x.c == 0:
        return Verdict(False, "c = 0")
    ok, why = _sigma_burn(x)
    if not ok:
        return Verdict(False, why, ctx=x)
    return _finish(x, [SLOT_EXT], 4 * PB + 96, gens_blob)


def verify(op: str, statement: bytes, proof: bytes, gens_blob: bytes) -> Verdict:
    return {"transfer": verify_transfer, "multi": verify_transfer_multi, "burn": verify_burn}[op](
        statement, proof, gens_blob)


def residuals(vd: Verdict):
    """Each recorded equation's own value Q_i on the curve (the per-equation verdicts), from the fold's point table."""
    pts = vd.pts
    out = []
    for slots, scalars in vd.eqs:
        q = msm_pts([dec(pts[s * PB:(s + 1) * PB]) for s in slots], scalars)
        out.append(q)
    return out


def fold_sum_from_residuals(res, rho):
    acc = Z1
    w = 1
    for q in res:
        acc = add(acc, mul(q, w))
        w = w * rho % R
    return acc


# ------------------------------------------------------------------ the prover (port of test/zether/helpers/ZetherProver.sol)

class Prover:
    def __init__(self, gens: Gens, seed: bytes):
        self.g = gens
        self.seed = seed
        self.rid = 0
        self.hooks = {}  # name -> callable(value) -> value, for cheating variants

    def rand(self, tag: str, i: int) -> int:
        # T.hashToScalar(keccak256(abi.encode(seed, tag, i)))
        tb = tag.encode()
        enc_ = self.seed + be32(0x60) + be32(i) + be32(len(tb)) + tb + bytes((32 - len(tb) % 32) % 32)
        return hash_to_scalar(kec(enc_))

    # --- ElGamal helpers
    def cipher(self, yf, yt, ya, amount, s):
        g = self.g.g
        c_out = add(mul(g, amount), mul(yt, s))
        d_out = mul(g, s)
        c_deb = add(mul(g, amount), mul(yf, s))
        c_aud = Z1 if is_inf(ya) else add(mul(g, amount), mul(ya, s))
        return c_out, d_out, c_deb, c_aud

    def aud_copy(self, ya, amount, t):
        if is_inf(ya):
            return Z1, Z1
        return add(mul(self.g.g, amount), mul(ya, t)), mul(self.g.g, t)

    # --- Σ transfer
    def prove_transfer(self, statement: bytes, x, v, s, bPrime, gammaV, gammaB, tamper=None):
        g, hb = self.g.g, self.g.h
        sp = lambda i: dec(statement[HEADER + i * PB:HEADER + (i + 1) * PB])
        k = [self.rand("sigma.k", i) for i in range(6)]  # k_x k_v k_s k_b k_gv k_gb
        yf, yt, ya, d_acc, d_out = sp(0), sp(1), sp(2), sp(4), sp(6)
        commits = [
            add(mul(g, v), mul(hb, gammaV)),                     # V_v
            add(mul(g, bPrime), mul(hb, gammaB)),                # V_b
            mul(g, k[0]),                                        # A_y
            mul(g, k[2]),                                        # A_D
            add(mul(g, k[1]), mul(yt, k[2])),                    # A_out
            add(mul(g, k[1]), mul(yf, k[2])),                    # A_deb
            add(mul(g, k[3]), mul(add(d_acc, neg(d_out)), k[0])),  # A_bal
            Z1 if is_inf(ya) else add(mul(g, k[1]), mul(ya, k[2])),  # A_aud
            add(mul(g, k[1]), mul(hb, k[4])),                    # A_Vv
            add(mul(g, k[3]), mul(hb, k[5])),                    # A_Vb
        ]
        if tamper:
            commits = tamper(commits)
        cb = b"".join(enc(c) for c in commits)
        st = absorb(T_INIT, "statement", statement)
        st = absorb(st, "sigma.commit", cb)
        st, c = challenge(st, "sigma.c")
        wit = [x, v, s, bPrime, gammaV, gammaB]
        zs = b"".join(be32((k[i] + c * wit[i]) % R) for i in range(6))
        self.rid = 32
        bp1, st = self.prove_range(st, v, gammaV)
        self.rid = 64
        bp2, st = self.prove_range(st, bPrime, gammaB)
        return cb + zs + bp1 + bp2

    def prove_burn(self, statement: bytes, x, bPrime, gammaB):
        g, hb = self.g.g, self.g.h
        sp = lambda i: dec(statement[HEADER + i * PB:HEADER + (i + 1) * PB])
        k = [self.rand("burn.k", i) for i in range(3)]  # k_x k_b k_gb
        commits = [
            add(mul(g, bPrime), mul(hb, gammaB)),  # V_b
            mul(g, k[0]),                          # A_y
            add(mul(g, k[1]), mul(sp(2), k[0])),   # A_bal
            add(mul(g, k[1]), mul(hb, k[2])),      # A_Vb
        ]
        cb = b"".join(enc(c) for c in commits)
        st = absorb(T_INIT, "statement", statement)
        st = absorb(st, "sigma.commit", cb)
        st, c = challenge(st, "sigma.c")
        wit = [x, bPrime, gammaB]
        zs = b"".join(be32((k[i] + c * wit[i]) % R) for i in range(3))
        self.rid = 64
        bp, st = self.prove_range(st, bPrime, gammaB)
        return cb + zs + bp

    def prove_multi(self, statement: bytes, x, s, vs, ts, bPrime, gammaVs, gammaB):
        g, hb = self.g.g, self.g.h
        m = len(vs)
        sp = lambda i: dec(statement[HEADER + i * PB:HEADER + (i + 1) * PB])
        lp = lambda j, kk: dec(statement[HEADER + 6 * PB + 32 + (4 * j + kk) * PB:][:PB])
        k = [self.rand("multi.k", i) for i in range(4 + 3 * m)]
        yf, ya, d_acc, d_out = sp(0), sp(1), sp(3), sp(4)
        aud = not is_inf(ya)
        kvSum = sum(k[4 + 3 * j] for j in range(m)) % R
        commits = [
            add(mul(g, bPrime), mul(hb, gammaB)),                   # V_b
            mul(g, k[0]),                                           # A_y
            mul(g, k[1]),                                           # A_D
            add(mul(g, kvSum), mul(yf, k[1])),                      # A_deb
            add(mul(g, k[2]), mul(add(d_acc, neg(d_out)), k[0])),   # A_bal
            add(mul(g, k[2]), mul(hb, k[3])),                       # A_Vb
        ]
        for j in range(m):
            kv, kgv, kt = k[4 + 3 * j], k[5 + 3 * j], k[6 + 3 * j]
            commits += [
                add(mul(g, vs[j]), mul(hb, gammaVs[j])),            # V_vj
                add(mul(g, kv), mul(lp(j, 0), k[1])),               # A_out_j
                add(mul(g, kv), mul(ya, kt)) if aud else Z1,        # A_aud_j
                mul(g, kt) if aud else Z1,                          # A_Daud_j
                add(mul(g, kv), mul(hb, kgv)),                      # A_Vvj
            ]
        cb = b"".join(enc(c) for c in commits)
        st = absorb(T_INIT, "statement", statement)
        st = absorb(st, "sigma.commit", cb)
        st, c = challenge(st, "sigma.c")
        zs = [(k[0] + c * x) % R, (k[1] + c * s) % R, (k[2] + c * bPrime) % R, (k[3] + c * gammaB) % R]
        for j in range(m):
            zs += [(k[4 + 3 * j] + c * vs[j]) % R, (k[5 + 3 * j] + c * gammaVs[j]) % R,
                   (k[6 + 3 * j] + c * ts[j]) % R if aud else 0]
        out = cb + b"".join(be32(z) for z in zs)
        for j in range(m):
            self.rid = 100 + j
            bp, st = self.prove_range(st, vs[j], gammaVs[j])
            out += bp
        self.rid = 64
        bp, st = self.prove_range(st, bPrime, gammaB)
        return out + bp

    # --- Bulletproof (§9), `value` taken mod 2^64 bits as the Solidity prover does (a cheating prover may pass any value)
    def prove_range(self, st: bytes, value: int, gamma: int):
        g, hb, u, gs, hs = self.g.g, self.g.h, self.g.u, self.g.gs, self.g.hs
        rid = self.rid
        aL = [(value >> i) & 1 for i in range(N)]
        aR = [0 if a == 1 else R - 1 for a in aL]
        sL = [self.rand(f"sL{rid}", i) for i in range(N)]
        sR = [self.rand(f"sR{rid}", i) for i in range(N)]
        alpha, rho_, tau1, tau2 = (self.rand(t, rid) for t in ("alpha", "rho", "tau1", "tau2"))
        A = msm_pts([hb] + gs + hs, [alpha] + aL + aR)
        S = msm_pts([hb] + gs + hs, [rho_] + sL + sR)
        AS = enc(A) + enc(S)
        st = absorb(st, "bp.AS", N.to_bytes(4, "big") + AS)
        st, y = challenge(st, "bp.y")
        st, z = challenge(st, "bp.z")
        z2 = z * z % R
        l0 = [(a - z) % R for a in aL]
        yn = [pow(y, i, R) for i in range(N)]
        r0 = [(yn[i] * (aR[i] + z) + z2 * pow(2, i, R)) % R for i in range(N)]
        r1 = [yn[i] * sR[i] % R for i in range(N)]
        t1 = (sum(l0[i] * r1[i] for i in range(N)) + sum(sL[i] * r0[i] for i in range(N))) % R
        t2 = sum(sL[i] * r1[i] for i in range(N)) % R
        T1 = add(mul(g, t1), mul(hb, tau1))
        T2 = add(mul(g, t2), mul(hb, tau2))
        T12 = enc(T1) + enc(T2)
        if self.hooks.get("T1") == rid:  # tamper: [1]G on T1 (ZetherProver.tamperT1)
            T12 = enc(add(T1, g)) + enc(T2)
        st = absorb(st, "bp.T", T12)
        st, xch = challenge(st, "bp.x")
        l = [(l0[i] + xch * sL[i]) % R for i in range(N)]
        r = [(r0[i] + xch * r1[i]) % R for i in range(N)]
        that = sum(l[i] * r[i] for i in range(N)) % R
        taux = (tau2 * xch * xch + tau1 * xch + z2 * gamma) % R
        mu = (alpha + rho_ * xch) % R
        tvals = be32(taux) + be32(mu) + be32(that)
        st = absorb(st, "bp.t", tvals)
        st, w = challenge(st, "bp.w")
        Q = mul(u, w)
        yinv = inv(y)
        Gv = list(gs)
        Hv = [mul(hs[i], pow(yinv, i, R)) for i in range(N)]
        a, bvec = l, r
        LR = b""
        while len(a) > 1:
            h = len(a) // 2
            a_lo, a_hi, b_lo, b_hi = a[:h], a[h:], bvec[:h], bvec[h:]
            g_lo, g_hi, h_lo, h_hi = Gv[:h], Gv[h:], Hv[:h], Hv[h:]
            L = add(add(msm_pts(g_hi, a_lo), msm_pts(h_lo, b_hi)), mul(Q, sum(x_ * y_ for x_, y_ in zip(a_lo, b_hi))))
            Rp = add(add(msm_pts(g_lo, a_hi), msm_pts(h_hi, b_lo)), mul(Q, sum(x_ * y_ for x_, y_ in zip(a_hi, b_lo))))
            lr = enc(L) + enc(Rp)
            LR += lr
            st = absorb(st, "ipa.LR", lr)
            st, uch = challenge(st, "ipa.u")
            ui = inv(uch)
            a = [(a_lo[i] * uch + a_hi[i] * ui) % R for i in range(h)]
            bvec = [(b_lo[i] * ui + b_hi[i] * uch) % R for i in range(h)]
            Gv = [add(mul(g_lo[i], ui), mul(g_hi[i], uch)) for i in range(h)]
            Hv = [add(mul(h_lo[i], uch), mul(h_hi[i], ui)) for i in range(h)]
        return AS + T12 + LR + tvals + be32(a[0]) + be32(bvec[0]), st


# ------------------------------------------------------------------ statements (ZetherMsmCorpus layouts)

def header(op: bytes, psid: bytes, fee: int, amount: int, to: int = 0, chainid: int = 31337) -> bytes:
    words = [op, psid, be32(chainid), kec(b"msm chain"), be32(0x70CE), kec(b"ZTX_V1_DIRECT"),
             be32(0), be32(7), be32(3), be32(fee), be32(0xBE),
             be32(amount), be32(to), be32(0) if op == OP_BURN else be32(0x5A17), be32(0), be32(1000)]
    h = b"".join(words)
    assert len(h) == HEADER
    return h


class World:
    """Keys and balances of a toy ledger: sender x_f, recipient x_t, auditor x_a; account (C_acc, D_acc) under Y_f."""

    def __init__(self, gens: Gens, xf=0xA11CE, xt=0xB0B, xa=0xA0D17, acc_r=0x5EED):
        self.g = gens
        self.xf, self.xt, self.xa, self.acc_r = xf, xt, xa, acc_r
        self.yf, self.yt, self.ya = mul(gens.g, xf), mul(gens.g, xt), mul(gens.g, xa)

    def acc(self, bal: int):
        return add(mul(self.g.g, bal), mul(self.yf, self.acc_r)), mul(self.g.g, self.acc_r)

    def transfer_statement(self, prover: Prover, bal, amt, fee, aud, s=5, yt=None):
        ya = self.ya if aud else Z1
        yt = yt if yt is not None else self.yt
        c_acc, d_acc = self.acc(bal)
        c_out, d_out, c_deb, c_aud = prover.cipher(self.yf, yt, ya, amt, s)
        pts = [self.yf, yt, ya, c_acc, d_acc, c_out, d_out, c_deb, c_aud]
        return header(OP_TRANSFER, PSID, fee, 0) + b"".join(enc(p) for p in pts)

    def burn_statement(self, bal, amt, fee):
        c_acc, d_acc = self.acc(bal)
        return header(OP_BURN, PSID, fee, amt, to=0xCAFE) + b"".join(enc(p) for p in (self.yf, c_acc, d_acc))

    def multi_statement(self, prover: Prover, bal, vs, fee, aud, s=5, t0=0x7A0, yts=None):
        ya = self.ya if aud else Z1
        m = len(vs)
        total = sum(vs)
        _, d_out, c_deb, _ = prover.cipher(self.yf, self.yf, ya, total, s)
        c_acc, d_acc = self.acc(bal)
        head = header(OP_MULTI_BUNDLE, PSID_MULTI, fee, 0) + b"".join(enc(p) for p in (self.yf, ya, c_acc, d_acc, d_out, c_deb))
        legs = b""
        for j in range(m):
            yt = yts[j] if yts else mul(self.g.g, 0xD00 + j)
            c_out, _, _, _ = prover.cipher(self.yf, yt, ya, vs[j], s)
            c_aud, d_aud = prover.aud_copy(ya, vs[j], t0 + j)
            legs += b"".join(enc(p) for p in (yt, c_out, c_aud, d_aud))
        return head + be32(m) + legs
