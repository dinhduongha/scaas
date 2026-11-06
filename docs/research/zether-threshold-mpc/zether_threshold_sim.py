# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Research sketch, UNAUDITED. Not production code; kept with docs/research/zether-threshold-mpc.md.
# Checks on real BLS12-381 G1 (py_ecc) that a t-of-n group holding Shamir shares of the Zether key x can
#  (1) threshold-decrypt acc with DLEQ-proven partial decryptions,
#  (2) jointly produce the x-part of the single-recipient transfer Sigma proof (FROST-style two nonces on two bases,
#      binding factors over every other input of c), and the result satisfies E1..E8 of zether.md §8.1 as written,
#  (3) jointly sign a Zether Schnorr (accounts / registry form) and an AUDITOR Chaum-Pedersen opening,
# and that the negative controls fail: too few shares, a tampered share response, a split nonce.
# The Bulletproofs are not built here: their witness (v, b', gammas) holds no x and the coordinator runs them alone.
import secrets, sys
from Crypto.Hash import keccak
from py_ecc.optimized_bls12_381 import G1, Z1, add, multiply, neg, normalize, curve_order as r, is_inf, eq

def kk(b): h = keccak.new(digest_bits=256); h.update(b); return h.digest()
def be32(n): return n.to_bytes(32, 'big')
def enc(P):  # EIP-2537 G1: pad16 || x48 || pad16 || y48; O = 128 zero bytes
    if is_inf(P): return bytes(128)
    x, y = normalize(P)
    return bytes(16) + int(x).to_bytes(48, 'big') + bytes(16) + int(y).to_bytes(48, 'big')
def h2s(seed):  # hashToScalar, zether.md §5
    return (int.from_bytes(kk(seed + b'\x02'), 'big') * 2**256 + int.from_bytes(kk(seed + b'\x03'), 'big')) % r
class T:  # the Zether transcript, zether.md §5
    def __init__(s): s.st = kk(b'SCAAS-ZETHER-TRANSCRIPT-V1')
    def absorb(s, lab, data): s.st = kk(s.st + b'\x00' + bytes([len(lab)]) + lab + len(data).to_bytes(4, 'big') + data)
    def challenge(s, lab): s.st = kk(s.st + b'\x01' + bytes([len(lab)]) + lab); return h2s(s.st)
def mul(P, k): return multiply(P, k % r)
def msum(*ps):
    acc = Z1
    for p in ps: acc = add(acc, p)
    return acc
def rnd(): return secrets.randbelow(r - 1) + 1
def lagrange(i, S):
    num, den = 1, 1
    for j in S:
        if j != i: num = num * j % r; den = den * (j - i) % r
    return num * pow(den, -1, r) % r

G = G1
Hb = mul(G, rnd())  # stand-in for the NUMS Hb (only E7/E8 use it; algebra check only)

# ---- key: Pedersen/Feldman DKG, t-of-n (each dealer's polynomial; x never formed)
def dkg(t, n):
    polys = [[rnd() for _ in range(t)] for _ in range(n)]
    share = {j: sum(sum(a * pow(j, k, r) for k, a in enumerate(p)) for p in polys) % r for j in range(1, n + 1)}
    Y = msum(*[mul(G, p[0]) for p in polys])            # group key = sum of the dealers' constant commitments
    Yi = {j: mul(G, share[j]) for j in share}            # verification shares (from the Feldman commitments)
    return share, Y, Yi

def dleq_prove(x, B, Pk, PB, ctx):  # log_G Pk == log_B PB
    k = rnd(); A1, A2 = mul(G, k), mul(B, k)
    e = h2s(kk(b'SIM-DLEQ' + ctx + enc(G) + enc(Pk) + enc(B) + enc(PB) + enc(A1) + enc(A2)))
    return A1, A2, (k + e * x) % r
def dleq_ok(B, Pk, PB, pf, ctx):
    A1, A2, z = pf
    e = h2s(kk(b'SIM-DLEQ' + ctx + enc(G) + enc(Pk) + enc(B) + enc(PB) + enc(A1) + enc(A2)))
    return eq(mul(G, z), add(A1, mul(Pk, e))) and eq(mul(B, z), add(A2, mul(PB, e)))

def bsgs(target, bound_bits=20):
    m = 1 << (bound_bits // 2); table = {}; P = Z1
    for j in range(m): table[enc(P)] = j; P = add(P, G)
    step = neg(mul(G, m)); Q = target
    for i in range(m):
        if enc(Q) in table: return i * m + table[enc(Q)]
        Q = add(Q, step)
    return None

def threshold_decrypt(share, Yi, S, C, D):
    parts = {}
    for i in S:
        P = mul(D, share[i]); parts[i] = (P, dleq_prove(share[i], D, Yi[i], P, b'dec'))
    for i, (P, pf) in parts.items():
        assert dleq_ok(D, Yi[i], P, pf, b'dec'), f'bad decryption share {i}'
    xD = msum(*[mul(P, lagrange(i, S)) for i, (P, _) in parts.items()])
    return bsgs(add(C, neg(xD))), {i: P for i, (P, _) in parts.items()}

def transfer(share, Y, Yi, S, b, rho_acc, v, fee, tamper=None, split_nonce=None, sign_set=None):
    """Joint single-recipient transfer Sigma; S decrypts, sign_set (default S) answers; True when E1..E8 hold."""
    D_set = S
    S = lag_set = sign_set or S
    C_acc, D_acc = add(mul(G, b), mul(Y, rho_acc)), mul(G, rho_acc)
    # (C) threshold decryption of acc: the coordinator learns b (it needs b' for BP#2 anyway)
    bb, Pacc = threshold_decrypt(share, Yi, D_set, C_acc, D_acc)
    assert bb == b
    # coordinator's witness: no x in it
    y_t, y_a = mul(G, rnd()), mul(G, rnd())
    s, g_v, g_b = rnd(), rnd(), rnd()
    bp = b - v - fee; assert bp >= 0
    C_out, D_out = add(mul(G, v), mul(y_t, s)), mul(G, s)
    C_deb, C_aud = add(mul(G, v), mul(Y, s)), add(mul(G, v), mul(y_a, s))
    header = secrets.token_bytes(480) + be32(fee)   # opaque to the check; the real header is 512 bytes with fee at 288
    stmt = header + b''.join(enc(p) for p in [Y, y_t, y_a, C_acc, D_acc, C_out, D_out, C_deb, C_aud])
    # round 1 (preprocessable per accSeq): each party commits two nonces on G and on D_acc
    nonces = {i: (rnd(), rnd()) for i in S}
    com = {i: (mul(G, d), mul(G, e), mul(D_acc, d), mul(D_acc, e)) for i, (d, e) in nonces.items()}
    if split_nonce is not None:  # party uses a different nonce on D_acc than on G
        d, e = nonces[split_nonce]; com[split_nonce] = com[split_nonce][:2] + (mul(D_acc, d + 1), com[split_nonce][3])
    # coordinator's own commitments, fixed before the binding factors
    k_v, k_s, k_b, k_gv, k_gb = (rnd() for _ in range(5))
    V_v, V_b = add(mul(G, v), mul(Hb, g_v)), add(mul(G, bp), mul(Hb, g_b))
    A_D, A_out, A_deb = mul(G, k_s), add(mul(G, k_v), mul(y_t, k_s)), add(mul(G, k_v), mul(Y, k_s))
    A_aud, A_Vv, A_Vb, K_b = add(mul(G, k_v), mul(y_a, k_s)), add(mul(G, k_v), mul(Hb, k_gv)), add(mul(G, k_b), mul(Hb, k_gb)), mul(G, k_b)
    own = b''.join(enc(p) for p in [V_v, V_b, A_D, A_out, A_deb, A_aud, A_Vv, A_Vb, K_b])
    clist = b''.join(i.to_bytes(4, 'big') + b''.join(enc(p) for p in com[i]) for i in sorted(S))
    def rho(i): return h2s(kk(b'SIM-TSIGMA-RHO' + i.to_bytes(4, 'big') + stmt + own + clist))  # every other input of c
    RG = {i: add(com[i][0], mul(com[i][1], rho(i))) for i in S}
    RB = {i: add(add(com[i][2], mul(com[i][3], rho(i))), neg(mul(RG[i], s))) for i in S}  # on B = D_acc - D_out
    A_y, A_bal = msum(*RG.values()), add(K_b, msum(*RB.values()))
    def chal():
        tr = T(); tr.absorb(b'statement', stmt)
        tr.absorb(b'sigma.commit', b''.join(enc(p) for p in [V_v, V_b, A_y, A_D, A_out, A_deb, A_bal, A_aud, A_Vv, A_Vb]))
        return tr.challenge(b'sigma.c')
    c = chal()
    # round 2: each party recomputes c itself, then answers once
    z = {}
    for i in S:
        assert chal() == c
        d, e = nonces[i]
        z[i] = (d + rho(i) * e + lagrange(i, lag_set) * c * share[i]) % r
    if tamper is not None: z[tamper] = (z[tamper] + 1) % r
    # identifiable abort: check every share on both bases ([x_i]B = [x_i]D_acc - [s]Y_i, from the decryption round)
    blamed = []
    for i in S:
        lc = lagrange(i, lag_set) * c % r
        okG = eq(mul(G, z[i]), add(RG[i], mul(Yi[i], lc)))
        xB = add(Pacc[i], neg(mul(Yi[i], s)))
        okB = eq(mul(add(D_acc, neg(D_out)), z[i]), add(RB[i], mul(xB, lc)))
        if not (okG and okB): blamed.append(i)
    z_x = sum(z.values()) % r
    z_v, z_s, z_b, z_gv, z_gb = ((k + c * w) % r for k, w in [(k_v, v), (k_s, s), (k_b, bp), (k_gv, g_v), (k_gb, g_b)])
    # the verifier's equations, zether.md §8.1, unchanged
    E = [
        msum(mul(G, z_x), neg(mul(Y, c)), neg(A_y)),
        msum(mul(G, z_s), neg(mul(D_out, c)), neg(A_D)),
        msum(mul(G, z_v), mul(y_t, z_s), neg(mul(C_out, c)), neg(A_out)),
        msum(mul(G, z_v), mul(Y, z_s), neg(mul(C_deb, c)), neg(A_deb)),
        msum(mul(G, z_b + c * fee), mul(D_acc, z_x), neg(mul(D_out, z_x)), neg(mul(C_acc, c)), mul(C_deb, c), neg(A_bal)),
        msum(mul(G, z_v), mul(y_a, z_s), neg(mul(C_aud, c)), neg(A_aud)),
        msum(mul(G, z_v), mul(Hb, z_gv), neg(mul(V_v, c)), neg(A_Vv)),
        msum(mul(G, z_b), mul(Hb, z_gb), neg(mul(V_b, c)), neg(A_Vb)),
    ]
    return all(is_inf(e) for e in E), [k + 1 for k, e in enumerate(E) if not is_inf(e)], blamed

def schnorr(share, Y, Yi, S, msg32):  # zether.md §13 Schnorr, FROST-style
    nonces = {i: (rnd(), rnd()) for i in S}
    com = {i: (mul(G, d), mul(G, e)) for i, (d, e) in nonces.items()}
    clist = b''.join(i.to_bytes(4, 'big') + enc(com[i][0]) + enc(com[i][1]) for i in sorted(S))
    rho = {i: h2s(kk(b'SIM-FROST-RHO' + i.to_bytes(4, 'big') + msg32 + clist)) for i in S}
    R = msum(*[add(com[i][0], mul(com[i][1], rho[i])) for i in S])
    e = h2s(kk(b'SCAAS-ZETHER-SCHNORR-V1' + enc(R) + enc(Y) + msg32))
    z = sum(nonces[i][0] + rho[i] * nonces[i][1] + lagrange(i, S) * e * share[i] for i in S) % r
    return (not is_inf(R)) and e != 0 and is_inf(msum(mul(G, z), neg(R), neg(mul(Y, e))))

def auditor_opening(share, Ya, Yi, S, amount):  # CTR-ZTH-40 AUDITOR, threshold auditor key (CTR-ZTH-41)
    t_j = rnd(); D_aud = mul(G, t_j); C_aud = add(mul(G, amount), mul(Ya, t_j))
    pre = b'SCAAS-ZETHER-DISCLOSE-V2' + be32(7622) + secrets.token_bytes(32) + secrets.token_bytes(20) + secrets.token_bytes(32) + be32(0) + be32(amount) + b'\x02'
    pts = enc(G) + enc(Ya) + enc(D_aud) + enc(C_aud)
    nonces = {i: (rnd(), rnd()) for i in S}
    com = {i: (mul(G, d), mul(G, e), mul(D_aud, d), mul(D_aud, e)) for i, (d, e) in nonces.items()}
    clist = b''.join(i.to_bytes(4, 'big') + b''.join(enc(p) for p in com[i]) for i in sorted(S))
    rho = {i: h2s(kk(b'SIM-TCP-RHO' + i.to_bytes(4, 'big') + pre + pts + clist)) for i in S}
    A1 = msum(*[add(com[i][0], mul(com[i][1], rho[i])) for i in S])
    A2 = msum(*[add(com[i][2], mul(com[i][3], rho[i])) for i in S])
    e = h2s(kk(pre + pts + enc(A1) + enc(A2)))
    z = sum(nonces[i][0] + rho[i] * nonces[i][1] + lagrange(i, S) * e * share[i] for i in S) % r
    # ZetherDisclosure._chaumPedersen: [z]G - A1 - [e]K == O and [z]B - A2 - [e](M - [amount]G) == O
    N = add(C_aud, neg(mul(G, amount)))
    return is_inf(msum(mul(G, z), neg(A1), neg(mul(Ya, e)))) and is_inf(msum(mul(D_aud, z), neg(A2), neg(mul(N, e))))

if __name__ == '__main__':
    t, n = 3, 5
    share, Y, Yi = dkg(t, n)
    S = [1, 3, 4]
    b, v, fee = 700_000, 123_456, 10
    ok, bad, blamed = transfer(share, Y, Yi, S, b, rnd(), v, fee)
    print('positive 3-of-5 transfer: E1..E8 hold =', ok, bad, 'blamed', blamed); assert ok and not blamed
    ok, bad, blamed = transfer(share, Y, Yi, S, b, rnd(), v, fee, sign_set=[3, 4])   # 2 signers of a 3-of-5 key
    print('negative, 2 signers of 3 needed: E1..E8 hold =', ok, 'failing', bad, 'blamed', blamed); assert not ok and bad == [1, 5] and not blamed
    ok, bad, blamed = transfer(share, Y, Yi, S, b, rnd(), v, fee, tamper=3)
    print('negative, party 3 tampers z_i: hold =', ok, 'failing', bad, 'blamed', blamed); assert not ok and blamed == [3]
    ok, bad, blamed = transfer(share, Y, Yi, S, b, rnd(), v, fee, split_nonce=4)
    print('negative, party 4 splits its nonce: hold =', ok, 'failing', bad, 'blamed', blamed); assert not ok and bad == [5] and blamed == [4]
    assert schnorr(share, Y, Yi, [2, 4, 5], secrets.token_bytes(32)); print('threshold Zether Schnorr verifies: True')
    share_a, Ya, Yai = dkg(3, 5)
    assert auditor_opening(share_a, Ya, Yai, [1, 2, 5], 42_000); print('threshold AUDITOR opening verifies: True')
    print('all checks passed')
