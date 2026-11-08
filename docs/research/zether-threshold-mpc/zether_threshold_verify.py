# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Research harness, UNAUDITED. Not production code; kept with docs/research/zether-threshold-mpc.md (§5.10).
# Closes the gap §5.8 names: a JOINTLY produced classical Zether transfer proof, in the exact wire format, checked by the
# repository's real native verifier (`zether-cli verifyTransfer` = zether_prover::zether::verify_transfer, the native
# mirror of the on-chain verifier: E1..E8 + both Bulletproofs), not only by the Python model of zether_threshold_sim.py.
#
# What is real: BLS12-381 G1 (py_ecc), the committed generators (smartcontracts/evm/test/vectors/zether/
# generators_bls12381.json), the 512-byte header of the frozen vector transfer_bls12381.json, the transcript, the
# statement and proof byte layouts (zether.rs TransferStatement / TransferProof, bulletproofs.rs RangeProof) and the
# verifier binary. What is simulated: the t-of-n holders run in one process (no network, no authentication); the
# coordinator's Bulletproofs are a Python port of bulletproofs.rs prove_unchecked with fresh random nonces (not the
# hedged Nonces); the DKG is the sim's Feldman-style sum (no complaint round).
#
# Run (from the repo root): python3 docs/research/zether-threshold-mpc/zether_threshold_verify.py [path/to/zether-cli]
# The verifier binary defaults to clients/zether-prover/target/release/zether-cli (build it with
# `scripts/capped cargo build --release --manifest-path clients/zether-prover/Cargo.toml` if missing).
import json, os, secrets, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from zether_threshold_sim import (kk, be32, enc, h2s, T, mul, msum, rnd, lagrange, dkg, threshold_decrypt, r,
                                  G1, Z1, add, neg, is_inf, eq)
from py_ecc.optimized_bls12_381 import FQ, is_on_curve, b as CURVE_B

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..', '..'))
CLI = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, 'clients/zether-prover/target/release/zether-cli')
GENS = json.load(open(os.path.join(ROOT, 'smartcontracts/evm/test/vectors/zether/generators_bls12381.json')))
VEC = json.load(open(os.path.join(ROOT, 'clients/zether-prover/vectors/transfer_bls12381.json')))

def dec_pt(h):
    b = bytes.fromhex(h[2:] if h.startswith('0x') else h); assert len(b) == 128 and b[:16] == bytes(16) and b[64:80] == bytes(16)
    P = (FQ(int.from_bytes(b[16:64], 'big')), FQ(int.from_bytes(b[80:128], 'big')), FQ(1))
    assert is_on_curve(P, CURVE_B); return P
G = G1
Hb, U = dec_pt(GENS['h']), dec_pt(GENS['U'])
Gs, Hs = [dec_pt(p) for p in GENS['G']], [dec_pt(p) for p in GENS['H']]
assert len(Gs) == len(Hs) == 64

def sc(x): return (x % r).to_bytes(32, 'big')
def msm(pts, ks):  # naive MSM; the bit vectors make most scalars 0, 1 or -1
    acc = Z1
    for P, k in zip(pts, ks):
        k %= r
        if k == 0: continue
        acc = add(acc, P if k == 1 else neg(P) if k == r - 1 else mul(P, k))
    return acc
def nz(tr, lab):
    c = tr.challenge(lab); assert c != 0; return c

def bp_prove(tr, n, v, gamma):
    """Port of bulletproofs.rs prove_unchecked (same absorbs and labels); fresh random nonces."""
    aL = [(v >> i) & 1 for i in range(n)]; aR = [a - 1 for a in aL]
    gs, hs = Gs[:n], Hs[:n]
    alpha, rho, tau1, tau2 = rnd(), rnd(), rnd(), rnd()
    sL, sR = [rnd() for _ in range(n)], [rnd() for _ in range(n)]
    A = msum(mul(Hb, alpha), msm(gs, aL), msm(hs, aR))
    S = msum(mul(Hb, rho), msm(gs, sL), msm(hs, sR))
    tr.absorb(b'bp.AS', n.to_bytes(4, 'big') + enc(A) + enc(S))
    y, z = nz(tr, b'bp.y'), nz(tr, b'bp.z')
    yn = [pow(y, i, r) for i in range(n)]; tw = [pow(2, i, r) for i in range(n)]; z2 = z * z % r
    l0 = [(a - z) % r for a in aL]; l1 = sL
    r0 = [(yn[i] * (aR[i] + z) + z2 * tw[i]) % r for i in range(n)]; r1 = [yn[i] * sR[i] % r for i in range(n)]
    ip = lambda a, b: sum(x * w for x, w in zip(a, b)) % r
    t1, t2 = (ip(l0, r1) + ip(l1, r0)) % r, ip(l1, r1)
    T1, T2 = add(mul(G, t1), mul(Hb, tau1)), add(mul(G, t2), mul(Hb, tau2))
    tr.absorb(b'bp.T', enc(T1) + enc(T2))
    x = nz(tr, b'bp.x')
    l = [(l0[i] + l1[i] * x) % r for i in range(n)]; rr = [(r0[i] + r1[i] * x) % r for i in range(n)]
    t_hat = ip(l, rr); taux = (tau2 * x * x + tau1 * x + z2 * gamma) % r; mu = (alpha + rho * x) % r
    tr.absorb(b'bp.t', sc(taux) + sc(mu) + sc(t_hat))
    w = nz(tr, b'bp.w'); Q = mul(U, w)
    yi = pow(y, -1, r); gv = list(gs); hv = [mul(h, pow(yi, i, r)) for i, h in enumerate(hs)]
    av, bv, Ls, Rs = l, rr, [], []
    while len(av) > 1:
        m = len(av) // 2
        aL_, aH, bL_, bH = av[:m], av[m:], bv[:m], bv[m:]
        Lp = msum(msm(gv[m:], aL_), msm(hv[:m], bH), mul(Q, ip(aL_, bH)))
        Rp = msum(msm(gv[:m], aH), msm(hv[m:], bL_), mul(Q, ip(aH, bL_)))
        tr.absorb(b'ipa.LR', enc(Lp) + enc(Rp)); u = nz(tr, b'ipa.u'); ui = pow(u, -1, r)
        av = [(aL_[i] * u + aH[i] * ui) % r for i in range(m)]; bv = [(bL_[i] * ui + bH[i] * u) % r for i in range(m)]
        gv = [add(mul(gv[i], ui), mul(gv[m + i], u)) for i in range(m)]
        hv = [add(mul(hv[i], u), mul(hv[m + i], ui)) for i in range(m)]
        Ls.append(Lp); Rs.append(Rp)
    return enc(A) + enc(S) + enc(T1) + enc(T2) + b''.join(enc(a) + enc(b) for a, b in zip(Ls, Rs)) + \
        sc(taux) + sc(mu) + sc(t_hat) + sc(av[0]) + sc(bv[0])

HEADER = bytes.fromhex(VEC['statement'][2:])[:512]          # the frozen vector's header: opTag, proofSystemId, fee 300, ...
FEE = int.from_bytes(HEADER[9 * 32:10 * 32], 'big')
assert HEADER[:32] == kk(b'SCAAS-ZETHER-OP-TRANSFER-V1') and FEE == VEC['request']['fee']

def build(share, Y, Yi, S, b, v, sign_set=None, single_x=None, tamper=None, split_nonce=None, swap_yf=None):
    """One transfer proof. single_x: the one-holder reference (k_x, z_x from x, like prove_transfer_core). Otherwise the
    joint protocol of §5.2: S decrypts acc, sign_set (default S) answers. Returns (statement bytes, proof bytes, blamed)."""
    sign = sign_set or S
    rho_acc = rnd(); C_acc, D_acc = add(mul(G, b), mul(Y, rho_acc)), mul(G, rho_acc)
    if single_x is None:
        bb, Pacc = threshold_decrypt(share, Yi, S, C_acc, D_acc); assert bb == b   # (C): the coordinator learns b
    Y_t, Y_a = mul(G, rnd()), mul(G, rnd())
    s, g_v, g_b = rnd(), rnd(), rnd(); bp_ = b - v - FEE; assert 0 <= bp_ < 2**64
    C_out, D_out = add(mul(G, v), mul(Y_t, s)), mul(G, s)
    C_deb, C_aud = add(mul(G, v), mul(Y, s)), add(mul(G, v), mul(Y_a, s))
    Y_f = Y if swap_yf is None else swap_yf
    stmt = HEADER + b''.join(enc(p) for p in [Y_f, Y_t, Y_a, C_acc, D_acc, C_out, D_out, C_deb, C_aud])
    k_v, k_s, k_b, k_gv, k_gb = (rnd() for _ in range(5))
    V_v, V_b = add(mul(G, v), mul(Hb, g_v)), add(mul(G, bp_), mul(Hb, g_b))
    A_D, A_out, A_deb = mul(G, k_s), add(mul(G, k_v), mul(Y_t, k_s)), add(mul(G, k_v), mul(Y, k_s))
    A_aud, A_Vv, A_Vb, K_b = add(mul(G, k_v), mul(Y_a, k_s)), add(mul(G, k_v), mul(Hb, k_gv)), add(mul(G, k_b), mul(Hb, k_gb)), mul(G, k_b)
    B = add(D_acc, neg(D_out)); blamed = []
    if single_x is not None:
        k_x = rnd(); A_y, A_bal = mul(G, k_x), add(K_b, mul(B, k_x))
    else:  # round 1: two nonces per holder, committed on G and on D_acc; binding factors over every other input of c
        non = {i: (rnd(), rnd()) for i in sign}
        com = {i: (mul(G, d), mul(G, e), mul(D_acc, d), mul(D_acc, e)) for i, (d, e) in non.items()}
        if split_nonce is not None:
            d, e = non[split_nonce]; com[split_nonce] = com[split_nonce][:2] + (mul(D_acc, d + 1), com[split_nonce][3])
        own = b''.join(enc(p) for p in [V_v, V_b, A_D, A_out, A_deb, A_aud, A_Vv, A_Vb, K_b])
        clist = b''.join(i.to_bytes(4, 'big') + b''.join(enc(p) for p in com[i]) for i in sorted(sign))
        rhof = lambda i: h2s(kk(b'SIM-TSIGMA-RHO' + i.to_bytes(4, 'big') + stmt + own + clist))
        RG = {i: add(com[i][0], mul(com[i][1], rhof(i))) for i in sign}
        RB = {i: add(add(com[i][2], mul(com[i][3], rhof(i))), neg(mul(RG[i], s))) for i in sign}
        A_y, A_bal = msum(*RG.values()), add(K_b, msum(*RB.values()))
    tr = T(); tr.absorb(b'statement', stmt)
    tr.absorb(b'sigma.commit', b''.join(enc(p) for p in [V_v, V_b, A_y, A_D, A_out, A_deb, A_bal, A_aud, A_Vv, A_Vb]))
    c = nz(tr, b'sigma.c')
    if single_x is not None:
        z_x = (k_x + c * single_x) % r
    else:  # round 2: one response per holder; the coordinator checks each on both bases (identifiable abort)
        z = {i: (non[i][0] + rhof(i) * non[i][1] + lagrange(i, sign) * c * share[i]) % r for i in sign}
        if tamper is not None: z[tamper] = (z[tamper] + 1) % r
        for i in sign:
            lc = lagrange(i, sign) * c % r
            xB = add(Pacc[i], neg(mul(Yi[i], s))) if i in Pacc else None
            okG = eq(mul(G, z[i]), add(RG[i], mul(Yi[i], lc)))
            okB = xB is not None and eq(mul(B, z[i]), add(RB[i], mul(xB, lc)))
            if not (okG and okB): blamed.append(i)
        z_x = sum(z.values()) % r
    z_v, z_s, z_b, z_gv, z_gb = ((k + c * w) % r for k, w in [(k_v, v), (k_s, s), (k_b, bp_), (k_gv, g_v), (k_gb, g_b)])
    sig = b''.join(enc(p) for p in [V_v, V_b, A_y, A_D, A_out, A_deb, A_bal, A_aud, A_Vv, A_Vb]) + \
        b''.join(sc(x) for x in [z_x, z_v, z_s, z_b, z_gv, z_gb])
    proof = sig + bp_prove(tr, 64, v, g_v) + bp_prove(tr, 64, bp_, g_b)
    assert len(proof) == 42 * 128 + 512                      # TransferProof::wire_len
    return stmt, proof, blamed

def verify(stmt, proof):
    out = subprocess.run([CLI, 'verifyTransfer'], input=json.dumps({'curve': 'bls12381', 'statement': '0x' + stmt.hex(),
                         'proof': '0x' + proof.hex()}), capture_output=True, text=True, check=True).stdout
    return json.loads(out)

if __name__ == '__main__':
    print('verifier:', os.path.relpath(CLI, ROOT))
    res = verify(bytes.fromhex(VEC['statement'][2:]), bytes.fromhex(VEC['proof'][2:]))
    print('P0 positive control, frozen vector transfer_bls12381.json:', res); assert res == {'ok': True}
    t, n = 3, 5
    share, Y, Yi = dkg(t, n)
    b, v = 700_000, 123_456
    x = sum(lagrange(i, [1, 2, 3]) * share[i] for i in [1, 2, 3]) % r    # only for the one-holder reference P1
    st, pf, _ = build(share, Y, Yi, [1, 2, 3], b, v, single_x=x); res = verify(st, pf)
    print('P1 one-holder proof by the Python port (prover port check):', res); assert res == {'ok': True}
    out = {}
    for S in ([1, 3, 4], [2, 4, 5]):
        st, pf, bl = build(share, Y, Yi, S, b, v); res = verify(st, pf)
        print(f'P2 joint 3-of-5 proof, holders {S}:', res, 'blamed', bl); assert res == {'ok': True} and not bl
        out[f'holders_{"".join(map(str, S))}'] = {'statement': '0x' + st.hex(), 'proof': '0x' + pf.hex()}
    st, pf, bl = build(share, Y, Yi, [1, 3, 4], b, v, sign_set=[3, 4]); res = verify(st, pf)
    print('N1 two holders answer for a 3-of-5 key:', res, 'blamed', bl); assert res['ok'] is False and 'E1' in res['error']
    st, pf, bl = build(share, Y, Yi, [1, 3, 4], b, v, tamper=3); res = verify(st, pf)
    print('N2 holder 3 adds 1 to z_i:', res, 'blamed', bl); assert res['ok'] is False and bl == [3]
    st, pf, bl = build(share, Y, Yi, [1, 3, 4], b, v, split_nonce=4); res = verify(st, pf)
    print('N3 holder 4 uses another nonce on D_acc:', res, 'blamed', bl); assert res['ok'] is False and 'E5' in res['error'] and bl == [4]
    st, pf, _ = build(share, Y, Yi, [1, 3, 4], b, v); res = verify(st, pf[:-1] + bytes([pf[-1] ^ 1]))
    print('N4 a valid joint proof with its last byte flipped (Bulletproof scalar b):', res); assert res['ok'] is False
    st2 = st[:512] + enc(mul(G, rnd())) + st[640:]; res = verify(st2, pf)
    print('N5 the same joint proof against another Y_f:', res); assert res['ok'] is False
    other = dkg(t, n)
    st, pf, _ = build(share, Y, Yi, [1, 3, 4], b, v, swap_yf=other[1]); res = verify(st, pf)
    print('N6 a joint proof by group 1 for a statement naming group 2 as sender:', res); assert res['ok'] is False
    json.dump({'note': 'UNAUDITED research output of zether_threshold_verify.py: jointly produced 3-of-5 transfer proofs '
               '(random group key, random keys) that zether-cli verifyTransfer accepted; regenerated on every run',
               'curve': 'bls12381', 'cases': out},
              open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'joint_transfer_bls12381.json'), 'w'), indent=1)
    print('all checks passed')
