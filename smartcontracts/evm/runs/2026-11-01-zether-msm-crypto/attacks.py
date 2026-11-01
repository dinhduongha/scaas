"""Forgery attempts against the merged-MSM Zether verifier (zv.py model, exact BLS12-381 G1 arithmetic).

Every attempt prints: verdict, the equations whose own value is not O (when the fold ran), and the code line that stopped it."""
import sys, time
import zv
from zv import R, PB, HEADER, be32, word, set_word, enc, dec, add, neg, mul, Z1, is_inf, SLOT_EXT

blob = zv.load_gens()
gens = zv.Gens(blob)
W = zv.World(gens)
B, FEE = 1_000_000, 5
rows = []          # for the forge replay
results = []       # (name, ok, revert, broken, stopped_by)


def attempt(name, op, st, pr, expect, stopped_by, replay=False):
    t = time.time()
    vd = zv.verify(op, st, pr, blob)
    broken = "-"
    if hasattr(vd, "eqs") and not vd.revert:
        broken = [i for i, q in enumerate(zv.residuals(vd)) if not is_inf(q)]
    verdict = "revert" if vd.revert else ("accept" if vd.ok else "false")
    flag = "OK" if verdict == expect else "!!! UNEXPECTED"
    print(f"[{flag}] {name}\n      verdict={verdict} (expected {expect}) why={vd.why!r} broken_eqs={broken}  <- {stopped_by}  ({time.time()-t:.1f}s)")
    results.append((name, verdict, expect, broken, stopped_by))
    if replay:
        rows.append({"name": name, "op": op, "statement": "0x" + st.hex(), "proof": "0x" + pr.hex(), "expect": expect})
    return vd


def transfer(aud, bal=B, amt=300, wit=None, fee=FEE, seed=b"t", gV=0x77, gB=0x88, bPrime=None, yt=None):
    pv = zv.Prover(gens, zv.kec(seed))
    st = W.transfer_statement(pv, bal, amt, fee, aud, yt=yt)
    wit = amt if wit is None else wit
    bp = (bal - wit - fee) % R if bPrime is None else bPrime
    return st, pv.prove_transfer(st, W.xf, wit, 5, bp, gV, gB), pv


def z_off(i):  # transfer: z_x z_v z_s z_b z_gv z_gb
    return 10 * PB + 32 * i


BP0 = 10 * PB + 192
BP1 = BP0 + zv.BP_LEN
T = zv.LOW_ORDER


def with_word(pr, off, v):
    b = bytearray(pr)
    set_word(b, off, v % R)
    return bytes(b)


def with_point(buf, off, pt_bytes):
    b = bytearray(buf)
    b[off:off + PB] = pt_bytes
    return bytes(b)


print("=" * 100)
print("honest baseline (transfer, auditor on): Σ E1..E8 = eqs 0..7, BP(v) = 8,9, BP(b') = 10,11")
st, pr, pv = transfer(True)
vd0 = attempt("honest transfer (python prover)", "transfer", st, pr, "accept", "-", replay=True)
rho = vd0.ctx.rho
c = vd0.ctx.c
print(f"      c = {hex(c)[:18]}..  rho = {hex(rho)[:18]}..")

# ------------------------------------------------------------------ A1/A2: cancelling pairs built to the honest rho
print("=" * 100)
print("A1  the documented pair: z_gv += d, z_gb -= d/rho  (breaks E7 by [d]Hb at rho^6 and E8 by [-d/rho]Hb at rho^7)")
d = 0xD00D
pr1 = with_word(pr, z_off(4), word(pr, z_off(4)) + d)
pr1 = with_word(pr1, z_off(5), word(pr1, z_off(5)) - d * zv.inv(rho))
vd = attempt("A1 pair built to the honest rho", "transfer", st, pr1, "false",
             "ZetherVerifier.sol:483 x.rho = _rho(x.st, x.pr) absorbs every proof byte (lines 59-61): rho moved", replay=True)
res = zv.residuals(vd)
print(f"      oracle: fold with the OLD rho would be {'O' if is_inf(zv.fold_sum_from_residuals(res, rho)) else 'non-O'}; "
      f"with the actual rho' = {hex(vd.ctx.rho)[:14]}.. it is non-O")

print("A2  shared-slot pair on G alone: z_v += d (E3,E4,E6,E7 share slot G) and z_b += Db (E5,E8) with "
      "Db = -d (r^2+r^3+r^5+r^6)/(r^4+r^7): the whole fold cancels in the GROUP for the honest rho, 6 equations false")
num = (pow(rho, 2, R) + pow(rho, 3, R) + pow(rho, 5, R) + pow(rho, 6, R)) % R
den = (pow(rho, 4, R) + pow(rho, 7, R)) % R
Db = (-d * num * zv.inv(den)) % R
pr2 = with_word(pr, z_off(1), word(pr, z_off(1)) + d)
pr2 = with_word(pr2, z_off(3), word(pr2, z_off(3)) + Db)
vd = attempt("A2 G-slot pair built to the honest rho", "transfer", st, pr2, "false",
             "same: rho re-hashed over the modified z_v, z_b (ZetherVerifier.sol:59-61, 483)", replay=True)
res = zv.residuals(vd)
print(f"      oracle: fold with the OLD rho = {'O (the attack beats a verifier whose rho ignores the scalars)' if is_inf(zv.fold_sum_from_residuals(res, rho)) else 'non-O'}")

print("A2b fixed-point grind: rebuild Db to the new rho, re-hash, repeat; the map rho -> rho' is a random function of r values")
cur = pr
seen = set()
hit = False
for it in range(12):
    r_ = zv.rho_of(vd0.ctx.st, cur)
    num = (pow(r_, 2, R) + pow(r_, 3, R) + pow(r_, 5, R) + pow(r_, 6, R)) % R
    den = (pow(r_, 4, R) + pow(r_, 7, R)) % R
    Db = (-d * num * zv.inv(den)) % R
    cand = with_word(pr, z_off(1), word(pr, z_off(1)) + d)
    cand = with_word(cand, z_off(3), word(cand, z_off(3)) + Db)
    r2 = zv.rho_of(vd0.ctx.st, cand)
    if r2 == r_:
        hit = True
        break
    cur = cand
print(f"      {it+1} iterations, fixed point found: {hit} (needs rho' to land on one of <= 7 roots of a degree-7 polynomial: <= 7/r per try)")

# ------------------------------------------------------------------ A3: zero scalars on shared slots
print("=" * 100)
print("A3  z_s := 0 zeroes the folded scalar of Y_t and Y_a (their only terms are z_s): not a forgery, E2 E3 E4 E6 break")
attempt("A3 z_s := 0", "transfer", st, with_word(pr, z_off(2), 0), "false", "equations E2/E3/E4/E6 no longer hold")
print("A3b z_x := 0 gives D_acc the folded scalar 0; D_acc moved out of the subgroup still reaches G1MSM")
st3 = with_point(st, HEADER + 4 * PB, zv.g1add_precompile(st[HEADER + 4 * PB:HEADER + 5 * PB], T))
attempt("A3b z_x := 0 and D_acc + T (order 3)", "transfer", st3, with_word(pr, z_off(0), 0), "revert",
        "ZetherVerifier.sol:182-185/211: every slot stays in pts; G1Bls12381.msm reverts BadPoint (ZetherCurves.sol:231)", replay=True)

# ------------------------------------------------------------------ A4: mix-and-match range proofs
print("=" * 100)
print("A4  range proofs swapped / spliced")
swapped = pr[:BP0] + pr[BP1:BP1 + zv.BP_LEN] + pr[BP0:BP1]
attempt("A4a BP(v) <-> BP(b')", "transfer", st, swapped, "false",
        "transcript order (ZetherVerifier.sol:202-210) and the commitment slot per position (403)")
sw2 = with_point(with_point(swapped, 0, pr[PB:2 * PB]), PB, pr[0:PB])
attempt("A4b BP(v) <-> BP(b') and V_v <-> V_b", "transfer", st, sw2, "false",
        "E7/E8 tie V_v to z_v (E3/E4) and V_b to z_b (E5): ZetherVerifier.sol:561-563")
st_o, pr_o, _ = transfer(True, seed=b"other-nonces")
spliced = pr[:BP0] + pr_o[BP0:BP1] + pr[BP1:]
attempt("A4c BP(v) spliced from another valid proof of the same statement", "transfer", st, spliced, "false",
        "its challenges come from this proof's transcript (ZetherVerifier.sol:246-266)")
attempt("A4d the other proof's full BP tail", "transfer", st, pr[:BP0] + pr_o[BP0:], "false",
        "the fold's rho and the BP transcript both hash this proof's Σ part")
# multi: two legs, swap their range proofs
pvm = zv.Prover(gens, zv.kec(b"m"))
vs = [100, 101]
stm = W.multi_statement(pvm, B, vs, FEE, True)
prm = pvm.prove_multi(stm, W.xf, 5, vs, [0x7A0, 0x7A1], B - FEE - sum(vs), [0x1234, 0x123B], 0x5678)
attempt("honest multi M=2 (auditor on)", "multi", stm, prm, "accept", "-", replay=True)
offm = (6 + 5 * 2) * PB + (4 + 3 * 2) * 32
prm_sw = prm[:offm] + prm[offm + zv.BP_LEN:offm + 2 * zv.BP_LEN] + prm[offm:offm + zv.BP_LEN] + prm[offm + 2 * zv.BP_LEN:]
attempt("A4e multi: BP(v_1) <-> BP(v_2)", "multi", stm, prm_sw, "false",
        "commitments[k] = V_vk by position (ZetherVerifier.sol:420) and the transcript order")

# ------------------------------------------------------------------ A5: overspend, reusing an in-range commitment for V_b
print("=" * 100)
print("A5  overspend by 1 (bal 1000, v 1001, fee 0): V_b := V_v with BP(b') proving v's opening, so E8 and both BPs hold")
st5, pr5, _ = transfer(False, bal=1000, amt=1001, fee=0, bPrime=1001, gB=0x77)
attempt("A5 V_b = V_v, witness b' := v", "transfer", st5, pr5, "false",
        "E5 ties z_b to the ciphertexts: b' + fee + v - b = 0 fails (ZetherVerifier.sol:501-512, 553)", replay=True)
print("A5b plain overspend: the prover's b' = r - 1 is committed, the 64 low bits are proved")
st5b, pr5b, _ = transfer(False, bal=1000, amt=1001, fee=0)
attempt("A5b honest flow with b' = -1 mod r", "transfer", st5b, pr5b, "false", "BP-1 of BP(b') (ZetherVerifier.sol:269-292)")
print("A5c value exactly 2^64: committed and proved on 64 bits")
st5c, pr5c, _ = transfer(False, bal=2 ** 64 + 10, amt=2 ** 64, fee=0)
attempt("A5c v = 2^64", "transfer", st5c, pr5c, "false", "BP-1 of BP(v): t_hat - delta does not match V's value")

# ------------------------------------------------------------------ A6: auditor-off O slots
print("=" * 100)
print("A6  auditor off: the O slots")
sto, pro, _ = transfer(False)
attempt("honest transfer (auditor off)", "transfer", sto, pro, "accept", "-")
attempt("A6a C_aud := G with Y_a = O", "transfer", with_point(sto, HEADER + 8 * PB, zv.G_BYTES), pro, "false",
        "ZetherVerifier.sol:555-556 _isZero(C_aud)")
attempt("A6b A_aud := G with Y_a = O", "transfer", sto, with_point(pro, 7 * PB, zv.G_BYTES), "false",
        "ZetherVerifier.sol:556 _isZero(A_aud)")
nz = bytearray(PB); nz[5] = 1  # 'zero' with a padding bit: not O for _isZero, invalid for the precompile
attempt("A6c C_aud := non-canonical O (padding bit) with Y_a = O", "transfer", with_point(sto, HEADER + 8 * PB, bytes(nz)), pro, "false",
        "ZetherVerifier.sol:555-556 compares raw bytes; a padding bit is not O")
attempt("A6d auditor-on proof, statement Y_a := O", "transfer", with_point(st, HEADER + 2 * PB, bytes(PB)), pr, "false",
        "statement is hashed (c, rho move) and C_aud != O under Y_a = O (ZetherVerifier.sol:555-556)")
stmo = W.multi_statement(pvm, B, vs, FEE, False)
prmo = pvm.prove_multi(stmo, W.xf, 5, vs, [0, 0], B - FEE - sum(vs), [0x1234, 0x123B], 0x5678)
attempt("honest multi M=2 (auditor off)", "multi", stmo, prmo, "accept", "-")
zt0 = (6 + 5 * 2) * PB + 32 * 6
attempt("A6e multi auditor off: z_t0 := 1", "multi", stmo, with_word(prmo, zt0, 1), "false", "ZetherVerifier.sol:662 zt == 0")
attempt("A6f multi auditor off: C_aud_0 := G", "multi", with_point(stmo, HEADER + 6 * PB + 32 + 2 * PB, zv.G_BYTES), prmo, "false",
        "ZetherVerifier.sol:662 _isZero(C_aud_j)")
attempt("A6g multi auditor off: A_Daud_0 := G", "multi", stmo, with_point(prmo, (6 + 3) * PB, zv.G_BYTES), "false",
        "ZetherVerifier.sol:662-663 _isZero(A_Daud_j)")
# auditor on: two legs with the same t (shared C_aud/D_aud)
prm_same_t = pvm.prove_multi(stm, W.xf, 5, vs, [0x7A0, 0x7A0], B - FEE - sum(vs), [0x1234, 0x123B], 0x5678)
stm_same_t = W.multi_statement(pvm, B, vs, FEE, True, t0=0x7A0)
st_dup = bytearray(stm_same_t)
# force leg 1 to reuse leg 0's t: rebuild leg 1's aud copy with t0
c_aud1, d_aud1 = pvm.aud_copy(W.ya, vs[1], 0x7A0)
st_dup[HEADER + 6 * PB + 32 + (4 * 1 + 2) * PB:HEADER + 6 * PB + 32 + (4 * 1 + 3) * PB] = enc(c_aud1)
st_dup[HEADER + 6 * PB + 32 + (4 * 1 + 3) * PB:HEADER + 6 * PB + 32 + (4 * 1 + 4) * PB] = enc(d_aud1)
pr_dup = pvm.prove_multi(bytes(st_dup), W.xf, 5, vs, [0x7A0, 0x7A0], B - FEE - sum(vs), [0x1234, 0x123B], 0x5678)
attempt("A6h multi auditor on: two legs share D_aud (same t_j), otherwise valid", "multi", bytes(st_dup), pr_dup, "false",
        "ZetherVerifier.sol:622-631 _distinctAud")

# ------------------------------------------------------------------ A7: low-order coset points
print("=" * 100)
print("A7  points in a low-order coset (T = (0,2), order 3)")
attempt("A7a A_y + T", "transfer", st, with_point(pr, 2 * PB, zv.g1add_precompile(pr[2 * PB:3 * PB], T)), "revert",
        "G1MSM subgroup check on every input (ZetherCurves.sol:230-231)", replay=True)
pr7 = with_point(pr, 2 * PB, zv.g1add_precompile(pr[2 * PB:3 * PB], T))
pr7 = with_point(pr7, 3 * PB, zv.g1add_precompile(pr[3 * PB:4 * PB], enc(neg(dec(T, False)))))
attempt("A7b A_y + T and A_D - T (would cancel under equal weights)", "transfer", st, pr7, "revert",
        "the call fails before any sum (ZetherCurves.sol:230-231)", replay=True)
attempt("A7c statement C_out + T", "transfer", with_point(st, HEADER + 5 * PB, zv.g1add_precompile(st[HEADER + 5 * PB:HEADER + 6 * PB], T)), pr,
        "revert", "statement points are in the MSM (ZetherVerifier.sol:400)")
print("A7d (hypothetical MSM without the subgroup check): see torsion.py")

# ------------------------------------------------------------------ A8: O for commitments
print("=" * 100)
print("A8  O as a commitment")
attempt("A8a V_v := O on a v = 300 proof", "transfer", st, with_point(pr, 0, bytes(PB)), "false", "E7 and BP-1 of BP(v) break")
st8, pr8, _ = transfer(True, amt=0, gV=0)
attempt("A8b honest v = 0, gamma_v = 0: V_v = O (a valid zero transfer, not a forgery)", "transfer", st8, pr8, "accept",
        "nothing refuses O as a commitment; E7 forces its opening to be (0, 0)", replay=True)
print(f"      V_v bytes all zero: {pr8[:PB] == bytes(PB)}")
attempt("A8c statement C_out := O", "transfer", with_point(st, HEADER + 5 * PB, bytes(PB)), pr, "false", "E3 breaks; c moves")
attempt("A8d statement D_out := O", "transfer", with_point(st, HEADER + 6 * PB, bytes(PB)), pr, "false", "ZetherVerifier.sol:539 _isZero(D_out)")
attempt("A8e statement Y_t := Y_f", "transfer", with_point(st, HEADER + 1 * PB, st[HEADER:HEADER + PB]), pr, "false", "ZetherVerifier.sol:540")

# ------------------------------------------------------------------ A9: M edge values and cross-form confusion
print("=" * 100)
print("A9  M edge values, cross-form confusion")
mAt = HEADER + 6 * PB
for mv in (0, 1, 3, 17, 2 + (1 << 255)):
    attempt(f"A9 M := {mv if mv < 100 else '2 + 2^255'}", "multi", stm[:mAt] + be32(mv) + stm[mAt + 32:], prm,
            "false", "ZetherVerifier.sol:426-437 _multiLegs")
attempt("A9f transfer statement/proof into verifyTransferMulti", "multi", st, pr, "false", "ZetherVerifier.sol:429-434")
stm1 = W.multi_statement(pvm, B, [300], FEE, True)
prm1 = pvm.prove_multi(stm1, W.xf, 5, [300], [0x7A0], B - FEE - 300, [0x1234], 0x5678)
attempt("honest multi M=1", "multi", stm1, prm1, "accept", "-")
attempt("A9g multi M=1 into verifyTransfer", "transfer", stm1, prm1, "false", "ZetherVerifier.sol:398-399 lengths/opTag/psid")
stb = W.burn_statement(B, 400, FEE)
prb = zv.Prover(gens, zv.kec(b"b")).prove_burn(stb, W.xf, B - 400 - FEE, 0x99)
attempt("honest burn", "burn", stb, prb, "accept", "-", replay=True)
attempt("A9h burn into verifyTransfer", "transfer", stb, prb, "false", "ZetherVerifier.sol:398")
attempt("A9i transfer opTag := burn opTag", "transfer", zv.OP_BURN + st[32:], pr, "false", "ZetherVerifier.sol:399")
attempt("A9j multi opTag := HASH variant (hashed, fine for the verifier: a different statement)", "multi",
        zv.OP_MULTI_HASH + stm[32:], prm, "false", "statement hashed: c and rho move")

# ------------------------------------------------------------------ A10: header fields the verifier reads mod r
print("=" * 100)
print("A10 fee / amount are read mod r by the verifier (ZetherVerifier.sol:505, 692): with fee = r - 2^63 a zero balance sends 2^63 - 1")
pv10 = zv.Prover(gens, zv.kec(b"fee"))
fee_big = R - (1 << 63)
st10 = W.transfer_statement(pv10, 0, (1 << 63) - 1, fee_big, False)
pr10 = pv10.prove_transfer(st10, W.xf, (1 << 63) - 1, 5, 1, 0x77, 0x88)  # b' = 0 - v - fee = 1 mod r
attempt("A10a transfer bal 0, v 2^63-1, fee r-2^63 (b' = 1): VERIFIER ACCEPTS; ZetherLib bounds fee < 2^64 (lines 184-185, 534-537)",
        "transfer", st10, pr10, "accept", "token boundary, not the verifier", replay=True)
stb10 = W.burn_statement(5, R - 1, 0)  # amount = -1 mod r
prb10 = zv.Prover(gens, zv.kec(b"b2")).prove_burn(stb10, W.xf, 6, 0x99)  # b' = 5 - (-1) = 6
attempt("A10b burn bal 5, amount r-1 (= -1), fee 0, b' = 6: VERIFIER ACCEPTS; ZetherLib.prepareUnshield bounds amount (line 551-560)",
        "burn", stb10, prb10, "accept", "token boundary, not the verifier", replay=True)
attempt("A10c honest proof, fee word += r (same E5 mod r, different bytes)", "transfer", st[:288] + be32(word(st, 288) + R) + st[320:], pr,
        "false", "statement hashed: c moves")

# ------------------------------------------------------------------ A12 / A16: header words, padding bytes
print("=" * 100)
print("A12 every header word is hashed; A16 a padding byte of a point")
attempt("A12 chainId word flipped", "transfer", st[:64] + be32(word(st, 64) ^ 1) + st[96:], pr, "false", "statement hashed")
padbit = bytearray(pr); padbit[2 * PB + 3] ^= 1
attempt("A16 A_y padding byte set", "transfer", st, bytes(padbit), "revert", "G1MSM rejects a non-zero padding (ZetherCurves.sol:231)")

# ------------------------------------------------------------------ A15: the inner-product verifier trusts its caller
print("=" * 100)
print("A15 verifyFold is external: with the caller's rho = 1 the A1 pair passes. The transfer/burn verifiers never pass a caller's rho.")
x = zv.Fold(st, pr1, 10 * PB, pr1[0:10 * PB] + st[HEADER:])
x.rho, x.w = 1, 1
ok, _ = zv._sigma_transfer(x)
# with rho = 1, build the pair so the Hb terms cancel: z_gv + d, z_gb - d
pr15 = with_word(pr, z_off(4), word(pr, z_off(4)) + d)
pr15 = with_word(pr15, z_off(5), word(pr15, z_off(5)) - d)
x = zv.Fold(st, pr15, 10 * PB, pr15[0:10 * PB] + st[HEADER:])
x.rho, x.w = 1, 1
zv._sigma_transfer(x)
vd15 = zv.verify_fold(x.st, 1, x.w, x.pts, x.f, [SLOT_EXT, SLOT_EXT + 1], pr15[BP0:], blob, eqs=x.eqs)
print(f"      verifyFold(rho = 1) on the cancelling pair: ok={vd15.ok}  (two false equations; the caller owns rho: IZetherVerifier.sol:105-106)")
results.append(("A15 verifyFold with caller rho = 1 and a cancelling pair", "accept" if vd15.ok else "false", "n/a (external API)", "[6, 7]",
                "documented precondition only; no production caller passes a foreign rho"))

# ------------------------------------------------------------------ dump
print("=" * 100)
unexpected = [r for r in results if r[2] not in ("n/a", "n/a (external API)") and r[1] != r[2]]
print("UNEXPECTED verdicts:", unexpected if unexpected else "none")
