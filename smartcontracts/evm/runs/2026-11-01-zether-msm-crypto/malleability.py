"""A11. Malleability: from one valid transfer proof, every single-field edit (negate a point, +1 or +r on a scalar) must
be refused, so no proof byte is free (a free byte would be a second valid proof for the same statement and a cheap
rho-grinding handle). Also the honest second proof under other nonces is different and valid (that is not malleability)."""
import zv
from zv import PB, R, HEADER, be32, word, set_word, dec, neg, enc, is_inf

blob = zv.load_gens()
gens = zv.Gens(blob)
W = zv.World(gens)
pv = zv.Prover(gens, zv.kec(b"t"))
st = W.transfer_statement(pv, 1_000_000, 300, 5, True)
pr = pv.prove_transfer(st, W.xf, 300, 5, 1_000_000 - 305, 0x77, 0x88)
assert zv.verify_transfer(st, pr, blob).ok
BP0 = 10 * PB + 192
names = "V_v V_b A_y A_D A_out A_deb A_bal A_aud A_Vv A_Vb".split()
zn = "z_x z_v z_s z_b z_gv z_gb".split()
bad = 0
total = 0


def run(label, p):
    global bad, total
    vd = zv.verify_transfer(st, p, blob)
    total += 1
    if vd.ok:
        bad += 1
    br = [i for i, q in enumerate(zv.residuals(vd)) if not is_inf(q)] if hasattr(vd, "eqs") and not vd.revert else "-"
    print(f"  {label:34s} -> {'ACCEPT !!!' if vd.ok else ('revert' if vd.revert else 'false')} {vd.why!r} broken={br}")


def negate(p, off):
    b = bytearray(p)
    b[off:off + PB] = enc(neg(dec(p[off:off + PB])))
    return bytes(b)


def plus(p, off, d):
    b = bytearray(p)
    b[off:off + 32] = ((word(p, off) + d) % (1 << 256)).to_bytes(32, "big")
    return bytes(b)


print("Σ points negated")
for i, n in enumerate(names):
    run(f"-{n}", negate(pr, i * PB))
print("Σ scalars +1 and +r")
for i, n in enumerate(zn):
    run(f"{n} + 1", plus(pr, 10 * PB + 32 * i, 1))
    run(f"{n} + r (same value, other encoding)", plus(pr, 10 * PB + 32 * i, R))
print("BP(v): points negated, scalars +1 / +r")
for i, n in enumerate("A S T1 T2 L0 R0 L5 R5".split()):
    idx = {"A": 0, "S": 1, "T1": 2, "T2": 3, "L0": 4, "R0": 5, "L5": 14, "R5": 15}[n]
    run(f"-{n} of BP(v)", negate(pr, BP0 + idx * PB))
for i, n in enumerate("tau_x mu t_hat a b".split()):
    run(f"{n} + 1 of BP(v)", plus(pr, BP0 + 16 * PB + 32 * i, 1))
    run(f"{n} + r of BP(v)", plus(pr, BP0 + 16 * PB + 32 * i, R))
print("BP(b'): a + 1, b + r")
run("a + 1 of BP(b')", plus(pr, BP0 + zv.BP_LEN + 16 * PB + 96, 1))
run("b + r of BP(b')", plus(pr, BP0 + zv.BP_LEN + 16 * PB + 128, R))
print("statement: every point negated")
for i, n in enumerate("Y_f Y_t Y_a C_acc D_acc C_out D_out C_deb C_aud".split()):
    run(f"-{n} (statement)", negate(st, HEADER + i * PB) if True else None) if False else None
    s2 = bytearray(st)
    s2[HEADER + i * PB:HEADER + (i + 1) * PB] = enc(neg(dec(st[HEADER + i * PB:HEADER + (i + 1) * PB])))
    vd = zv.verify_transfer(bytes(s2), pr, blob)
    total += 1
    bad += vd.ok
    print(f"  {('-' + n + ' (statement)'):34s} -> {'ACCEPT !!!' if vd.ok else 'false'} {vd.why!r}")
pv2 = zv.Prover(gens, zv.kec(b"other"))
pr2 = pv2.prove_transfer(st, W.xf, 300, 5, 1_000_000 - 305, 0x77, 0x88)
print(f"second honest proof under other nonces: different bytes = {pr2 != pr}, valid = {zv.verify_transfer(st, pr2, blob).ok} (not malleability: it needs the witness)")
print(f"single-field edits accepted: {bad}/{total}")
