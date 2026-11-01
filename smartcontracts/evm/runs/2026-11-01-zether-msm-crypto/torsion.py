"""A7d. HYPOTHETICAL: an MSM that does not check the subgroup (not EIP-2537; the off-EVM ports the docs mention).
A cheating prover adds the order-3 point T to A_D BEFORE it is absorbed (so c stays consistent): E2's own value is -T,
every other equation holds. The per-equation verifier rejects every such proof (E2 != O). The fold multiplies E2 by the
integer scalar f[A_D] = r - rho; when 3 | (r - rho) the torsion component is erased and the fold is O: about one proof
in three passes a no-check MSM. With the EIP-2537 check on (the EVM case) every one of them reverts BadPoint."""
import zv
from zv import PB, R, is_inf, add, dec

blob = zv.load_gens()
gens = zv.Gens(blob)
W = zv.World(gens)
T = dec(zv.LOW_ORDER, subgroup=False)
hits = tries = 0
for sd in range(6):
    pv = zv.Prover(gens, zv.kec(b"torsion-%d" % sd))
    st = W.transfer_statement(pv, 1_000_000, 300, 5, True)

    def tamper(commits):  # A_D + T before "sigma.commit" is absorbed
        commits[3] = add(commits[3], T)
        return commits

    pr = pv.prove_transfer(st, W.xf, 300, 5, 1_000_000 - 305, 0x77, 0x88, tamper=tamper)
    zv.set_subgroup_check(True)
    on = zv.verify_transfer(st, pr, blob)
    zv.set_subgroup_check(False)
    off = zv.verify_transfer(st, pr, blob)
    rho = off.ctx.rho
    res = zv.residuals(off)
    tries += 1
    hits += off.ok
    print(f"seed {sd}: EIP-2537 check on -> {'revert BadPoint' if on.revert else on}; check off -> ok={off.ok}; "
          f"(r - rho) mod 3 = {(R - rho) % 3}; equations with non-O value: {[i for i, q in enumerate(res) if not is_inf(q)]}")
zv.set_subgroup_check(True)
print(f"hypothetical no-check MSM: {hits}/{tries} torsion-tampered proofs accepted (expected ~1/3); with the check: 0/{tries}")
