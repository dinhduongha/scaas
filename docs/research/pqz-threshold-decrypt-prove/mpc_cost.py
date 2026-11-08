# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Paper estimates for docs/research/pqz-threshold-decrypt-prove.md §5 (assumptions stated in the note; nothing measured).
import math
AND_PER_KECCAK_F = 24 * 1600           # chi: 1600 AND per round, 24 rounds
RATE = 136                             # Keccak-256 rate, bytes
def perms(nbytes): return nbytes // RATE + 1   # pad10*1 needs at least one byte
rows = {"R_DR/R_DS/R_REG": 63, "R_TX": 124}
for setn, ncols, eb in (("n2048-kmax1024", 32756, 6), ("n2304-kmax4096", 45752, 6)):
    for rel, m in rows.items():
        leaf = 32 + (m + 12) * eb
        p = perms(leaf)
        tot = ncols * p
        ands = tot * AND_PER_KECCAK_F
        a2b = ncols * (m + 12) * 150     # assumption: ~150 AND per 46-bit A2B mod q (upper bound: every entry secret)
        print(f"{setn} {rel}: leaf {leaf} B, {p} perms/leaf, {tot} Keccak-f, {ands:.3g} AND, A2B {a2b:.2g} AND, "
              f"total {ands+a2b:.3g} AND = {(ands+a2b)/8/2**30:.2f} GiB/party at 1 bit/AND")
assert perms(848) == 7 and perms(482) == 4
# PQZL R_TX at n2304-kmax4096 (pqz_tx_params.h): m1 = 170 polys (163 + 7), m2 = 70, d = 64
y1, y2 = 170 * 64, 70 * 64
att = 18                                 # quad attempts per proof (of ~20 total measured, both loops)
g = att * (y1 + y2)
print(f"PQZL masks per quad attempt {y1}+{y2}={y1+y2}; per proof ~{g:.3g} Gaussian samples")
for c in (1e4, 1e5):
    print(f"  at {c:.0e} AND/sample: {g*c:.3g} AND = {g*c/8/2**30:.2f} GiB/party")
alpha = math.sqrt(2 * (38**2 + 173**2) + 3 * 64**2 + 16 * 64)
print(f"alpha {alpha:.1f}, eta*alpha {140*alpha:.0f}, sigma1/(eta*alpha) {406323.2/(140*alpha):.2f}")
for t in (2, 3, 4):
    print(f"  t={t}: one honest share sigma1/sqrt(t) / (eta*alpha) = {406323.2/math.sqrt(t)/(140*alpha):.2f}")
# Shamir with d = floor((n-1)/2): reconstruct d+1, multiply needs 2d+1 online
for n in (3, 5, 7):
    d = (n - 1) // 2
    print(f"n={n}: degree {d}, reconstruct {d+1}, multiplication online {2*d+1}")
