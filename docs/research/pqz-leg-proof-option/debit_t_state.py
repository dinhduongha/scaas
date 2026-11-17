# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Paper arithmetic for docs/research/pqz-leg-proof-option.md §14 (debit-T from state). Nothing is measured here.

Inputs copied from the repository (each tagged where it is used):
  - EIP-8037: 1,530 state gas per byte (CPSB), a new slot 64 * CPSB = 97,920; clearing a slot that existed before the
    transaction gives no state gas back (EIP-8037 text, checked 2026-11-06);
  - EIP-8038 rewrite 10,000 + 2,100 cold (docs/contracts/pq-zero-knowledge.md §7.6); the clear refund 4,800 is the Osaka
    figure of the state spec (2026-10-20-pqz-state-redesign.md §4, §5.5), not re-recorded for Amsterdam;
  - CTP = (N + 16) * PACK_BITS / 8, PACK_BITS = ceil(log2 q) (pq-zero-knowledge.md stored form; 13,340 B at n2304-kmax4096,
    PqzSet.ZERO_HASH comment); ACC_WORDS 339 / 417 / 504 / 598;
  - op 1 with the auditor: blob 11,052 / 13,572 / 16,348 / 19,380 B and 17.58 / 21.44 / 25.69 / 30.33 M state gas,
    regular 8.99 / 9.17 / 9.35 / 9.55 M (CTR-PQZ-07, §9.3; leg_proof_cost.py BASE);
  - PQZL proof sizes (pqz-core/params/sets/README.md, as in leg_proof_cost.py); PQZH debit about 250 KB (note §11.3);
  - a new code account about 183,600 state gas (docs/research/zether-library-split.md, a library account);
  - 24,576 B code limit on public chains, 60 M block (review C0-10 reference), node max_gas_per_tx 64 M (networks/evm.md).
Everything derived is an ESTIMATE.
"""
import math

SETS = ["n2048-kmax1024", "n2304-kmax4096", "n2560-kmax16384", "n2816-kmax65536"]
N = [2048, 2304, 2560, 2816]
PACK = [42, 46, 50, 54]
ACC_WORDS = [339, 417, 504, 598]
KMAX = [1024, 4096, 16384, 65536]
ROLL_MAX = [96, 80, 64, 32]
CT = [8 * n + 128 for n in N]        # u || v in 64-bit lanes (k polys x 64 coefficients x 8 B, plus 16 x 8 B)
CTP = [(n + 16) * b // 8 for n, b in zip(N, PACK)]
BLOB_OP1A = [11052, 13572, 16348, 19380]
STATE_OP1A = [17.58e6, 21.44e6, 25.69e6, 30.33e6]
REG_OP1A = [8.99e6, 9.17e6, 9.35e6, 9.55e6]
R_TX = [42783, 46670, 50382, 54880]
R_BURN = [41934, 45857, 49558, 54001]
R_TXM8A = [85138, 80289, 72745, 79207]
PQZH_DEBIT = 250_000  # n2304-kmax4096 only, rough

CPSB, SLOT = 1530, 97920
CLEAR_GROSS, CLEAR_REFUND = 2100 + 10000, 4800
RECORD_REG = 2100 + 2900       # regular part of a zero -> non-zero write, cold [estimate]
ACCOUNT = 183600
CODE_LIMIT = 24576
BLOCK60, NODE_CAP = 60e6, 64e6
INLINE_MAX = 16


def m(x):
    return f"{x / 1e6:.2f} M"


def main():
    assert CTP[1] == 13340, CTP  # PqzSet.ZERO_HASH: 13,340 zero bytes at n2304-kmax4096
    for i, w in enumerate(ACC_WORDS):
        assert math.ceil(CTP[i] / 32) == w, (SETS[i], CTP[i], w)

    print("== storing T itself (for comparison) and the debit-T log ==")
    for i, s in enumerate(SETS):
        sstore2 = CTP[i] * CPSB + ACCOUNT
        slots = ACC_WORDS[i] * SLOT
        log = 375 + 2 * 375 + 8 * (640 + CT[i]) + 10000
        print(f"{s}: T in SSTORE2 {m(sstore2)}, T in fresh slots {m(slots)}, log header||T {m(log)}")

    print("\n== direction 2: keep the pending slots, one record slot per debit ==")
    hdr_log = 375 + 2 * 375 + 8 * 640 + 2000
    for i, s in enumerate(SETS):
        lo = SLOT + RECORD_REG                                    # no slot kept that a debit would have deleted
        hi_fit = SLOT + RECORD_REG - 2 * INLINE_MAX * CLEAR_GROSS  # 32 deletions skipped: regular gas for the 2^24 fit
        hi_pay = SLOT + RECORD_REG - 2 * INLINE_MAX * (CLEAR_GROSS - CLEAR_REFUND)  # what the payer sees
        roll = ROLL_MAX[i] * CLEAR_GROSS
        print(f"{s}: debit +{m(SLOT)} state, regular +{RECORD_REG:,} minus up to {2 * INLINE_MAX} skipped deletions"
              f" (fit: {m(hi_fit - SLOT)} regular at 32; payer net {m(hi_pay)} total at 32, {m(lo)} at 0);"
              f" + header-only log {m(hdr_log)}; rollover at ROLL_MAX: up to {m(roll)} regular less (gross)")

    print("\n== keeping the proof P in state as well (SSTORE2, chunks at the public 24,576 B code limit) ==")
    rows = [("op 1 aud", R_TX), ("burn/refresh", R_BURN), ("op 7 M=8 aud", R_TXM8A)]
    for i, s in enumerate(SETS):
        out = []
        for name, sz in rows:
            chunks = math.ceil(sz[i] / (CODE_LIMIT - 1))
            g = sz[i] * CPSB + chunks * ACCOUNT
            out.append(f"{name} {sz[i]:,} B -> +{m(g)} state ({chunks} chunks)")
        tot = REG_OP1A[i] + STATE_OP1A[i] + R_TX[i] * CPSB + math.ceil(R_TX[i] / (CODE_LIMIT - 1)) * ACCOUNT + SLOT
        fit = "fits" if tot <= BLOCK60 else "over a 60 M block"
        fit += ", over the node's 64 M" if tot > NODE_CAP else ""
        print(f"{s}: " + "; ".join(out) + f"; op 1 aud tx.gas ~ {m(tot)} ({fit})")
    g = PQZH_DEBIT * CPSB + math.ceil(PQZH_DEBIT / (CODE_LIMIT - 1)) * ACCOUNT
    print(f"PQZH debit at n2304-kmax4096 (~{PQZH_DEBIT:,} B): +{m(g)} state")

    print("\n== state growth ==")
    for i, s in enumerate(SETS):
        print(f"{s}: op 1 aud blob {BLOB_OP1A[i]:,} B per debit today; direction 2 adds 32 B per debit (record) and"
              f" keeps 32 B per credit; with P: +{R_TX[i]:,} B per op 1 ({R_TX[i] / BLOB_OP1A[i]:.1f}x the blob)")

    print("\n== a wallet rebuilding a third party's T from state (no server) ==")
    for i, s in enumerate(SETS):
        worst = (KMAX[i] - 1) * CTP[i]
        print(f"{s}: per entry ~{CTP[i]:,} B packed (or a shared blob); typical 1-16 entries "
              f"{CTP[i] / 1e3:.0f}-{16 * CTP[i] / 1e3:.0f} KB; worst K_MAX - 1 entries {worst / 1e6:.0f} MB")


if __name__ == "__main__":
    main()
