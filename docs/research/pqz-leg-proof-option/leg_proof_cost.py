# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Paper arithmetic for docs/research/pqz-leg-proof-option.md §6 (sizes, gas, wallet cost). Nothing is measured here.

Inputs are copied from the repository (each tagged where it is used):
  - proof sizes: pqz-core/params/sets/README.md, "PQZL per set: proof sizes" (the vector proofs);
  - regular gas per form: docs/contracts/pq-zero-knowledge.md §9.3 "Measured gas per relation and set" (relayed
    mtxExecute, provisional precompile rows; plan 5h Task 8d part 2b);
  - precompile rows: pqz-core/nethermind/chain/engine-pqz-provisional-n*.json (PQZL id; equal at every set:
    provisional, not calibrated per set);
  - EIP-7976 floor 15,000 + 64 gas per calldata byte, EIP-7825 cap 2^24, standard calldata 16 gas per non-zero byte
    (proof bytes are taken as all non-zero: an over-estimate), LOG data 8 gas per byte.
Everything derived is an ESTIMATE; the note says how each line is derived.
"""
import math

SETS = ["n2048-kmax1024", "n2304-kmax4096", "n2560-kmax16384", "n2816-kmax65536"]
PK = [16384, 18432, 20480, 22528]
CT = [p + 128 for p in PK]                      # u || v in 64-bit lanes
KMAX = [1024, 4096, 16384, 65536]
S_AUD = [2, 3, 4, 4]
CAP = 2 ** 24
CD_CAP = (CAP - 15000) // 64                    # 261,909 B
DISC_STMT = [33184, 37280, 41376, 45472]        # disclosure statement (op 4 / op 5)
DISC_CD = [29188, 31012, 33188, 36132]          # verifyTransferAmount calldata
DISC_GAS = [4.24e6, 4.32e6, 4.41e6, 4.51e6]     # sender disclosure, direct eth_call, regular gas

# PQZL proof sizes (B)
R_DS = [28967, 30813, 32970, 35942]
R_TX = [42783, 46670, 50382, 54880]
R_TX0 = [42424, 46343, 50045, 54541]
R_BURN = [41934, 45857, 49558, 54001]
R_TXM = {  # (M, auditor) -> sizes per set
    (1, 1): [42777, 46700, 50386, 54863], (2, 1): [43614, 47525, 51263, 57774],
    (4, 1): [58285, 63907, 54847, 59502], (8, 1): [85138, 80289, 72745, 79207],
    (1, 0): [42436, 46348, 50039, 54500], (2, 0): [42938, 46855, 50554, 55016],
    (4, 0): [43928, 47820, 51538, 58127], (8, 0): [58997, 64606, 69894, 76354],
}
# PQZL precompile rows (gas), provisional, the same at every set
P_DS, P_TX, P_TX0, P_BURN = 3381000, 7032000, 6790000, 4840000
P_TXM = {(1, 0): 5139000, (1, 1): 4712000, (2, 0): 4975000, (2, 1): 4823000,
         (4, 0): 5164000, (4, 1): 5357000, (8, 0): 6941000, (8, 1): 8030000}
# regular gas today (M), relayed mtxExecute
BASE = {
    "op1 aud": [8.99, 9.17, 9.35, 9.55], "op1 noaud": [8.70, 8.88, 9.05, 9.25],
    "op7 M1 aud": [6.69, 6.87, 7.05, 7.25], "op7 M1 noaud": [7.07, 7.25, 7.42, 7.62],
    "op7 M2 aud": [6.89, 7.08, 7.26, 7.51], "op7 M2 noaud": [6.99, 7.17, 7.34, 7.54],
    "op7 M4 aud": [8.39, 8.70, 8.05, 8.27], "op7 M4 noaud": [7.34, 7.52, 7.71, 7.97],
    "op7 M8 aud": [13.10, 12.73, 12.17, 12.56], "op7 M8 noaud": [10.24, 10.57, 10.91, 11.28],
    "burn/refresh": [6.68, 6.85, 7.02, 7.21],
}
CD_KNOWN = {"op1 aud": [64036, 70020, 75780, 82308], "op1 noaud": [63588, 69540, 75332, 81828],
            "burn/refresh": [62980, 68932, 74660, 81220],
            "op7 M8 aud": [157700, 142596, 120708, 131268], "op7 M8 noaud": [97732, 107428, 116804, 127364]}


def form(name):
    """(M, auditor) of a form; burn has no legs."""
    if name.startswith("op1"):
        return 1, int("noaud" not in name)
    if name.startswith("op7"):
        return int(name.split()[1][1:]), int("noaud" not in name)
    return 0, 0


def groups(M, A, i):
    return math.ceil(M / (S_AUD[i] if A else 4))


def out_len(M, A, i):
    return PK[i] * groups(M, A, i) + 128 * (M + 1) + 128 * M * A


def debit_proof(name, i):
    M, A = form(name)
    if name == "op1 aud":
        return R_TX[i]
    if name == "op1 noaud":
        return R_TX0[i]
    if M == 0:
        return R_BURN[i]
    return R_TXM[(M, A)][i]


def calldata(name, i):
    if name in CD_KNOWN:
        return CD_KNOWN[name][i]
    # op 7 forms without a recorded figure: the op 1 overhead (envelope, payload words) + 32 B per UA + out + proof
    over = CD_KNOWN["op1 aud"][i] - out_len(1, 1, i) - R_TX[i]
    M, A = form(name)
    return over + 64 + 32 * M + out_len(M, A, i) + debit_proof(name, i)


def leg_exec(i):
    """Execution overhead of one disclosure-style statement build, from the measured disclosure row [estimate]."""
    words = math.ceil((DISC_STMT[i] + R_DS[i]) / 32)
    return DISC_GAS[i] - 15000 - 16 * DISC_CD[i] - P_DS - 3 * words


def r_leg(i):
    """R_LEG: R_DS plus the digits as a hidden witness; the per-leg increment of R_TXM without the auditor (M 1 -> 2)."""
    return R_DS[i] + (R_TXM[(2, 0)][i] - R_TXM[(1, 0)][i])


def regular(base_m, add_gas, cd):
    floor = 15000 + 64 * cd
    return max(base_m * 1e6 + add_gas, floor)


def verdict(g, cd):
    return "fits" if g <= CAP and cd <= CD_CAP else ("over cd cap" if cd > CD_CAP else "over 2^24")


def main():
    print("== per-set inputs and derived sizes (B) ==")
    for i, s in enumerate(SETS):
        print(f"{s}: ct {CT[i]}, R_DS {R_DS[i]}, R_LEG est {r_leg(i)}, "
              f"per-leg statement-build overhead {leg_exec(i) / 1e6:.2f} M, "
              f"R_TX - R_DS {R_TX[i] - R_DS[i]}")
    print()
    print("== (a) one standalone R_LEG proof per leg (recipient legs + auditor copies) ==")
    print("== (b) one aggregated R_LEGS proof per transaction: low = R_DS price / R_TXM size - (R_TX - R_DS); "
          "high = the R_TXM price and size of the same (M, A) ==")
    print("== (c) debit-T: the token logs header (640 B) + T; no new proof ==")
    for name in BASE:
        M, A = form(name)
        legs = M * (1 + A)
        for i, s in enumerate(SETS):
            cd0 = calldata(name, i)
            base = BASE[name][i]
            row = [f"{name:13s} {s:16s} today {base:5.2f} M, cd {cd0:7d}"]
            if legs:
                per = P_DS + 16 * r_leg(i) + leg_exec(i) + 3 * math.ceil((DISC_STMT[i] + r_leg(i)) / 32)
                cd_a = cd0 + legs * r_leg(i)
                g_a = regular(base, legs * per, cd_a)
                row.append(f"(a) {legs} legs +{legs * per / 1e6:5.2f} M -> {g_a / 1e6:5.2f} M {verdict(g_a, cd_a)}")
                key = (M, A)
                sz_hi = R_TXM[key][i]
                sz_lo = sz_hi - (R_TX[i] - R_DS[i])
                stmt_words = math.ceil((out_len(M, A, i) + PK[i] * (M + A) + 640 + sz_hi) / 32)
                add_lo = P_DS + 16 * sz_lo + leg_exec(i) + 3 * stmt_words
                add_hi = P_TXM[key] + 16 * sz_hi + leg_exec(i) + 3 * stmt_words
                g_lo, g_hi = regular(base, add_lo, cd0 + sz_lo), regular(base, add_hi, cd0 + sz_hi)
                row.append(f"(b) size {sz_lo}-{sz_hi} -> {g_lo / 1e6:5.2f}-{g_hi / 1e6:5.2f} M "
                           f"{verdict(g_lo, cd0 + sz_lo)}/{verdict(g_hi, cd0 + sz_hi)}")
            log = 375 + 2 * 375 + 8 * (640 + CT[i]) + 10000
            g_c = regular(base, log, cd0)
            row.append(f"(c) +{log / 1e6:.2f} M -> {g_c / 1e6:5.2f} M {verdict(g_c, cd0)}")
            print(" | ".join(row))
    print()
    print("== wallet: bytes to fetch per credit, and for K_MAX credits (the set's own K_MAX) ==")
    for i, s in enumerate(SETS):
        a = r_leg(i) + CT[i]
        c1 = 640 + CT[i] + out_len(1, 1, i) + R_TX[i] + PK[i]
        c8 = 640 + CT[i] + out_len(8, 1, i) + R_TXM[(8, 1)][i] + PK[i]
        print(f"{s}: standalone {a} B/credit, x{KMAX[i]} = {a * KMAX[i] / 1e6:.0f} MB; "
              f"debit-T op1 aud {c1} B, op7 M8 aud {c8} B/credit, x{KMAX[i]} = "
              f"{c1 * KMAX[i] / 1e6:.0f}-{c8 * KMAX[i] / 1e6:.0f} MB (sender pk counted every time)")
    print()
    print("== verify time proxy: provisional row / 1.3 (provisional factor) / 0.12 M gas per ms p99 [estimate] ==")
    for nm, g in [("R_DS (~R_LEG)", P_DS), ("R_TX", P_TX), ("R_TXM M8 aud", P_TXM[(8, 1)])]:
        ms = g / 1.3 / 0.12e6
        print(f"{nm}: ~{ms:.0f} ms p99 on the chain host; x4096 = {4096 * ms / 1000:.0f} s single-threaded")
    print()
    print("== USD: usd = gas * gwei * 1e-9 * eth_usd; example 1 gwei, 3,000 USD/ETH (assumptions, not forecasts) ==")
    for g in (0.17e6, 4.2e6, 8.4e6):
        print(f"{g / 1e6:.2f} M gas -> {g * 1 * 1e-9 * 3000:.2f} USD")


if __name__ == "__main__":
    main()
