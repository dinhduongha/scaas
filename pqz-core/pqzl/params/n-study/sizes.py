#!/usr/bin/env python3
"""Plan 5h Task 7c: sizes and gas per candidate cell, from the measured codegen proof sizes (e-s1-<cell>.txt; the 16k
reference from ../p16k/estimator-e-s1-16k.txt) and the pqz-stmt layout (pqz-core/stmt/src/lib.rs: PK = 8 n,
CT = PK + 128, V = 128, header 640; op 7 multi_len with one randomness group for M <= 4).

Gas, all [estimate]:
- old rules (Foundry 1.3.5, Task 7's as-built pins at 516 words = today and 644 words = 16k): every figure linear in
  the acc word count w = CT / 32 between the two measured points; ROLL_MAX = the largest multiple of 16 whose full
  relayed rollover transaction (fee 7) stays <= 0.75 * 2^24;
- Amsterdam (EIP-7976 / 8037 / 8038; Task 7b commit 9c2f53ef, Foundry 1.8.5, 644 words only): the full relayed
  rollover is 51,003 / entry + 8,276,219, whose fixed part is w cold acc rewrites at 12,100 (EIP-8038) + 483,819; the
  per-entry part moves with w by the old rules' slope (53.75 / word, the lane-add loop); state gas (EIP-8037) of the op 1
  SSTORE2 blob at 1,530 / byte and of a prepare half in proportion to w;
- precompile: today's calibrated rows times n / 2048 (Task 7 used the statement ratio 1.25 for n = 2560).
Stdlib only:  python3 -I pqz-core/pqzl/params/n-study/sizes.py > pqz-core/pqzl/params/n-study/sizes.txt
"""
import json
import math
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))
HDR, V = 640, 128
CAP = 12_582_912                      # 0.75 * 2^24
CALLDATA_MAX = 261_909                # Task 7b: 15,000 + 64 n <= 2^24 (EIP-7976 floor), one transaction
MAX_INPUT, MAX_PROOF = 261_120, 98_304      # Task 7b's MAX_INPUT proposal (255 KiB)
FORMS = ("reg", "tx", "tx0", "burn", "ds", "dr", "txm2", "txm20", "txm4", "txm40")

# old rules: (516 words, 644 words) measured by Task 7 (results-16k.md §6)
OLD = {"roll_entry": (36_323, 43_203), "roll_fixed": (12_246_838 - 256 * 36_323, 11_934_843 - 192 * 43_203),
       "prep": (5_856_602, 7_274_714), "op1": (4_002_873, 4_928_464), "op7m4": (4_468_572, 5_419_746)}
# Amsterdam, Task 7b at 644 words (gas-amsterdam-r80.txt): fit per entry / fixed, full-tx overhead at ROLL_MAX 80,
# relayed prepare half full tx (regular / state)
AMS = {"roll_entry": 51_003, "roll_word": 12_100, "roll_fixed0": 8_276_219 - 644 * 12_100,
       "prep_reg": 4_024_867, "prep_state": 31_824_000, "blob_state": 1_530}
PRECOMPILE = {"tx": 5_409_000, "txm4": 4_121_000}     # today's PQZL rows (pq-zero-knowledge.md), n = 2048


def lerp(pair, w):
    a, b = pair
    return a + (b - a) * (w - 516) / (644 - 516)


def stmt(n):
    pk = 8 * n
    ct = pk + V

    def multi(m, a):
        return HDR + (1 + m + a) * pk + ct + pk + (m + 1 + a * m) * V
    return {"reg": 96 + pk, "tx": HDR + 3 * pk + ct + pk + 3 * V, "tx0": HDR + 2 * pk + ct + pk + 2 * V,
            "burn": HDR + pk + 2 * ct, "ds": 9 * 32 + 2 * pk + V, "dr": 9 * 32 + 2 * pk + V,
            "txm2": multi(2, 1), "txm20": multi(2, 0), "txm4": multi(4, 1), "txm40": multi(4, 0)}


def proofs(path, pat):
    if not os.path.exists(path):
        return None
    got = {m.group(1): int(m.group(2)) for m in re.finditer(pat, open(path).read())}
    return got if all(f in got for f in FORMS) else None


def roll_max(entry, fixed, over=0):
    r = int((CAP - over - fixed) // entry)
    return r - r % 16


def main():
    cells = json.load(open(os.path.join(HERE, "cells.json")))
    ref = proofs(os.path.join(HERE, "..", "p16k", "estimator-e-s1-16k.txt"),
                 r"=> /tmp/w/(\w+)_params\.sage: .*codegen proof size ~(\d+) B")
    cands = [("16k (approved)", 2560, 16384, 2**50 - 42_310_535, ref)]
    for c in cells:
        if c["variant"] != "q3":
            continue
        p = proofs(os.path.join(HERE, f"e-s1-n{c['n']}k{c['K']}.txt"), r"/p/specs/[^/]+/(\w+)_params\.sage: kmlwe_min .*proof (\d+) B")
        if p:
            cands.append((f"n{c['n']} K{c['K']}", c["n"], c["K"], c["q"], p))
    base = None
    print("| candidate | n | K_MAX | log2 q | pk / u B | ct B | acc words | stmt R_TX / R_TX0 / R_BURN / R_REG / disclosure |"
          " stmt op 7 M = 4 aud / off | op 1 blob | op 7 M = 4 blob | proofs reg / tx / tx0 / burn / ds / dr / txm2 / txm20 /"
          " txm4 / txm40 B | max proof | max input (form) | relayed op 1 / op 7 M = 4 calldata, EIP-7976 floor |")
    print("|" + "---|" * 15)
    rows = []
    for lab, n, K, q, p in cands:
        pk, ct, w = 8 * n, 8 * n + V, (8 * n + V) // 32
        s = stmt(n)
        inp = {f: 5 + s[f] + p[f] for f in FORMS}
        fmax = max(inp, key=inp.get)
        op1_blob = 16 + ct + V + 32 + V
        op7_blob = 16 + pk + 4 * 2 * V + 32 * 4 + V
        # relayed calldata = proof + PK + the rest of the mtxExecute payload (Task 7b's 16k rows: op 1 78,020 with a
        # 52,624-byte proof, op 7 M = 4 83,524 with 57,202)
        cd1, cd7 = p["tx"] + pk + (78_020 - 52_624 - 20_480), p["txm4"] + pk + (83_524 - 57_202 - 20_480)
        fl = lambda b: 15_000 + 64 * b
        r = dict(lab=lab, n=n, K=K, pk=pk, ct=ct, w=w, s=s, p=p, inp=inp, fmax=fmax, op1_blob=op1_blob,
                 op7_blob=op7_blob, cd1=cd1, cd7=cd7)
        rows.append(r)
        print(f"| {lab} | {n} | {K:,} | {math.log2(q):.3f} | {pk:,} | {ct:,} | {w} | {s['tx']:,} / {s['tx0']:,} / "
              f"{s['burn']:,} / {s['reg']:,} / {s['ds']:,} | {s['txm4']:,} / {s['txm40']:,} | {op1_blob:,} | {op7_blob:,} | "
              f"{' / '.join(f'{p[f]:,}' for f in FORMS)} | {max(p[f] for f in FORMS):,} ({max(p[f] for f in FORMS) / MAX_PROOF:.0%} of MAX_PROOF) | "
              f"{inp[fmax]:,} ({fmax}; {'≤' if inp[fmax] <= MAX_INPUT else '>'} MAX_INPUT {MAX_INPUT:,}) | {cd1:,} / {cd7:,}, "
              f"{fl(cd1):,} / {fl(cd7):,} |")
    base = rows[0]
    print("\nChange against the approved 16k set (negative = smaller):")
    print("| candidate | pk / ct / acc words | R_TX stmt | op 7 M = 4 stmt | R_TX proof | txm4 proof | max input | op 1 blob |")
    print("|---|---|---|---|---|---|---|---|")
    pct = lambda a, b: f"{(a / b - 1) * 100:+.1f} %"
    for r in rows[1:]:
        print(f"| {r['lab']} | {pct(r['ct'], base['ct'])} | {pct(r['s']['tx'], base['s']['tx'])} | "
              f"{pct(r['s']['txm4'], base['s']['txm4'])} | {pct(r['p']['tx'], base['p']['tx'])} | "
              f"{pct(r['p']['txm4'], base['p']['txm4'])} | {pct(r['inp'][r['fmax']], base['inp'][base['fmax']])} | "
              f"{pct(r['op1_blob'], base['op1_blob'])} |")
    print("\nGas [estimate] (old rules: linear in acc words between Task 7's measured 516 / 644; Amsterdam: scaled from Task "
          "7b's 644-word point)")
    print("| candidate | acc words | old: ROLL_MAX (full relayed tx) | old: prepare half full tx | old: op 1 / op 7 M = 4 "
          "execution | precompile op 1 / op 7 M = 4 | Amsterdam: ROLL_MAX (regular gas) | Amsterdam: prepare half regular / "
          "state | Amsterdam: op 1 blob state gas | rollovers to fill acc (K_MAX: old / Amsterdam) |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    for n in sorted({r["n"] for r in rows} | {2048, 2176, 2304, 2432, 2560}):
        w = (8 * n + V) // 32
        e, f = lerp(OLD["roll_entry"], w), lerp(OLD["roll_fixed"], w)
        rm = roll_max(e, f)
        ae = AMS["roll_entry"] - (OLD["roll_entry"][1] - OLD["roll_entry"][0]) / 128 * (644 - w)
        af = AMS["roll_fixed0"] + AMS["roll_word"] * w
        arm = roll_max(ae, af)
        print(f"| n = {n} | {w} | {rm} ({f + rm * e:,.0f}; {e:,.0f} / entry + {f:,.0f}) | {lerp(OLD['prep'], w):,.0f} | "
              f"{lerp(OLD['op1'], w):,.0f} / {lerp(OLD['op7m4'], w):,.0f} | {PRECOMPILE['tx'] * n / 2048:,.0f} / "
              f"{PRECOMPILE['txm4'] * n / 2048:,.0f} | {arm} ({af + arm * ae:,.0f}; {ae:,.0f} / entry + "
              f"{af:,.0f}) | {AMS['prep_reg'] * w / 644:,.0f} / {AMS['prep_state'] * w / 644:,.0f} | "
              f"{AMS['blob_state'] * (8 * n + 432):,} | {', '.join(f'{K}: {math.ceil((K - 1) / rm)} / {math.ceil((K - 1) / arm)}' for K in (1024, 4096, 8192, 16384))} |")


if __name__ == "__main__":
    # self-checks: the layout reproduces pqz-stmt's today lengths and Task 7's 16k lengths; the old-rules model
    # reproduces Task 7's ROLL_MAX 192 at 644 words and today's 256 at 516
    t, s16 = stmt(2048), stmt(2560)
    assert (t["tx"], t["tx0"], t["burn"], t["reg"], t["ds"]) == (83_072, 66_560, 50_048, 16_480, 33_184)
    assert (s16["tx"], s16["txm4"], s16["burn"], s16["ds"]) == (103_552, 165_760, 62_336, 41_376)
    assert roll_max(lerp(OLD["roll_entry"], 644), lerp(OLD["roll_fixed"], 644)) == 192
    assert roll_max(lerp(OLD["roll_entry"], 516), lerp(OLD["roll_fixed"], 516)) == 256
    assert roll_max(AMS["roll_entry"], AMS["roll_fixed0"] + 644 * AMS["roll_word"]) == 80
    main()
