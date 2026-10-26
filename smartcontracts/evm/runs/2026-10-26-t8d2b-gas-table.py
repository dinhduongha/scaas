#!/usr/bin/env python3
"""t8d2b: the GAS lines of runs/2026-10-26-t8d2b-gas-<set>.txt (PqzStatePinGasTest.test_gasTable_*) as markdown.
  python3 -I runs/2026-10-26-t8d2b-gas-table.py rows     every row: calldata, standard / EIP-7976 floor, precompile,
                                                          execution, regular (forge), state, fits 2^24
  python3 -I runs/2026-10-26-t8d2b-gas-table.py pqzh     PQZH rows with both calldata-floor regimes (EIP-7976 15,000 + 64 /
                                                          byte; EIP-7623 alone 21,000 + 40 / non-zero + 10 / zero byte)
  python3 -I runs/2026-10-26-t8d2b-gas-table.py sets     regular / state per row, one column per set (README)"""
import os, re, sys
H = os.path.dirname(os.path.abspath(__file__))
SETS = ["n2048-kmax1024", "n2304-kmax4096", "n2560-kmax16384", "n2816-kmax65536"]
CAP = 1 << 24
m = lambda g: f"{g / 1e6:.2f}"  # noqa: E731


def rows():
    for s in SETS:
        t = open(os.path.join(H, f"2026-10-26-t8d2b-gas-{s}.txt")).read().split("\n")
        for i, l in enumerate(t):
            a = re.search(r"GAS (\S+) (\S+) \| (.*) \| calldata (\d+) \(zero (\d+)\) \| std (\d+) \| floor (\d+)", l)
            if a:
                b = re.search(r"pqz (\d+) \| exec (\d+) \| regular (\d+) \(model (\d+)\) \| state (\d+)", t[i + 1])
                n, z, std, fl = map(int, a.group(4, 5, 6, 7))
                pq, ex, reg, mod, st = map(int, b.groups())
                yield dict(set=s, sys=a.group(2), row=a.group(3), n=n, z=z, std=std, fl=fl, pq=pq, ex=ex, reg=reg, st=st,
                           f23=21_000 + 40 * (n - z) + 10 * z)


mode = sys.argv[1] if len(sys.argv) > 1 else "rows"
R = list(rows())
if mode == "rows":
    print("| set | system | row | calldata B | standard / floor | precompile | execution | regular | state | ≤ 2^24 |")
    print("|---|---|---|---|---|---|---|---|---|---|")
    for r in R:
        print(f"| {r['set']} | {r['sys']} | {r['row']} | {r['n']:,} | {m(r['std'])} / {m(r['fl'])} | {m(r['pq'])} | {m(r['ex'])} | "
              f"{m(r['reg'])} | {m(r['st'])} | {'yes' if r['reg'] <= CAP else '**no**'} |")
elif mode == "pqzh":
    for s in SETS[:3]:
        print(f"\n`{s}`\n")
        print("| PQZH form | calldata B | standard | precompile | execution | EIP-7976 floor | regular (forge) | fits 2^24 | EIP-7623-only floor | fits by that floor |")
        print("|---|---|---|---|---|---|---|---|---|---|")
        for r in R:
            if r["set"] == s and r["sys"] == "pqzh" and "verifyPop" not in r["row"]:
                print(f"| {r['row']} | {r['n']:,} | {m(r['std'])} | {m(r['pq'])} | {m(r['ex'])} | {m(r['fl'])} | {m(r['reg'])} | "
                      f"{'yes' if r['reg'] <= CAP else '**no**'} | {m(r['f23'])} | {'yes' if r['f23'] <= CAP else '**no**'} |")
elif mode == "sets":
    names = []
    for r in R:
        if (r["sys"], r["row"]) not in names:
            names.append((r["sys"], r["row"]))
    print("| system | row | " + " | ".join(f"`{s}`" for s in SETS) + " |")
    print("|---|---|" + "---|" * len(SETS))
    for sy, row in names:
        c = []
        for s in SETS:
            x = [r for r in R if r["set"] == s and r["sys"] == sy and r["row"] == row]
            c.append("—" if not x else f"{m(x[0]['reg'])}{'' if x[0]['reg'] <= CAP else ' ✗'} / {m(x[0]['st'])}")
        print(f"| {sy.upper()} | {row} | " + " | ".join(c) + " |")
