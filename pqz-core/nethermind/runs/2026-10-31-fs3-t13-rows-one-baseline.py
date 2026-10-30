#!/usr/bin/env python3
"""fs3 Task 13 option (b), owner ruling 2026-10-31: every row priced from its logged t_row with ONE ecMul baseline.
  python3 -I runs/2026-10-31-fs3-t13-rows-one-baseline.py <live> <run 1 logs> <run 2 logs> <out.json> <table.md>
Each run argument is a comma list of a run's slice logs (runs/fs3-t13-calib/run<r>-k<a-b>.txt); the slice's engine json
is the same path with .json. Why: Calibrate prices a row with the t_ecMul median of its own process, and that median is
bimodal across processes (0.016 or 0.025 ms) while t_row varies <= 6 %, so slices that drew 0.025 ms priced their rows
about 35 % low. Here gas = 1000 * ceil(6000 * t_row / T_EC / 1000) (Calibrate's formula and rounding) with
T_EC = 0.016 ms, the fast mode (2026-10-15 / 17 / 19 calibrations: medians logged 0.017 ms = 0.355-0.359 M gas per ms;
2026-10-31 fast slices and the discarded run 1: 0.016 ms = 0.366-0.368 M gas per ms). t_row is the log's 3-decimal
value (<= 0.0005 ms off, at most one 1,000 step). selftestGas = the smallest re-priced row of the run (as Calibrate).
Then the rule of runs/2026-10-30-fs3-t13-rows.py (imported, kept unchanged as record): new = min(live, max(run 1, run 2)),
FAIL unless live and both runs have the same keys (never on 0 matches), FAIL on t_row > 60 ms, WARN rows printed.
mldsa44Gas / mldsa65Gas stay live (as in the rule; their calibrated value depends on the baseline too). The table compares
each row's per-slice-baseline price (Calibrate's json) with the single-baseline price."""
import importlib.util
import json
import math
import os
import re
import sys

_s = importlib.util.spec_from_file_location("rows", os.path.join(os.path.dirname(os.path.abspath(__file__)), "2026-10-30-fs3-t13-rows.py"))
R = importlib.util.module_from_spec(_s)
_s.loader.exec_module(R)
T_EC = 0.016


def gas(t_row, t_ec=T_EC):
    return 1000 * math.ceil(6000 * t_row / t_ec / 1000)


def run(arg):
    """{key: (per-slice gas, single-baseline gas, t_row, slice t_ecMul)}, selftestGas of the single baseline"""
    out = {}
    for log in arg.split(","):
        rows = json.load(open(log[:-4] + ".json"))["schedules"][0]["pqz"]
        t = R.t_rows(log)
        ec = re.search(r"^t_ecMul median ([0-9.]+) ms", open(log).read(), re.M).group(1)
        if len(t) != len(rows):
            sys.exit(f"FAIL {log}: {len(t)} table rows, {len(rows)} json rows")
        for r, (name, tr) in zip(rows, t):
            if not name.startswith(f"op {r['op']} ") or f" {r['stmtLen']}" not in name:
                sys.exit(f"FAIL {log}: table row {name} != json row op {r['op']} stmtLen {r['stmtLen']}")
            if tr > R.LIMIT_MS:
                sys.exit(f"FAIL {log}: {name} t_row {tr:.3f} ms > {R.LIMIT_MS:.0f} ms")
            if R.K(r) in out:
                sys.exit(f"FAIL {log}: {name} measured twice")
            out[R.K(r)] = (r["gas"], gas(tr), tr, ec)
    return out, min(v[1] for v in out.values())


def main(live_p, l1, l2, out_p, md_p):
    lj = json.load(open(live_p))
    live = (lj["engine"]["Pqz"] if "engine" in lj else lj)["schedules"][-1]
    lk = {R.K(r) for r in live["pqz"]}
    (a, st1), (b, st2) = run(l1), run(l2)
    for name, g in (("run 1", a), ("run 2", b)):
        if not g or set(g) != lk:
            sys.exit(f"FAIL keys: live {len(lk)} rows, {name} {len(g)}; only live {sorted(lk - set(g))}, only {name} {sorted(set(g) - lk)}")
    rows, warn, md = [], [], ["| row | live | t_row run 1 / run 2 ms | slice t_ecMul run 1 / run 2 ms | per-slice baseline: run 1 / run 2 → rule | one baseline 0.016 ms: run 1 / run 2 → rule | change |",
                              "|---|---|---|---|---|---|---|"]
    for r in live["pqz"]:
        k, r = R.K(r), dict(r)
        name = f"op {r['op']} {'pqzl' if r['id'].startswith('0xef1f') else 'pqzh'} {r['stmtLen']}{R.shape(r)}"
        hi = max(a[k][1], b[k][1])
        if hi > r["gas"]:
            warn.append(f"  WARN {name}: max(run 1, run 2) {hi:,} > live {r['gas']:,} (kept at live)")
        old = R.rule(r["gas"], a[k][0], b[k][0])
        new = R.rule(r["gas"], a[k][1], b[k][1])
        md.append(f"| {name} | {r['gas']:,} | {a[k][2]:.3f} / {b[k][2]:.3f} | {a[k][3]} / {b[k][3]} | {a[k][0]:,} / {b[k][0]:,} → {old:,} | "
                  f"{a[k][1]:,} / {b[k][1]:,} → **{new:,}** | {100 * (new - old) / old:+.1f} % |")
        r["gas"] = new
        rows.append(r)
    st = R.rule(live["selftestGas"], st1, st2)
    st0 = R.rule(live["selftestGas"], min(v[0] for v in a.values()), min(v[0] for v in b.values()))
    json.dump({"schedules": [dict(live, timestamp="0x0", pqz=rows, selftestGas=st)]}, open(out_p, "w"), indent=2)
    md.append(f"| selftestGas (smallest row) | {live['selftestGas']:,} | | | → {st0:,} | {st1:,} / {st2:,} → **{st:,}** | {100 * (st - st0) / st0:+.1f} % |")
    open(md_p, "w").write("\n".join(md) + "\n")
    print(f"{out_p}: {len(rows)} rows matched, T_EC {T_EC} ms, selftestGas {live['selftestGas']:,} -> {st:,}; table {md_p}")
    print("\n".join(warn) if warn else "no row measured above live")


if __name__ == "__main__":
    assert gas(8.605) == 3227000 and gas(8.605, 0.0246) == 2099000 and gas(0.016) == 6000
    main(*sys.argv[1:])
