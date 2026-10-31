#!/usr/bin/env python3
"""fs3 Task 13 + plan 5h Task 9 (2026-10-30): the row rule of 2026-10-19 (runs/2026-10-19-pqzl-rows.py, kept unchanged
as record) adapted to today's ids, for the SCaaS testnet reset on path B:
  python3 -I runs/2026-10-30-fs3-t13-rows.py <live> <run 1 json> <run 2 json> <run 1 log> <run 2 log> <out.json>
Each run argument may be a comma list (the slices of one run, runs/2026-10-30-fs3-t13-calib-step.sh): rows are joined,
selftestGas = the smallest slice value (= the smallest row; a row-less slice has none), ML-DSA = the largest.
<live> = the live engine.Pqz: chain/engine-pqz-provisional-n2304.json, or the live genesis.json (its engine.Pqz is read).
Per row: new = min(live, max(run 1, run 2)); the same for selftestGas; mldsa44Gas / mldsa65Gas stay live.
Adapted: the committed script matched PQZL rows by the v2 id only, so on other ids it printed "0 PQZL rows changed" and
succeeded. Here every PQZ row of both proof systems is matched by (op, id, stmtLen, legs, auditorOn) under today's ids
(the live rows are the provisional n2304-kmax4096 rows, already at PQZL v5 / PQZH v3; every row is provisional, so the
rule covers PQZH too), and the script FAILS unless the live rows and both runs have exactly the same keys (so never on
0 matches). It also FAILS if any row's t_row (the max of p99 valid and p99 adversarial, the Calibrate log table) exceeds
the 60 ms verify limit, and prints a WARN for each row whose max(run 1, run 2) is above live (kept at live by the rule:
the measured cost is above the price). <out> is calibration-shaped (one schedule, timestamp 0x0) for
chain/patch-chainspec.py <genesis> <out> 0x0 <new genesis> --testnet-reset."""
import json
import sys

K = lambda r: (r["op"], r["id"].lower(), r["stmtLen"], r.get("legs"), r.get("auditorOn"))
LIMIT_MS = 60.0


def rule(live, a, b):
    return min(live, max(a, b))


def t_rows(log):
    """the t_row ms column (index 9) of the Calibrate table rows: | op | id | stmtLen | forms | valid n | p50 | p99 valid
    | p99 adversarial | worst set | t_row ms | gas | calldata floor |"""
    out = []
    for line in open(log):
        c = [x.strip() for x in line.split("|")[1:-1]]
        if len(c) == 12 and c[0].isdigit():
            out.append((f"op {c[0]} {c[1]} {c[2]}", float(c[9])))
    return out


def run_json(arg):
    ss = [json.load(open(p))["schedules"][0] for p in arg.split(",")]
    st = [s["selftestGas"] for s in ss if s["pqz"]]
    return {"pqz": [r for s in ss for r in s["pqz"]], "selftestGas": min(st),
            "mldsa44Gas": max(s["mldsa44Gas"] for s in ss), "mldsa65Gas": max(s["mldsa65Gas"] for s in ss)}


def main(live_p, r1_p, r2_p, l1_p, l2_p, out_p):
    lj = json.load(open(live_p))
    live = (lj["engine"]["Pqz"] if "engine" in lj else lj)["schedules"][-1]
    r1, r2 = run_json(r1_p), run_json(r2_p)
    g1, g2 = ({K(r): r["gas"] for r in s["pqz"]} for s in (r1, r2))
    for name, s in (("run 1", r1), ("run 2", r2)):
        if len({K(r) for r in s["pqz"]}) != len(s["pqz"]):
            sys.exit(f"FAIL {name}: a row measured twice")
    lk = {K(r) for r in live["pqz"]}
    for name, g in (("run 1", g1), ("run 2", g2)):
        if not g or set(g) != lk:
            sys.exit(f"FAIL keys: live {len(lk)} rows, {name} {len(g)}; only live {sorted(lk - set(g))}, only {name} {sorted(set(g) - lk)}")
    worst = 0.0
    for log in (l1_p, l2_p):
        t = [x for p in log.split(",") for x in t_rows(p)]
        if len(t) != len(lk):
            sys.exit(f"FAIL {log}: {len(t)} table rows, {len(lk)} expected")
        over = [f"{k} {v:.3f} ms" for k, v in t if v > LIMIT_MS]
        if over:
            sys.exit(f"FAIL {log}: t_row above {LIMIT_MS:.0f} ms: {'; '.join(over)}")
        worst = max([worst] + [v for _, v in t])
    rows, warn = [], []
    for r in live["pqz"]:
        r = dict(r)
        hi = max(g1[K(r)], g2[K(r)])
        if hi > r["gas"]:
            warn.append(f"  WARN op {r['op']} {r['id'][:10]} stmtLen {r['stmtLen']}{shape(r)}: max(run 1, run 2) {hi:,} > live {r['gas']:,} (kept at live)")
        r["gas"] = rule(r["gas"], g1[K(r)], g2[K(r)])
        rows.append(r)
    st = rule(live["selftestGas"], r1["selftestGas"], r2["selftestGas"])
    out = {"schedules": [dict(live, timestamp="0x0", pqz=rows, selftestGas=st)]}
    json.dump(out, open(out_p, "w"), indent=2)
    changed = [(r, o) for r, o in zip(rows, live["pqz"]) if r["gas"] != o["gas"]]
    print(f"{out_p}: {len(rows)} rows matched, {len(changed)} changed, selftestGas {live['selftestGas']:,} -> {st:,}; "
          f"max t_row {worst:.3f} ms <= {LIMIT_MS:.0f} ms in both runs")
    for r, o in changed:
        print(f"  op {r['op']} {r['id'][:10]} stmtLen {r['stmtLen']}{shape(r)}: {o['gas']:,} -> {r['gas']:,} ({100 * (r['gas'] - o['gas']) / o['gas']:+.1f} %)")
    print("\n".join(warn) if warn else "no row measured above live")


def shape(r):
    return f" [{r['legs']}, {r['auditorOn']}]" if r["op"] == 7 else ""


if __name__ == "__main__":
    assert rule(5409000, 3454000, 3225000) == 3454000 and rule(3710000, 4735000, 4696000) == 3710000
    main(*sys.argv[1:])
