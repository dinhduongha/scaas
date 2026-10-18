#!/usr/bin/env python3
"""Rust PQZL roll-out (2026-10-19): compare calibrations' rows with the live chain's last schedule, row by row.
  python3 -I runs/2026-10-19-calib-compare.py chain/engine-pqz.json runs/<date>-calib-<ops>-engine-pqz.json [...]
Prints markdown tables (PQZL and PQZH separately, then selftestGas and the ML-DSA prices), one column pair per run."""
import json
import sys

live = json.load(open(sys.argv[1]))["schedules"][-1]
news = [json.load(open(p))["schedules"][0] for p in sys.argv[2:]]
N = {"0x2e07e6ed1fd303a08c89b3eab6e8423fdfb8f31202958dd682a0619313798c2f": "PQZL",
     "0x0a47a7689250ba178a52ad5972cdd9153358c022cb694c08d2389e82de2fead4": "PQZH"}
K = lambda r: (r["op"], r["id"], r["stmtLen"], r.get("legs"), r.get("auditorOn"))
nrs = [{K(r): r["gas"] for r in n["pqz"]} for n in news]
pct = lambda a, b: f"{100 * (b - a) / a:+.1f} %"
order = lambda r: (r["op"], -r["stmtLen"], -(r.get("legs") or 0), -(r.get("auditorOn") or 0))
cols = "".join(f" run {i + 1} | change |" for i in range(len(news)))
sep = "|---|---|---|" + "---|---|" * len(news)
for name in ("PQZL", "PQZH"):
    print(f"\n| op | {name} stmtLen [M, auditorOn] | live (last schedule) |{cols}\n{sep}")
    for r in sorted((r for r in live["pqz"] if N[r["id"]] == name), key=order):
        shape = f" [{r['legs']}, {r['auditorOn']}]" if r["op"] == 7 else ""
        print(f"| {r['op']} | {r['stmtLen']}{shape} | {r['gas']:,} |" + "".join(
            f" {nr[K(r)]:,} | {pct(r['gas'], nr[K(r)])} |" for nr in nrs))
print(f"\n| price | live |{cols}\n{sep[4:]}")
for k in ("selftestGas", "mldsa44Gas", "mldsa65Gas"):
    print(f"| {k} | {live[k]:,} |" + "".join(f" {n[k]:,} | {pct(live[k], n[k])} |" for n in news))
