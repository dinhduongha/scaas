#!/usr/bin/env python3
"""Rust PQZL roll-out (2026-10-19), the controller's rule for the live PQZL rows (owner may override):
  python3 -I runs/2026-10-19-pqzl-rows.py <live engine-pqz.json> <run 1 engine json> <run 2 engine json> <out.json>
Per PQZL row: new = min(live, max(run 1, run 2)). The max of two noisy runs is an upper estimate of the true cost,
and never above live, because D6 measured the Rust core faster than the C core on every PQZL row (a row whose max
exceeds live keeps live). Same rule for selftestGas (PQZL-led: the smallest row). <out> is a calibration-shaped file
(one schedule) for chain/add-schedule.py ... --ops 1,2,3,4,5,7 --id pqzl --selftest: its PQZL rows and selftestGas
are the result; its PQZH rows and ML-DSA prices are the live ones (add-schedule takes only the PQZL rows)."""
import json
import sys

PQZL = "0x2e07e6ed1fd303a08c89b3eab6e8423fdfb8f31202958dd682a0619313798c2f"
K = lambda r: (r["op"], r["id"].lower(), r["stmtLen"], r.get("legs"), r.get("auditorOn"))


def rule(live, a, b):
    return min(live, max(a, b))


def main(live_p, r1_p, r2_p, out_p):
    live = json.load(open(live_p))["schedules"][-1]
    r1, r2 = (json.load(open(p))["schedules"][0] for p in (r1_p, r2_p))
    g1, g2 = ({K(r): r["gas"] for r in s["pqz"]} for s in (r1, r2))
    rows = []
    for r in live["pqz"]:
        r = dict(r)
        if r["id"].lower() == PQZL:
            r["gas"] = rule(r["gas"], g1[K(r)], g2[K(r)])
        rows.append(r)
    st = rule(live["selftestGas"], r1["selftestGas"], r2["selftestGas"])
    out = {"schedules": [dict(live, timestamp="0x0", pqz=rows, selftestGas=st)]}
    json.dump(out, open(out_p, "w"), indent=2)
    changed = [(r, o) for r, o in zip(rows, live["pqz"]) if r["gas"] != o["gas"]]
    print(f"{out_p}: {len(changed)} PQZL rows changed, selftestGas {live['selftestGas']:,} -> {st:,}")
    for r, o in changed:
        shape = f" [{r['legs']}, {r['auditorOn']}]" if r["op"] == 7 else ""
        print(f"  op {r['op']} stmtLen {r['stmtLen']}{shape}: {o['gas']:,} -> {r['gas']:,} ({100 * (r['gas'] - o['gas']) / o['gas']:+.1f} %)")


if __name__ == "__main__":
    assert rule(5409000, 3454000, 3225000) == 3454000 and rule(3710000, 4735000, 4696000) == 3710000
    main(*sys.argv[1:])
