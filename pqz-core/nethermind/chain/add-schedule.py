#!/usr/bin/env python3
"""P6-ANON S8: add-schedule.py <chainspec.json> <calib-engine-pqz.json> <timestamp> <out.json> [--ops 7]

Path A on a chain that already has engine.Pqz (RUNBOOK "Two activation paths"): writes <out> = <chainspec> with one more
schedule at <timestamp> (decimal or 0x hex, after the last one): a copy of the last schedule whose rows of the given ops
(default 7) are taken from the calibration output <calib-engine-pqz.json> (its first schedule), every other row and
price unchanged. The timestamp must lie at least 5 minutes in the future (wall clock): a schedule that starts at a block
already made would re-price history and split a re-synced node from the chain. Refuses an earlier timestamp, a
chainspec without engine.Pqz, or any other difference. Prints the new rows. Run with python3 -I."""
import copy
import json
import sys
import time


def main(src, cal, ts, out, *flags):
    ops = {int(x) for x in flags[flags.index("--ops") + 1].split(",")} if "--ops" in flags else {7}
    g = json.load(open(src))
    sch = g.get("engine", {}).get("Pqz", {}).get("schedules")
    if not sch:
        sys.exit("no engine.Pqz in the chainspec (a first activation is patch-chainspec.py's)")
    t = int(ts, 0)
    if t < time.time() + 300:
        sys.exit(f"timestamp {t} is not at least 5 minutes in the future (now {int(time.time())})")
    if t <= int(str(sch[-1]["timestamp"]), 0):
        sys.exit(f"timestamp {t} is not after the last schedule's {sch[-1]['timestamp']}")
    new_rows = [r for r in json.load(open(cal))["schedules"][0]["pqz"] if r["op"] in ops]
    if not new_rows:
        sys.exit(f"no rows of ops {sorted(ops)} in {cal}")
    s = copy.deepcopy(sch[-1])
    s["timestamp"] = hex(t)
    s["pqz"] = [r for r in s["pqz"] if r["op"] not in ops] + new_rows
    g2 = copy.deepcopy(g)
    g2["engine"]["Pqz"]["schedules"].append(s)
    rest = lambda x: {k: v for k, v in x.items() if k != "engine"} | {"engine": {k: v for k, v in x["engine"].items() if k != "Pqz"}}
    if rest(g2) != rest(g) or g2["engine"]["Pqz"]["schedules"][:-1] != sch:
        sys.exit("unexpected diff")
    json.dump(g2, open(out, "w"), indent=1)
    print(f"{out}: schedule {len(sch)} added at {t} = {hex(t)}: {len(s['pqz'])} rows ({len(new_rows)} new of ops {sorted(ops)}), "
          f"selftest {s['selftestGas']}, mldsa44 {s['mldsa44Gas']}, mldsa65 {s['mldsa65Gas']}")
    for r in new_rows:
        shape = f" M {r.get('legs')} auditorOn {r.get('auditorOn')}" if r["op"] == 7 else ""
        print(f"  op {r['op']} id {r['id'][:10]}… stmtLen {r['stmtLen']}{shape} gas {r['gas']:,}")


if __name__ == "__main__":
    main(*sys.argv[1:])
