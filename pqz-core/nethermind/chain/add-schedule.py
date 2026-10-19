#!/usr/bin/env python3
"""P6-ANON S8: add-schedule.py <chainspec.json> <calib-engine-pqz.json> <timestamp> <out.json> [--ops 7] [--id pqzl] [--selftest]

Path A on a chain that already has engine.Pqz (RUNBOOK "Two activation paths"): writes <out> = <chainspec> with one more
schedule at <timestamp> (decimal or 0x hex, after the last one): a copy of the last schedule whose rows of the given ops
(default 7) are taken from the calibration output <calib-engine-pqz.json> (its first schedule), every other row and
price unchanged. The timestamp must lie at least 5 minutes in the future (wall clock): a schedule that starts at a block
already made would re-price history and split a re-synced node from the chain. Refuses an earlier timestamp, a
chainspec without engine.Pqz, or any other difference. Prints the new rows (with the old price and the change when the
last schedule had the row). --id (Rust PQZL roll-out, 2026-10-19) also limits the replaced rows to one proof system:
pqzl, pqzh or a hex prefix of the proofSystemId; --selftest also takes selftestGas from the calibration file (every
other price stays). Refuses a calibration file with other than one schedule, one that lacks a row of the replaced ops
/ id that the last schedule has (that shape would become a miss), and a duplicate row (review W-F, 2026-10-19).
add-schedule.py --check runs the self-check. Run with python3 -I."""
import copy
import json
import os
import sys
import tempfile
import time

IDS = {"pqzl": "0x8079d65b5e5c15e330f7e65c875776dfc1b0f6c93ced90c045e83865d116baef",
       "pqzh": "0x0a47a7689250ba178a52ad5972cdd9153358c022cb694c08d2389e82de2fead4"}
KEY = lambda r: (r["op"], r["id"].lower(), r["stmtLen"], r.get("legs"), r.get("auditorOn"))


def main(src, cal, ts, out, *flags):
    ops = {int(x) for x in flags[flags.index("--ops") + 1].split(",")} if "--ops" in flags else {7}
    idp = flags[flags.index("--id") + 1].lower() if "--id" in flags else "0x"
    idp = IDS.get(idp, idp)
    if not idp.startswith("0x"):
        sys.exit(f"--id {idp}: pqzl, pqzh or a 0x prefix")
    pick = lambda r: r["op"] in ops and r["id"].lower().startswith(idp)
    g = json.load(open(src))
    sch = g.get("engine", {}).get("Pqz", {}).get("schedules")
    if not sch:
        sys.exit("no engine.Pqz in the chainspec (a first activation is patch-chainspec.py's)")
    t = int(ts, 0)
    if t < time.time() + 300:
        sys.exit(f"timestamp {t} is not at least 5 minutes in the future (now {int(time.time())})")
    if t <= int(str(sch[-1]["timestamp"]), 0):
        sys.exit(f"timestamp {t} is not after the last schedule's {sch[-1]['timestamp']}")
    css = json.load(open(cal))["schedules"]
    if len(css) != 1:
        sys.exit(f"{cal} has {len(css)} schedules, not 1 (a calibration output)")
    cs = css[0]
    new_rows = [r for r in cs["pqz"] if pick(r)]
    if not new_rows:
        sys.exit(f"no rows of ops {sorted(ops)} id {idp} in {cal}")
    s = copy.deepcopy(sch[-1])
    s["timestamp"] = hex(t)
    old = {KEY(r): r["gas"] for r in s["pqz"]}
    # review W-F (2026-10-19): a replaced row with no new row would be a miss from T on (…00 for every honest proof of
    # that shape), a duplicate key makes every node refuse to start; both are refused here
    dropped = {KEY(r) for r in s["pqz"] if pick(r)} - {KEY(r) for r in new_rows}
    if dropped:
        sys.exit(f"{cal} lacks {len(dropped)} row(s) the last schedule has: {sorted(dropped, key=str)}")
    s["pqz"] = [r for r in s["pqz"] if not pick(r)] + new_rows
    keys = [KEY(r) for r in s["pqz"]]
    if len(set(keys)) != len(keys):
        sys.exit(f"duplicate rows: {sorted({k for k in keys if keys.count(k) > 1}, key=str)}")
    if "--selftest" in flags:
        s["selftestGas"] = cs["selftestGas"]
    g2 = copy.deepcopy(g)
    g2["engine"]["Pqz"]["schedules"].append(s)
    rest = lambda x: {k: v for k, v in x.items() if k != "engine"} | {"engine": {k: v for k, v in x["engine"].items() if k != "Pqz"}}
    if rest(g2) != rest(g) or g2["engine"]["Pqz"]["schedules"][:-1] != sch:
        sys.exit("unexpected diff")
    json.dump(g2, open(out, "w"), indent=1)
    print(f"{out}: schedule {len(sch)} added at {t} = {hex(t)}: {len(s['pqz'])} rows ({len(new_rows)} new of ops {sorted(ops)}"
          f"{'' if idp == '0x' else f' id {idp[:10]}…'}), "
          f"selftest {s['selftestGas']}, mldsa44 {s['mldsa44Gas']}, mldsa65 {s['mldsa65Gas']}")
    for r in new_rows:
        shape = f" M {r.get('legs')} auditorOn {r.get('auditorOn')}" if r["op"] == 7 else ""
        was = old.get(KEY(r))
        delta = f" (was {was:,}, {100 * (r['gas'] - was) / was:+.1f} %)" if was else ""
        print(f"  op {r['op']} id {r['id'][:10]}… stmtLen {r['stmtLen']}{shape} gas {r['gas']:,}{delta}")
    return g2


def check():
    """--check: a chainspec with one PQZL and one PQZH row; --id pqzl replaces only the PQZL row."""
    row = lambda i, gas: {"op": 1, "id": IDS[i], "stmtLen": 83072, "gas": gas}
    sched = {"timestamp": "0x0", "pqz": [row("pqzl", 5), row("pqzh", 4)], "selftestGas": 4, "mldsa44Gas": 1, "mldsa65Gas": 2}
    with tempfile.TemporaryDirectory() as d:
        src, cal, out = (os.path.join(d, f) for f in ("g.json", "c.json", "o.json"))
        json.dump({"params": {}, "engine": {"Pqz": {"schedules": [sched]}}}, open(src, "w"))
        json.dump({"schedules": [dict(sched, pqz=[row("pqzl", 3), row("pqzh", 9)], selftestGas=3)]}, open(cal, "w"))
        g = main(src, cal, str(int(time.time()) + 900), out, "--ops", "1", "--id", "pqzl")
        assert [r["gas"] for r in g["engine"]["Pqz"]["schedules"][1]["pqz"]] == [4, 3], g
        g = main(src, cal, str(int(time.time()) + 900), out, "--ops", "1")
        assert sorted(r["gas"] for r in g["engine"]["Pqz"]["schedules"][1]["pqz"]) == [3, 9], g
        assert g["engine"]["Pqz"]["schedules"][1]["selftestGas"] == 4, g
        g = main(src, cal, str(int(time.time()) + 900), out, "--ops", "1", "--id", "pqzl", "--selftest")
        assert g["engine"]["Pqz"]["schedules"][1]["selftestGas"] == 3, g
        for bad in (["--id", "pqzq"], ["--ops", "2"]):
            try:
                main(src, cal, str(int(time.time()) + 900), out, *bad)
                raise AssertionError(bad)
            except SystemExit as e:
                assert e.code, bad
        # review W-F: a calibration file that lacks a replaced row, has a duplicate row or more than one schedule
        for name, cal_s in (("dropped", [dict(sched, pqz=[row("pqzh", 9)])]),
                            ("duplicate", [dict(sched, pqz=[row("pqzl", 3), row("pqzl", 7), row("pqzh", 9)])]),
                            ("two schedules", [sched, dict(sched, timestamp="0x1")])):
            json.dump({"schedules": cal_s}, open(cal, "w"))
            try:
                main(src, cal, str(int(time.time()) + 900), out, "--ops", "1")
                raise AssertionError(name)
            except SystemExit as e:
                assert isinstance(e.code, str) and e.code, name
                print(f"  refused ({name}): {e.code}")
        # a new shape (no row in the last schedule) is no drop: the op 7 roll-out of 2026-10-17 added its rows so
        json.dump({"schedules": [dict(sched, pqz=[row("pqzl", 3), row("pqzh", 9), dict(row("pqzl", 8), op=2)])]}, open(cal, "w"))
        g = main(src, cal, str(int(time.time()) + 900), out, "--ops", "1,2")
        assert sorted(r["gas"] for r in g["engine"]["Pqz"]["schedules"][1]["pqz"]) == [3, 8, 9], g
    print("add-schedule --check: ok")


if __name__ == "__main__":
    check() if sys.argv[1:] == ["--check"] else main(*sys.argv[1:])
