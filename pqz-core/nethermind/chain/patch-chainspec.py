#!/usr/bin/env python3
"""P6f: patch-chainspec.py <genesis.json> <engine-pqz.json> <timestamp> <out.json>

Writes <out> = <genesis> with engine.Pqz = <engine-pqz.json> whose first schedule's timestamp is <timestamp>
(decimal or 0x hex; later schedules keep theirs and must be later). Refuses if engine.Pqz is already there or a
precompile address has an allocation. Prints the diff: exactly one added key, engine.Pqz. Run with python3 -I."""
import difflib
import json
import sys

ADDR = ["5caa500000000000000000000000000000000f01", "5caa500000000000000000000000000000000012",
        "5caa500000000000000000000000000000000013"]


def main(src, eng, ts, out):
    g = json.load(open(src))
    e = json.load(open(eng))
    if "Pqz" in g.get("engine", {}):
        sys.exit("engine.Pqz already present")
    alloc = {k.lower().removeprefix("0x") for k in g.get("accounts", {})}
    if alloc & set(ADDR):
        sys.exit("a precompile address has an allocation")
    t = int(ts, 0)
    e["schedules"][0]["timestamp"] = hex(t)
    if any(int(str(s["timestamp"]), 0) <= t for s in e["schedules"][1:]):
        sys.exit("later schedules must be after the first")
    g2 = json.loads(json.dumps(g))
    g2["engine"]["Pqz"] = e
    a, b = json.dumps(g, indent=1, sort_keys=True).splitlines(), json.dumps(g2, indent=1, sort_keys=True).splitlines()
    d = [l for l in difflib.unified_diff(a, b, "genesis", "patched", lineterm="", n=0)]
    removed = [l for l in d if l.startswith("-") and not l.startswith("---")]
    if removed or set(g2) != set(g) or set(g2["engine"]) - set(g["engine"]) != {"Pqz"}:
        sys.exit("unexpected diff")
    json.dump(g2, open(out, "w"), indent=1)
    print(f"{out}: engine.Pqz added (first timestamp {t} = {hex(t)}, {len(e['schedules'])} schedule(s), "
          f"{len(e['schedules'][0]['pqz'])} rows); diff: {len([l for l in d if l.startswith('+') and not l.startswith('+++')])} added lines, 0 removed")


if __name__ == "__main__":
    main(*sys.argv[1:5])
