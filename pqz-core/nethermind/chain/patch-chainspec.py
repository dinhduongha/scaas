#!/usr/bin/env python3
"""P6f: patch-chainspec.py <genesis.json> <engine-pqz.json> <timestamp> <out.json> [--testnet-reset]

Writes <out> = <genesis> with engine.Pqz = <engine-pqz.json> whose first schedule's timestamp is <timestamp>
(decimal or 0x hex; later schedules keep theirs and must be later). Refuses if engine.Pqz is already there or a
precompile address has an allocation. Prints the diff: exactly one added key, engine.Pqz.

--testnet-reset (path B: a fresh chain from this genesis, owner 2026-10-15) also sets three params that leave the
genesis block, hence its hash, unchanged: eip4895TransitionTimestamp 1 (withdrawals from block 1: without them a
follower rejects every block of a chain with eip4844 at 0), maximumExtraDataSize 0xffff (Clique's 97 B extraData; the
default 32 B makes a follower reject every header) and maxCodeSizeTransition 0 (the 64 KiB code size from block 0, not
from block 6432 of the old history). Run with python3 -I."""
import difflib
import json
import sys

ADDR = ["5caa500000000000000000000000000000000f01", "5caa500000000000000000000000000000000012",
        "5caa500000000000000000000000000000000013"]
RESET = {"eip4895TransitionTimestamp": 1, "maximumExtraDataSize": "0xffff", "maxCodeSizeTransition": 0}


def main(src, eng, ts, out, *flags):
    reset = "--testnet-reset" in flags
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
    if reset:
        g2["params"].update(RESET)
    a, b = json.dumps(g, indent=1, sort_keys=True).splitlines(), json.dumps(g2, indent=1, sort_keys=True).splitlines()
    d = [l for l in difflib.unified_diff(a, b, "genesis", "patched", lineterm="", n=0)]
    removed = [l for l in d if l.startswith("-") and not l.startswith("---")]
    changed = {k for k in set(g["params"]) | set(g2["params"]) if g["params"].get(k) != g2["params"].get(k)}
    if set(g2) != set(g) or set(g2["engine"]) - set(g["engine"]) != {"Pqz"} or g2["genesis"] != g["genesis"] \
            or g2["accounts"] != g["accounts"] or changed - set(RESET if reset else {}) \
            or any(not l.lstrip("-").strip().startswith(tuple(f'"{k}"' for k in RESET)) for l in removed):
        sys.exit("unexpected diff")
    json.dump(g2, open(out, "w"), indent=1)
    print(f"{out}: engine.Pqz added (first timestamp {t} = {hex(t)}, {len(e['schedules'])} schedule(s), "
          f"{len(e['schedules'][0]['pqz'])} rows); diff: {len([l for l in d if l.startswith('+') and not l.startswith('+++')])} added lines, "
          f"{len(removed)} removed; params changed: {', '.join(f'{k} {g['params'].get(k)} -> {g2['params'][k]}' for k in sorted(changed)) or 'none'}")


if __name__ == "__main__":
    main(*sys.argv[1:])
