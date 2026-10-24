#!/usr/bin/env python3
"""Provisional engine.Pqz rows for a library built with new proofSystemIds (plan 5h Task 8d part 1), for the SCaaS
testnet only, until the calibration of plan 5h Task 9 measures real prices (owner 2026-10-24: deploy 8d part 1 to the
testnet now). NOT for any other chain.

  provisional-rows.py <corpus.jsonl> <engine-pqz.json> <out.json> [factor]

Every honest input of the corpus (built for the library's set, corpus.py) gives one row key (op, id, stmtLen, legs,
auditorOn) read exactly as the plugin and e2e.py read it. Its price is the live schedule's (the last one in
engine-pqz.json) row of the same op, proof system (PQZL / PQZH), legs and auditor flag, matched by statement-length rank
within that group, times `factor` (default 1.3: the new sets' larger n and q verify slower; an over-estimate is safe on
a testnet, an under-estimate is not). A key without such a row takes the largest live price of its op and system times
`factor`. `selftestGas` is scaled the same way; the ML-DSA prices are kept. Output: one schedule at timestamp 0x0 (the
testnet reset, path B) with only the new rows — the library refuses the retired ids, so their rows would be dead."""
import json
import sys

PQZL_V3 = "8079d65b5e5c15e330f7e65c875776dfc1b0f6c93ced90c045e83865d116baef"
PQZH_V1 = "0a47a7689250ba178a52ad5972cdd9153358c022cb694c08d2389e82de2fead4"


def small_word(b):
    return b[31] if not any(b[:31]) else -1


def key(b):
    legs = aud = 0
    if b[0] == 7:
        legs, aud = small_word(b[5 + 320:5 + 352]), small_word(b[5 + 448:5 + 480])
    return b[0], b[37:69].hex(), int.from_bytes(b[1:5], "big"), legs, aud


def main(corpus, engine, out, factor="1.3"):
    f = float(factor)
    live = json.load(open(engine))["schedules"][-1]
    old = {}  # (op, system, legs, aud) -> [(stmtLen, gas)] sorted
    for r in live["pqz"]:
        sysname = {PQZL_V3: "pqzl", PQZH_V1: "pqzh"}.get(r["id"].lower().removeprefix("0x"))
        if sysname:
            old.setdefault((r["op"], sysname, r.get("legs", 0), r.get("auditorOn", 0)), []).append((r["stmtLen"], r["gas"]))
    for v in old.values():
        v.sort()
    keys = {}
    for line in open(corpus):
        c = json.loads(line)
        if c["kind"] != "honest" or c["op"] == 6:
            continue
        keys[key(bytes.fromhex(c["input"]))] = c["id"]
    new = {}  # (op, system, legs, aud) -> sorted stmtLens
    for (op, idh, sl, legs, aud), sysname in keys.items():
        new.setdefault((op, sysname, legs, aud), set()).add((sl, idh))
    rows = []
    for g, members in sorted(new.items()):
        members = sorted(members)
        ref = old.get(g)
        for rank, (sl, idh) in enumerate(members):
            if ref:
                base = ref[min(rank, len(ref) - 1)][1]
                src = f"live {g[1]} op {g[0]} legs {g[2]} auditor {g[3]} rank {rank}"
            else:
                base = max(gas for (op, s, _, _), v in old.items() if op == g[0] and s == g[1] for _, gas in v)
                src = f"largest live {g[1]} op {g[0]}"
            row = {"op": g[0], "id": "0x" + idh, "stmtLen": sl, "gas": int(round(base * f / 1000.0)) * 1000}
            if g[0] == 7:
                row["legs"], row["auditorOn"] = g[2], g[3]
            rows.append(row)
            print(f"op {g[0]} {g[1]} legs {g[2]} aud {g[3]} stmtLen {sl:,}: {row['gas']:,} ({src} {base:,} x {f})")
    sched = {"timestamp": "0x0", "pqz": rows, "selftestGas": int(round(live["selftestGas"] * f / 1000.0)) * 1000,
             "mldsa44Gas": live["mldsa44Gas"], "mldsa65Gas": live["mldsa65Gas"]}
    json.dump({"schedules": [sched]}, open(out, "w"), indent=2)
    print(f"{len(rows)} rows, selftestGas {sched['selftestGas']:,} -> {out}")


if __name__ == "__main__":
    main(*sys.argv[1:])
