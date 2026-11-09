#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T66b Step 5b: the on-chain coverage list and its tally. Python stdlib (python3 -I). UNAUDITED.

  coverage.py gen [--groups G] [--out O]          every external entry of every contract of groups.json (name, selector,
                                                  state-changing or view), from the build (out/) and, for a token kind,
                                                  script/t66b/entries.json (its module letter too) -> O/coverage.json
  coverage.py forge <net> <book> <run.json>...    a forge broadcast (broadcast/<script>/<chain>/run-latest.json) as
                                                  records: one per transaction (to, selector, hash, gasUsed, status)
                                                  -> O/records-<net>.jsonl (appended)
  coverage.py trace <net> <rpc>                   on a node with debug_traceTransaction (the local copy): every frame of
                                                  every recorded transaction of <net>, so the entries reached inside a
                                                  call (a module, a library, a relayed call) are counted as reached
  coverage.py table [--net N]...                  coverage.json updated from the records; the per-contract table

A book (deployments/onchain-<chain>.json, written by the scripts) maps an address to a contract label of groups.json. A
record is one JSON line: {net, to, sel, tx, gas, status, what, frames?}; any harness may append its own (the Python ones
do). A group is pluggable by name: add it to groups.json, gen again; records of earlier runs keep their entries."""
import argparse
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
EVM = os.path.abspath(os.path.join(HERE, "../.."))
OUT = os.path.join(EVM, "runs/2026-11-10-ua-mtx-merge-t66b-step5b")
BUILD = os.path.join(EVM, os.environ.get("ONCHAIN_OUT", "out/onchain"))  # the build the scripts ran from (src unchanged since the deploy)


def _entries(c):
    if "t66b" in c:
        rows = json.load(open(os.path.join(EVM, "script/t66b/entries.json")))["kinds"][c["t66b"]]
        return [{"sig": r["sig"], "sel": r["sel"], "mut": r["mut"], "module": r["group"]} for r in rows]
    a = json.load(open(os.path.join(BUILD, c["artifact"] + ".json")))
    muts = {}
    for x in a["abi"]:
        if x["type"] == "function":
            for f in (_t, _it):  # a library's selectors name its structs (internalType)
                muts[x["name"] + "(" + ",".join(f(i) for i in x["inputs"]) + ")"] = x["stateMutability"]
    return [{"sig": s, "sel": h, "mut": muts.get(s, "delegatecall")} for s, h in sorted(a["methodIdentifiers"].items())]


def _t(i):
    """The canonical ABI type of an input (tuples expanded)."""
    t = i["type"]
    if t.startswith("tuple"):
        return "(" + ",".join(_t(c) for c in i["components"]) + ")" + t[5:]
    return t


def _it(i):
    """A library's selector type: the internal type, `struct ` / `enum ` / `contract ` dropped (enum -> uint8)."""
    t = i.get("internalType", i["type"])
    if t.startswith("enum "):
        return "uint8" + t[t.index("]"):] if "]" in t else "uint8"
    for p in ("struct ", "contract "):
        t = t.removeprefix(p)
    return t


def gen(a):
    g = json.load(open(a.groups))["groups"]
    cov = {"_comment": "T66b Step 5b coverage list (script/onchain/coverage.py gen; runs added by `table`). mut: the ABI "
                       "state mutability; module: a token kind's body module (K = kept in the core). UNAUDITED.",
           "groups": {}}
    for name, cs in g.items():
        cov["groups"][name] = {c["label"]: {k: v for k, v in c.items() if k != "label"} | {"entries": _entries(c)}
                               for c in cs}
    os.makedirs(a.out, exist_ok=True)
    json.dump(cov, open(os.path.join(a.out, "coverage.json"), "w"), indent=1)
    n = sum(len(c["entries"]) for cs in cov["groups"].values() for c in cs.values())
    print(f"coverage.json: {len(cov['groups'])} groups, {n} entries")


def _book(p):
    return {k.lower(): v for k, v in json.load(open(p)).items()}


def forge(a):
    book = _book(a.book)
    with open(os.path.join(a.out, f"records-{a.net}.jsonl"), "a") as f:
        for p in a.runs:
            r = json.load(open(p))
            rc = {x["transactionHash"]: x for x in r["receipts"]}
            for t in r["transactions"]:
                tx = t["transaction"]
                to = (tx.get("to") or t.get("contractAddress") or "").lower()
                data = tx.get("input") or tx.get("data") or "0x"
                x = rc.get(t["hash"], {})
                f.write(json.dumps({"net": a.net, "to": to, "label": book.get(to, t.get("contractName") or ""),
                                    "sel": data[2:10] if tx.get("to") else "create", "tx": t["hash"],
                                    "gas": int(x.get("gasUsed", "0x0"), 16), "status": int(x.get("status", "0x0"), 16),
                                    "what": t.get("function") or t.get("contractName") or "",
                                    "script": os.path.basename(os.path.dirname(os.path.dirname(p)))}) + "\n")
    print("records appended")


def _rpc(url, m, p):
    q = urllib.request.Request(url, json.dumps({"jsonrpc": "2.0", "id": 1, "method": m, "params": p}).encode(),
                               {"content-type": "application/json"})
    r = json.load(urllib.request.urlopen(q, timeout=600))
    if "error" in r:
        raise RuntimeError(r["error"])
    return r["result"]


def trace(a):
    p = os.path.join(a.out, f"records-{a.net}.jsonl")
    rows = [json.loads(x) for x in open(p)]
    for r in rows:
        if "frames" in r or not r["tx"]:
            continue
        fr = []

        def walk(c):
            if c.get("input", "0x")[2:10] and c.get("to"):
                fr.append([c["to"].lower(), c["input"][2:10], c.get("type", ""), 0 if c.get("error") else 1])
            for k in c.get("calls", []):
                walk(k)
        walk(_rpc(a.rpc, "debug_traceTransaction", [r["tx"], {"tracer": "callTracer"}]))
        r["frames"] = fr[1:]
    with open(p, "w") as f:
        f.writelines(json.dumps(r) + "\n" for r in rows)
    print(f"{len(rows)} records traced")


def table(a):
    cov = json.load(open(os.path.join(a.out, "coverage.json")))
    books = {}
    for n in a.net:
        b = os.path.join(EVM, f"deployments/onchain-{n}.json")
        books[n] = _book(b) if os.path.exists(b) else {}
    lab = {lb: c for cs in cov["groups"].values() for lb, c in cs.items()}
    for c in lab.values():
        for e in c["entries"]:
            e["runs"] = {}
    for n in a.net:
        p = os.path.join(a.out, f"records-{n}.jsonl")
        if not os.path.exists(p):
            continue
        for r in map(json.loads, open(p)):
            hits = [(r.get("label") or books[n].get(r["to"], ""), r["sel"], "outer", r["status"])]
            hits += [(books[n].get(t, ""), s, "inner", ok) for t, s, _, ok in r.get("frames", [])]
            for lb, s, how, ok in hits:
                for e in lab.get(lb, {}).get("entries", []):
                    if e["sel"] == s:
                        v = e["runs"].setdefault(n, {"outer": 0, "inner": 0, "ok": 0, "tx": []})
                        v[how] += 1
                        v["ok"] += ok
                        if how == "outer" and len(v["tx"]) < 3:
                            v["tx"].append([r["tx"], r["gas"], r["status"], r.get("what", "")])
    json.dump(cov, open(os.path.join(a.out, "coverage.json"), "w"), indent=1)
    hdr = "group | contract | entries | state-changing | " + " | ".join(
        f"{n} sc called / reached / views called" for n in a.net)
    print(hdr)
    for g, cs in cov["groups"].items():
        for lb, c in cs.items():
            es = c["entries"]
            sc = [e for e in es if e["mut"] not in ("view", "pure")]
            cols = []
            for n in a.net:
                called = sum(1 for e in sc if e["runs"].get(n, {}).get("outer"))
                reached = sum(1 for e in sc if e["runs"].get(n, {}).get("ok"))
                views = sum(1 for e in es if e not in sc and e["runs"].get(n))
                cols.append(f"{called} / {reached} / {views}")
            print(f"{g} | {lb} | {len(es)} | {len(sc)} | " + " | ".join(cols)
                  + (f" | needs {c['needs']}" if c.get("needs") else "") + (f" | via {', '.join(c['via'])}" if c.get("via") else ""))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=OUT)
    sp = ap.add_subparsers(dest="cmd", required=True)
    p = sp.add_parser("gen")
    p.add_argument("--groups", default=os.path.join(HERE, "groups.json"))
    p = sp.add_parser("forge")
    p.add_argument("net")
    p.add_argument("book")
    p.add_argument("runs", nargs="+")
    p = sp.add_parser("trace")
    p.add_argument("net")
    p.add_argument("rpc")
    p = sp.add_parser("table")
    p.add_argument("--net", action="append", default=[])
    a = ap.parse_args()
    if a.cmd == "table" and not a.net:
        a.net = ["local", "7622"]
    {"gen": gen, "forge": forge, "trace": trace, "table": table}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
