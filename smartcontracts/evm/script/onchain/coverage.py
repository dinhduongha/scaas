#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T66b Step 5b: the on-chain coverage list and its tally. Python stdlib (python3 -I). UNAUDITED.

  coverage.py gen [--groups G] [--out O]          every external entry of every contract of groups.json (name, selector,
                                                  state-changing or view), from the build (out/) and, for a token kind,
                                                  script/modules/entries.json (its module letter too) -> O/coverage.json
  coverage.py forge <net> <book> <run.json>       a forge broadcast (broadcast/<Group>.s.sol/<chain>/run-latest.json) as
                                                  records: one per transaction (to, selector, hash, gasUsed, status)
                                                  -> O/records-<net>-<group>.jsonl (replaced)
  coverage.py trace <net> <group> <rpc>           on a node with debug_traceTransaction (the local copy): every frame of
                                                  every recorded transaction of <net>, so the entries reached inside a
                                                  call (a module, a library, a relayed call) are counted as reached
  coverage.py neg <net> <group> <rpc>             the group's negatives (listed by the script), each by eth_call on the
                                                  node: refused with the expected named error or not
  coverage.py views <net> <rpc>                   every view with static parameters of every booked contract, by eth_call
                                                  with zero arguments (records-<net>-views.jsonl)
  coverage.py note [--net N]... [--reasons R] [--txs]   the runs note's body (per record file, table, entries not called
                                                  with their reason, negatives, heaviest; every transaction with --txs)
  coverage.py table [--net N]...                  coverage.json updated from the records; the per-contract table

A book (deployments/onchain-<net>-<group>.json, git-ignored, written by each group script) maps an address to a contract label of groups.json. A
record is one JSON line: {net, to, sel, tx, gas, status, what, frames?}; any harness may append its own (the Python ones
do). A group is pluggable by name: add it to groups.json, gen again; records of earlier runs keep their entries."""
import argparse
import glob
import json
import os
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
EVM = os.path.abspath(os.path.join(HERE, "../.."))
# matrix.sh's run dir (MATRIX_OUT), else today's; never an earlier round's committed run note
OUT = os.path.join(EVM, os.environ.get("MATRIX_OUT") or time.strftime("runs/%Y-%m-%d-matrix"))
BUILD = os.path.join(EVM, os.environ.get("ONCHAIN_OUT", "out/onchain"))  # the build the scripts ran from (src unchanged since the deploy)


def _entries(c):
    if "t66b" in c:
        rows = json.load(open(os.path.join(EVM, "script/modules/entries.json")))["kinds"][c["t66b"]]
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
    book = _book(a.book) if os.path.exists(a.book) else {}
    # one file per net and script: a rerun of a script replaces its records; groups run side by side
    rp = os.path.join(a.out, f"records-{a.net}-{_script(a.runs[0])}.jsonl")
    with open(rp, "w") as f:
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
                                    "script": _script(p)}) + "\n")
    print(f"records: {rp}")


def _script(p):
    """`broadcast/<Group>.s.sol/<chain>/run-latest.json` -> `<group>`."""
    return os.path.basename(os.path.dirname(os.path.dirname(p))).split(".")[0].lower()


def _rpc(url, m, p):
    q = urllib.request.Request(url, json.dumps({"jsonrpc": "2.0", "id": 1, "method": m, "params": p}).encode(),
                               {"content-type": "application/json"})
    r = json.load(urllib.request.urlopen(q, timeout=600))
    if "error" in r:
        raise RuntimeError(r["error"])
    return r["result"]


def trace(a):
    p = os.path.join(a.out, f"records-{a.net}-{a.group}.jsonl")
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


def neg(a):
    """The group's negatives (deployments/onchain-<net>-<group>-neg.txt: from to data selector what), each by eth_call
    on the node at the latest block: status 2 = refused with the expected error, 0 = anything else (ran, or another
    error). Appended to the group's records with tx "" (a call, not a transaction)."""
    p = os.path.join(EVM, f"deployments/onchain-{a.net}-{a.group}-neg.txt")
    if not os.path.exists(p):
        return
    book = _book(os.path.join(EVM, f"deployments/onchain-{a.net}-{a.group}.json"))
    rp = os.path.join(a.out, f"records-{a.net}-{a.group}.jsonl")
    n = bad = 0
    with open(rp, "a") as f:
        for line in open(p):
            frm, to, data, want, what = line.rstrip("\n").split(" ", 4)
            try:
                _rpc(a.rpc, "eth_call", [{"from": frm, "to": to, "data": data, "gas": hex(50_000_000)}, "latest"])
                got = "ran"
            except RuntimeError as e:
                err = e.args[0] if isinstance(e.args[0], dict) else {}
                d = err.get("data") or ""
                d = d.get("data", "") if isinstance(d, dict) else d
                # the selector, or the whole revert data when the script listed it whole (`_negData`)
                got = (d if len(want) > 10 else d[:10]) if isinstance(d, str) and d.startswith("0x") \
                    else str(err.get("message", ""))[:80]
            ok = got.lower() == want.lower()
            n, bad = n + 1, bad + (not ok)
            f.write(json.dumps({"net": a.net, "to": to.lower(), "label": book.get(to.lower(), ""), "sel": data[2:10],
                                "tx": "", "gas": 0, "status": 2 if ok else 0, "what": f"negative: {what}",
                                "expected": want, "got": got, "script": a.group}) + "\n")
            print(f"{'ok ' if ok else 'BAD'} negative {what}: expected {want}, got {got}")
    print(f"negatives: {n}, {bad} not refused as expected")
    if bad:
        sys.exit(1)


def _static_words(sig):
    """The head words of a signature whose parameters are all static (tuples flattened), else None."""
    import re
    args = sig[sig.index("(") + 1:-1]
    if "[" in args or "string" in args or re.search(r"\bbytes\b(?!\d)", args):
        return None
    return len([t for t in re.split(r"[(),]", args) if t])


def views(a):
    """Every view / pure entry with static parameters of every booked contract of <net>, by eth_call on the node with
    zero arguments (the deployed state answers): records-<net>-views.jsonl, status 1 = answered, 0 = reverted (a view
    that needs real arguments; not counted as reached)."""
    cov = json.load(open(os.path.join(a.out, "coverage.json")))
    lab = {lb: c for cs in cov["groups"].values() for lb, c in cs.items()}
    book = {}
    for b in sorted(glob.glob(os.path.join(EVM, f"deployments/onchain-{a.net}-*.json"))):
        if not b.endswith("-neg.txt"):
            book.update(_book(b))
    n = ok = 0
    with open(os.path.join(a.out, f"records-{a.net}-views.jsonl"), "w") as f:
        for addr, lb in sorted(book.items()):
            if lb not in lab or _rpc(a.rpc, "eth_getCode", [addr, "latest"]) in ("0x", None):
                continue  # not a contract on this node (a group's local fork is gone after its run)
            for e in lab.get(lb, {}).get("entries", []):
                w = _static_words(e["sig"]) if e["mut"] in ("view", "pure") else None
                if w is None:
                    continue
                n += 1
                try:
                    _rpc(a.rpc, "eth_call", [{"to": addr, "data": "0x" + e["sel"] + "00" * 32 * w}, "latest"])
                    st = 1
                except RuntimeError:
                    st = 0
                ok += st
                f.write(json.dumps({"net": a.net, "to": addr, "label": lb, "sel": e["sel"], "tx": "", "gas": 0,
                                    "status": st, "what": f"view {e['sig']}", "script": "views"}) + "\n")
    print(f"views: {n} called, {ok} answered")


def _records(out, n):
    """The record files of net `n`: the run dir's and its groups' own subdirectories (wraplimits writes under its own)."""
    return glob.glob(os.path.join(out, f"records-{n}-*.jsonl")) + glob.glob(os.path.join(out, "*", f"records-{n}-*.jsonl"))


def table(a):
    # fail closed: a net with no book would recount its records unlabelled and write empty runs over the tally
    missing = [n for n in a.net if not glob.glob(os.path.join(EVM, f"deployments/onchain-{n}-*.json"))]
    if missing:
        sys.exit(f"coverage.py table: no book for {', '.join(missing)} (deployments/onchain-<net>-*.json); "
                 f"{os.path.join(a.out, 'coverage.json')} left as it was")
    cov = json.load(open(os.path.join(a.out, "coverage.json")))
    books = {}
    own = {}  # per net and group: its own book over the base book (local groups run on separate forks of one state, so
    # one key at one nonce makes the same address in two groups: a record's frames are labelled by its own group's book)
    for n in a.net:
        books[n], own[n] = {}, {}
        base = os.path.join(EVM, f"deployments/onchain-{n}-base.json")
        for b in sorted(glob.glob(os.path.join(EVM, f"deployments/onchain-{n}-*.json"))):
            books[n].update(_book(b))
            g = os.path.basename(b)[len(f"onchain-{n}-"):-len(".json")]
            own[n][g] = {**(_book(base) if os.path.exists(base) else {}), **_book(b)}
    lab = {lb: c for cs in cov["groups"].values() for lb, c in cs.items()}
    for c in lab.values():
        for e in c["entries"]:  # recount only the nets asked for; another net's tally stays
            e["runs"] = {k: v for k, v in e.get("runs", {}).items() if k not in a.net}
    for n in a.net:
        for r in (json.loads(x) for p in sorted(_records(a.out, n)) for x in open(p)):
            if r["status"] == 2:
                continue  # a negative refused as expected: listed in the note, not counted as a call
            hits = [(r.get("label") or books[n].get(r["to"], ""), r["sel"], "outer", r["status"])]
            bk = own[n].get(r.get("script", ""), books[n])
            hits += [(bk.get(t, ""), s, "inner", ok) for t, s, _, ok in r.get("frames", [])]
            for lb, s, how, ok in hits:
                for e in lab.get(lb, {}).get("entries", []):
                    if e["sel"] == s:
                        v = e["runs"].setdefault(n, {"called": 0, "reached": 0, "failed": 0, "tx": []})
                        v["called"] += how == "outer" and ok == 1
                        v["reached"] += ok == 1
                        v["failed"] += how == "outer" and ok != 1
                        if how == "outer" and len(v["tx"]) < 3:
                            v["tx"].append([r["tx"], r["gas"], r["status"], r.get("what", "")])
    json.dump(cov, open(os.path.join(a.out, "coverage.json"), "w"), indent=1)
    hdr = "group | contract | entries | state-changing | " + " | ".join(
        f"{n}: state-changing called / reached / views reached" for n in a.net)
    print(hdr)
    for g, cs in cov["groups"].items():
        for lb, c in cs.items():
            es = c["entries"]
            sc = [e for e in es if e["mut"] not in ("view", "pure")]
            cols = []
            for n in a.net:
                called = sum(1 for e in sc if e["runs"].get(n, {}).get("called"))
                reached = sum(1 for e in sc if e["runs"].get(n, {}).get("reached"))
                views = sum(1 for e in es if e not in sc and e["runs"].get(n, {}).get("reached"))
                cols.append(f"{called} / {reached} / {views}")
            print(f"{g} | {lb} | {len(es)} | {len(sc)} | " + " | ".join(cols)
                  + (f" | needs {c['needs']}" if c.get("needs") else "") + (f" | via {', '.join(c['via'])}" if c.get("via") else ""))


def note(a):
    """The runs note's body: the table, then per net the entries not called (each with its reason from --reasons:
    {label: {sig glob: reason}}, `*` as the label for every contract), the negatives, the heaviest transactions, and
    every transaction (status, gasUsed, hash, what)."""
    import contextlib
    import fnmatch
    import io
    rs = json.load(open(a.reasons)) if a.reasons and os.path.exists(a.reasons) else {}
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        table(a)
    cov = json.load(open(os.path.join(a.out, "coverage.json")))
    out = ["## Coverage per contract (state-changing called = a transaction of this net called the entry and succeeded;",
           "## reached = it also ran inside another call, by the trace (local only); views reached = answered an eth_call)",
           buf.getvalue().rstrip()]
    for n in a.net:
        recs = [json.loads(x) for p in sorted(_records(a.out, n)) for x in open(p)]
        if not recs:
            continue
        out.append(f"\n## {n}: per record file (txs, status 1, the heaviest gasUsed; eth_calls answered; negatives refused as expected)")
        out.append("records | txs | status 1 | max gasUsed | calls ok | negatives")
        for p in sorted(_records(a.out, n)):
            rr = [json.loads(x) for x in open(p)]
            t = [r for r in rr if r["tx"]]
            ng = [r for r in rr if r["what"].startswith("negative")]
            c = [r for r in rr if not r["tx"] and r not in ng]
            out.append(f"{os.path.basename(p)[len(f'records-{n}-'):-6]} | {len(t)} | {sum(r['status'] == 1 for r in t)} | "
                       f"{max([r['gas'] for r in t], default=0):,} | {sum(r['status'] == 1 for r in c)} / {len(c)} | "
                       f"{sum(r['status'] == 2 for r in ng)} / {len(ng)}")
        out.append(f"\n## {n}: state-changing entries not called by a transaction, with the reason")
        miss = 0
        for g, cs in cov["groups"].items():
            for lb, c in cs.items():
                for e in c["entries"]:
                    if e["mut"] in ("view", "pure") or e["runs"].get(n, {}).get("called"):
                        continue
                    why = c.get("needs") and f"needs {c['needs']}"
                    if not why and e["runs"].get(n, {}).get("reached"):
                        why = "reached inside another call (trace)" if c.get("via") is None else "a library / module entry, reached by its callers"
                    for key in (lb, "*"):
                        for pat, r in rs.get(key, {}).items():
                            if not why and fnmatch.fnmatchcase(e["sig"], pat):
                                why = r
                    if not why and c.get("via"):
                        why = "a library / module entry: runs only through " + ", ".join(c["via"])
                    miss += not why
                    out.append(f"{g} | {lb} | {e['sig']} | {why or 'NO REASON RECORDED'}")
        out.append(f"({miss} without a reason)")
        neg = [r for r in recs if r["what"].startswith("negative")]
        out.append(f"\n## {n}: negatives ({len(neg)}; refused as expected = status 2)")
        out += [f"{'ok ' if r['status'] == 2 else 'BAD'} | {r.get('label', '')} | {r['what']} | expected {r.get('expected', '')}"
                f" got {r.get('got', '')}" for r in neg]
        txs = [r for r in recs if r["tx"]]
        out.append(f"\n## {n}: transactions {len(txs)}, status 1: {sum(r['status'] == 1 for r in txs)}; the heaviest ten")
        out += [f"{r['gas']:,} | {r['tx']} | {r.get('label', '')} | {r['what']}" for r in sorted(txs, key=lambda r: -r["gas"])[:10]]
        if a.txs:  # the records hold every transaction; the note lists them only when asked
            out.append(f"\n## {n}: every transaction (script | status | gasUsed | hash | contract | what)")
            out += [f"{r['script']} | {r['status']} | {r['gas']:,} | {r['tx']} | {r.get('label', '')} | {r['what'][:90]}" for r in txs]
    print("\n".join(out))


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
    p.add_argument("group")
    p.add_argument("rpc")
    p = sp.add_parser("neg")
    p.add_argument("net")
    p.add_argument("group")
    p.add_argument("rpc")
    p = sp.add_parser("views")
    p.add_argument("net")
    p.add_argument("rpc")
    p = sp.add_parser("table")
    p.add_argument("--net", action="append", default=[])
    p = sp.add_parser("note")
    p.add_argument("--net", action="append", default=[])
    p.add_argument("--reasons", default=os.path.join(HERE, "notrun.json"))
    p.add_argument("--txs", action="store_true", help="also list every transaction")
    a = ap.parse_args()
    if a.cmd in ("table", "note") and not a.net:
        a.net = ["local", "scaas-testnet"]
    {"gen": gen, "forge": forge, "trace": trace, "neg": neg, "views": views, "table": table, "note": note}[a.cmd](a)


if __name__ == "__main__":
    sys.exit(main())
