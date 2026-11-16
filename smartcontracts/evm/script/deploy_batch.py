# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""deploy.sh evm, DeploySend's plan in batches (NET-EVM-11 Change, owner 2026-11-15). Stdlib only (python3 -I).
  deploy_batch.py check <dry-run plan> <send plan> <broadcast> <from> <to> <all> [fail <rc>]
      after one batch `[from, to)` (forge's run of `DeploySend.run(string,uint256,uint256)`): one line per transaction from
      the batch's receipts, in plan order (`send <i>/<N> <phase> <contract> gas <used> <address> tx <hash>`), a `skip` line
      for a release already there (no transaction: DeploySend's release-done check); exit 0 only if every transaction forge
      sent maps to a plan index of the batch, has a receipt and every receipt has status 1; else the `FAIL` line of the
      first transaction without a good receipt and exit 1 (with `fail <rc>`, forge's own exit code, always exit 1). The
      batch's transactions and receipts are appended to <all> (every batch of this deploy).
  deploy_batch.py fee <MAX_FEE_GWEI> <max fee, wei>
      the fee gate before each batch: exit 0 iff the max fee (2 x base fee + tip) <= MAX_FEE_GWEI; else a named line, exit 1.
  deploy_batch.py self-test
Never a key: plans, receipts and fees only."""
import decimal
import json
import os
import sys
import tempfile


def phase_of(t):
    """The phase of each dry-run plan transaction (libraries, verifiers, registry, …, releases, pqchat, zether)."""
    out, last = [], None
    for x in t:
        n, f = x.get("contractName") or "", (x.get("function") or "").split("(")[0]
        if f == "configureChain":
            p = "configureChain"
        elif f == "setChainEntries":
            p = "directory entries"
        elif f in ("createToken", "transfer"):
            p = "demo tokens"
        elif f in ("publishClassEnv", "deployImplementation", "setClassKindEnabled", "createInstance") or n.startswith("PqChat"):
            p = "pqchat"
        elif f or "Token" in n or n.startswith("SCaaSDex"):
            z = "Zether" in n or any("Zether" in (a.get("contractName") or "") for a in x.get("additionalContracts") or [])
            if not z and f and last in ("releases", "zether releases"):
                p = last  # publishTokenEnv / setTokenKindEnabled: the release they belong to
            else:
                p = "zether releases" if z else "releases"
        elif n.endswith("Lib"):
            p = "libraries"
        elif n.endswith("Verifier"):
            p = "verifiers"  # the UA kind verifiers, ZetherSchnorrBls12381Verifier included
        elif n.startswith("Zether"):
            p = "zether"
        else:
            p = {"SmartKeyAccountFactory": "SKA factory", "RelayFeeRouter": "relay fee router", "UARegistry": "registry",
                 "GovernanceRouter": "router", "ComplianceRegistry": "compliance registry",
                 "OpenFactory": "factory"}.get(n, n or "other")
        out.append(p)
        last = p
    return out


def check(plan, send, bc, lo, hi, allf, fail_rc=None):
    t = json.load(open(plan))["transactions"]
    q = json.load(open(send))
    n, ph = len(q["to"]), phase_of(t)
    try:
        b = json.load(open(bc)) if os.path.exists(bc) else {}
    except ValueError:
        b = {}
    txs, rec = b.get("transactions") or [], b.get("receipts") or []
    free = {}  # (to, input) -> the batch's plan indices still unmatched, in order
    for i in range(lo, hi):
        free.setdefault((q["to"][i].lower(), q["input"][i].lower()), []).append(i)
    at, bad = {}, None  # plan index -> (forge's transaction, its receipt)
    by = {r.get("transactionHash"): r for r in rec}
    for x in txs:
        tx = x.get("transaction") or {}
        k = ((tx.get("to") or "").lower(), (tx.get("input") or tx.get("data") or "0x").lower())
        if not free.get(k):
            bad = bad or f"a transaction outside the batch's plan rows (to {k[0]}) tx {x.get('hash')}"
            continue
        at[free[k].pop(0)] = (x, by.get(x.get("hash")))

    def name(i):
        return t[i].get("contractName") or (t[i].get("function") or "call").split("(")[0] if i < len(t) else "?"

    def addr(i, r):
        p = t[i] if i < len(t) else {}
        return (r or {}).get("contractAddress") or p.get("contractAddress") or (p.get("transaction") or {}).get("to") or ""

    first = None  # the first plan index of the batch without a good receipt
    for i in range(lo, hi):
        if i not in at:
            if fail_rc is None:
                print(f"[deploy] skip {i + 1}/{n} {ph[i] if i < len(ph) else '?'} {name(i)}: the release is there (no transaction)")
            elif first is None:
                first = i
            continue
        x, r = at[i]
        if r is None:
            first = i if first is None else first
            continue
        st = "" if r.get("status") == "0x1" else f" STATUS {r.get('status')}"
        print(f"[deploy] send {i + 1}/{n} {ph[i]} {name(i)} gas {int(r['gasUsed'], 16)}{st} {addr(i, r)} tx {r['transactionHash']}")
        if st and first is None:
            first = i
    a = json.load(open(allf)) if os.path.exists(allf) and os.path.getsize(allf) else {"transactions": [], "receipts": []}
    a["transactions"] += txs
    a["receipts"] += rec
    json.dump(a, open(allf, "w"))
    if fail_rc is None and first is None and bad is None and len(rec) == len(txs):
        return 0
    if first is None and bad:
        print(f"[deploy] FAIL send txs {lo + 1}-{hi}/{n}: {bad}" + (f", forge rc {fail_rc}" if fail_rc is not None else ""))
        return 1
    i = first if first is not None else lo
    h = at[i][0].get("hash") if i in at else None
    why = bad or ("no receipt" if i in at and at[i][1] is None else f"status {at[i][1].get('status')}" if i in at else "not sent")
    if fail_rc is not None:
        why = f"rc {fail_rc}, {why}"
    print(f"[deploy] FAIL {ph[i] if i < len(ph) else 'send'} tx {i + 1}/{n} {name(i)} {why} {addr(i, at[i][1] if i in at else None)}"
          + (f" tx {h}" if h else ""))
    return 1


def fee(max_gwei, wei):
    try:
        cap = int(decimal.Decimal(max_gwei) * 10**9)
        got = int(wei)
    except (decimal.InvalidOperation, ValueError):
        print(f"[deploy] FAIL fee gate: MAX_FEE_GWEI {max_gwei!r} / max fee {wei!r} is not a number (FEE_GATE_BAD)")
        return 1
    g = decimal.Decimal(got) / 10**9
    if cap < 0 or got > cap:
        print(f"[deploy] FAIL fee gate: max fee 2 x base fee + tip = {g} gwei > MAX_FEE_GWEI {max_gwei} (FEE_OVER_MAX); "
              "nothing of this batch sent; a re-run skips the releases already there")
        return 1
    print(f"[deploy] fee gate ok: {g} gwei <= MAX_FEE_GWEI {max_gwei}")
    return 0


def self_test():
    d = tempfile.mkdtemp()
    A, B = "0x" + "aa" * 20, "0x" + "bb" * 20
    plan = os.path.join(d, "p.json")
    send = os.path.join(d, "q.json")
    bc = os.path.join(d, "b.json")
    allf = os.path.join(d, "all.json")
    json.dump({"transactions": [{"contractName": "MetaTxLib", "contractAddress": A},
                                {"contractName": "UARegistry", "contractAddress": B},
                                {"contractName": "OpenFactory", "function": "deployTokenImplementation(uint8)"}]}, open(plan, "w"))
    json.dump({"from": [A] * 3, "to": [A, A, B], "value": ["0x0"] * 3, "input": ["0x01", "0x02", "0x03"]}, open(send, "w"))

    def bcast(*rows):  # (to, input, hash, status | None = no receipt)
        json.dump({"transactions": [{"hash": h, "transaction": {"to": to, "input": i}} for to, i, h, _ in rows],
                   "receipts": [{"transactionHash": h, "status": s, "gasUsed": "0x5208"} for _, _, h, s in rows if s]},
                  open(bc, "w"))

    bad = []
    def want(rc, got, what):
        if rc != got:
            bad.append(what)

    bcast((A, "0x01", "0x11", "0x1"), (A, "0x02", "0x12", "0x1"))
    want(0, check(plan, send, bc, 0, 2, allf), "a good batch")
    bcast((A, "0x02", "0x12", "0x1"), (A, "0x01", "0x11", "0x1"))
    want(0, check(plan, send, bc, 0, 2, allf), "receipts in another order")
    bcast((A, "0x01", "0x11", "0x1"), (A, "0x02", "0x12", "0x0"))
    want(1, check(plan, send, bc, 0, 2, allf), "a status 0 receipt")
    bcast((A, "0x01", "0x11", "0x1"), (A, "0x02", "0x12", None))
    want(1, check(plan, send, bc, 0, 2, allf), "a receipt missing")
    bcast((A, "0x01", "0x11", "0x1"), (B, "0x09", "0x19", "0x1"))
    want(1, check(plan, send, bc, 0, 2, allf), "a transaction outside the plan")
    bcast((A, "0x01", "0x11", "0x1"), (A, "0x02", "0x12", "0x1"))
    want(1, check(plan, send, bc, 1, 3, allf), "a row of another batch")
    bcast((A, "0x02", "0x12", "0x1"))
    want(0, check(plan, send, bc, 1, 3, allf), "a release already there: skipped")
    want(1, check(plan, send, bc, 1, 3, allf, fail_rc=1), "forge failed")
    want(1, check(plan, send, os.path.join(d, "none.json"), 0, 2, allf, fail_rc=1), "forge failed before any send")
    want(13, len(json.load(open(allf))["receipts"]), "every batch appended")
    want(0, fee("0.1", "100000000"), "fee at the cap")
    want(0, fee("0.1", "99999999"), "fee under the cap")
    want(1, fee("0.1", "100000001"), "fee over the cap by 1 wei")
    want(1, fee("x", "1"), "a bad MAX_FEE_GWEI")
    want(1, fee("-1", "0"), "a negative MAX_FEE_GWEI")
    print("deploy_batch self-test: " + ("ok" if not bad else "FAIL " + "; ".join(bad)))
    return 1 if bad else 0


if __name__ == "__main__":
    a = sys.argv[1:]
    if a[:1] == ["check"] and len(a) in (7, 9):
        sys.exit(check(a[1], a[2], a[3], int(a[4]), int(a[5]), a[6], a[8] if len(a) == 9 else None))
    if a[:1] == ["fee"] and len(a) == 3:
        sys.exit(fee(a[1], a[2]))
    if a == ["self-test"]:
        sys.exit(self_test())
    sys.exit(__doc__)
