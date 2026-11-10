#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T66b Step 5b, NET-EVM-09 (owner 2026-11-10): every contract we deployed on a chain is verified on Blockscout. Discovery,
not only broadcasts: the deployment books (deployments/<chain>.json, its releases json, onchain-<net>-*.json), every
broadcast of the chain (CREATE / CREATE2 rows, factory children), then the getters that name a child, to a fixed point:
a DEX's puller(), modules() of a release or DEX, RelayFeeRouter's EXECUTOR(), the implementation of each EIP-1167 clone,
the libraries and dependencies of every factory env (token kinds 0-13, the DEX) and the factory's contractsPage per class.
Each address with code ends in one state: verified (full match), linked clone (EIP-1167, its implementation verified),
data (SSTORE2, code 0x00…); anything else is a fail row and the exit is 1. --fix first verifies what is not: the
artifact and constructor arguments from its broadcast row (init code after the creation bytecode), or from its creator's
code path (DexPuller(rescueTo), RelayFeeExecutor()); a child whose arguments cannot be derived fails with that reason.
  python3 -I script/onchain/vcheck.py <net> <rpc> <blockscout api> [--fix]      (from smartcontracts/evm)
Rows: <state> | <name> | <address> [| reason]. Test chains only."""
import glob
import json
import os
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
EVM = os.path.abspath(os.path.join(HERE, "../.."))
CAPPED = os.path.join(EVM, "../../scripts/capped")
CLONE = "363d3d373d3d3d363d73"
net, RPC, API = sys.argv[1:4]
FIX = "--fix" in sys.argv


def rpc(m, p):
    q = urllib.request.Request(RPC, json.dumps({"jsonrpc": "2.0", "id": 1, "method": m, "params": p}).encode(),
                               {"Content-Type": "application/json"})
    return json.load(urllib.request.urlopen(q, timeout=60)).get("result")


def call(to, sig, *words):
    out = subprocess.run(["cast", "call", "-r", RPC, to, sig, *words], capture_output=True, text=True)
    return out.stdout.strip() if out.returncode == 0 else None


def bs(path):
    for i in range(6):
        try:
            return json.load(urllib.request.urlopen(f"{API}/v2/{path}", timeout=30))
        except Exception:  # noqa: BLE001  429 / 404 / a slow lookup: back off
            time.sleep(5 * (i + 1))
    return {}


chain = int(rpc("eth_chainId", []), 16)
name, init, found = {}, {}, set()  # address -> artifact name / init code (a broadcast's), every address seen


def add(a, n=None, code=None):
    a = a.lower()
    if a in ("0x" + "0" * 40,):
        return
    found.add(a)
    if n and n not in ("", "-") and a not in name:
        name[a] = n
    if code and a not in init:
        init[a] = code


rel = os.environ.get("RELEASES_JSON", f"deployments/{chain}-t66b-releases.json" if chain == 7622 else f"deployments/{chain}-releases.json")
for p in [f"deployments/{chain}.json", rel]:
    if os.path.exists(os.path.join(EVM, p)):
        for k, v in json.load(open(os.path.join(EVM, p))).items():
            if isinstance(v, str) and v.startswith("0x") and len(v) == 42:
                add(v)
            elif isinstance(v, dict) and "address" in v:
                add(v["address"], k)
for p in glob.glob(os.path.join(EVM, f"deployments/onchain-{net}-*.json")):
    for a, lab in json.load(open(p)).items():
        add(a)
for p in glob.glob(os.path.join(EVM, f"broadcast/*/{chain}/*-latest.json")):
    for t in json.load(open(p)).get("transactions", []):
        if str(t.get("transactionType", "")).startswith("CREATE") and t.get("contractAddress"):
            tx = t["transaction"]
            add(t["contractAddress"], t.get("contractName"), "0x" + tx["input"][66:] if tx.get("to") else tx["input"])
        for c in t.get("additionalContracts") or []:
            add(c["address"], c.get("contractName"), c.get("initCode"))

# the getters that name a child, to a fixed point
code, done, creator = {}, set(), {}
while found - done:
    for a in sorted(found - done):
        done.add(a)
        c = code[a] = (rpc("eth_getCode", [a, "latest"]) or "0x").lower()
        if c in ("0x", "0x0") or c.startswith("0x00"):
            continue
        if c[2:].startswith(CLONE):
            add("0x" + c[22:62])
            continue
        for sig in ("puller()(address)", "EXECUTOR()(address)"):
            r = call(a, sig)
            if r and r.startswith("0x") and len(r) == 42:
                add(r)
                creator[r.lower()] = (a, sig)
        r = call(a, "modules()(address[])")
        for m in (r or "").strip("[]").replace(" ", "").split(","):
            if m.startswith("0x"):
                add(m)
        if call(a, "latestDexVersion()(uint64)") is not None:  # a factory: its envs and its contracts by class
            envs = []
            for k in range(14):
                envs += [("envOf(uint8,uint16)((address,address,bool,address[],bytes32[],address[],bytes32[]))", str(k), str(v))
                         for v in range(1, 4)]
            envs += [("dexEnvOf(uint16)((address,address,bool,address[],bytes32[],address[],bytes32[]))", str(v)) for v in range(1, 4)]
            for e in envs:
                r = call(a, *e)
                for w in (r or "").replace("(", " ").replace(")", " ").replace("[", " ").replace("]", " ").replace(",", " ").split():
                    if w.startswith("0x") and len(w) == 42:
                        add(w)
            for cls in range(8):
                r = call(a, "contractsPage(uint16,uint256,uint256)((address,bytes32,bytes32,uint16,uint16,uint64)[],uint256)", str(cls), "0", "200")
                for w in (r or "").replace("(", " ").replace(",", " ").split():
                    if w.startswith("0x") and len(w) == 42:
                        add(w)


def art(n):
    p = glob.glob(os.path.join(EVM, "out", "*", f"{n}.json"))
    return p[0] if len(p) == 1 else None


def args_of(a, n):
    """Constructor arguments: a broadcast row's init code after the creation bytecode, or the creator's code path."""
    if a in init and art(n):  # both with 0x; linked library placeholders have the addresses' length
        return init[a][len(json.load(open(art(n)))["bytecode"]["object"]):]
    if n == "DexPuller":
        return subprocess.run(["cast", "abi-encode", "f(address)", call(a, "rescueTo()(address)")],
                              capture_output=True, text=True).stdout.strip()[2:]
    if n == "RelayFeeExecutor":
        return ""
    return None


def guess(a):
    """A child's artifact name from its creator's getter (DexPuller, RelayFeeExecutor), else Blockscout's name."""
    if a in name:
        return name[a]
    if a in creator:
        return {"puller()(address)": "DexPuller", "EXECUTOR()(address)": "RelayFeeExecutor"}[creator[a][1]]
    return bs(f"smart-contracts/{a}").get("name")


def verify(a, n):
    ar = art(n)
    if not ar:
        return f"no single artifact out/*/{n}.json"
    x = args_of(a, n)
    if x is None:
        return f"{n}: constructor arguments not derivable (no broadcast row, no known creator path)"
    src = next(iter(json.load(open(ar))["metadata"]["settings"]["compilationTarget"]))
    cmd = [CAPPED, "forge", "verify-contract", a, f"{src}:{n}", "--verifier", "blockscout", "--verifier-url", API + "/",
           "--chain-id", str(chain), "--watch", "--delay", "10", "--skip-is-verified-check"] + (["--constructor-args", "0x" + x] if x else [])
    out = subprocess.run(cmd, capture_output=True, text=True, cwd=EVM, env={**os.environ, "FOUNDRY_PROFILE": os.environ.get("FOUNDRY_PROFILE", "scaas-testnet")})
    return None if out.returncode == 0 else (out.stdout + out.stderr).strip().splitlines()[-1][:160]


rows = []
for a in sorted(found):
    c = code.get(a, "0x")
    if c in ("0x", "0x0"):
        continue  # no code: an account (an EOA in a book), nothing deployed
    if c.startswith("0x00"):
        rows.append(("data", "SSTORE2", a, f"{(len(c) - 2) // 2} B"))
        continue
    if c[2:].startswith(CLONE):
        impl = "0x" + c[22:62]
        j = bs(f"smart-contracts/{a}")
        li = [x.get("address_hash", x.get("address", "")).lower() for x in (j.get("implementations") or [])]
        ok = j.get("proxy_type") in ("eip1167", "clone_with_immutable_arguments") and impl in li
        iv = bs(f"smart-contracts/{impl}").get("is_verified") is True
        rows.append(("linked clone" if ok and iv else "fail", guess(impl) or "?", a,
                     f"of {impl}" + ("" if ok and iv else f": proxy_type {j.get('proxy_type')}, implementations {li}, implementation verified {iv}")))
        continue
    j = bs(f"smart-contracts/{a}")
    why = None
    if not (j.get("is_verified") and not j.get("is_partially_verified")):
        n = guess(a)
        why = verify(a, n) if FIX and n else (f"not verified ({n or 'no name'})")
        j = bs(f"smart-contracts/{a}") if FIX and n else j
    full = j.get("is_verified") and not j.get("is_partially_verified")
    rows.append(("verified" if full else "fail", j.get("name") or guess(a) or "?", a, "" if full else (why or "partial match")))
    print(f"[{net}/verify] {rows[-1][1]} {a} {'ok' if full else 'FAIL ' + rows[-1][3]}", flush=True)
for r in rows:
    if r[0] != "verified":
        print(f"[{net}/verify] {r[1]} {r[2]} {r[0]} {r[3]}", flush=True)
cnt = {s: sum(r[0] == s for r in rows) for s in ("verified", "linked clone", "data", "fail")}
with open(os.path.join(EVM, f"runs/2026-11-10-ua-mtx-merge-t66b-step5b/verify-{net}.txt"), "w") as f:
    f.write(f"# NET-EVM-09: every contract deployed on chain {chain} ({net}), discovered from the books, broadcasts and getters\n")
    f.write(" | ".join(f"{k} {v}" for k, v in cnt.items()) + "\n")
    f.writelines(f"{s} | {n} | {a}" + (f" | {w}" if w else "") + "\n" for s, n, a, w in rows)
print(f"[{net}/verify] " + ", ".join(f"{k} {v}" for k, v in cnt.items()))
sys.exit(1 if cnt["fail"] else 0)
