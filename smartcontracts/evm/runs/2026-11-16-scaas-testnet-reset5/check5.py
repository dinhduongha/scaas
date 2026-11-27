# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""SCaaS testnet reset 5: reset 4's check4.py for one deploy set (owner 2026-11-16: option 2, one chain, two deploy sets;
the set's entries from deployments/scaas-testnet.json, deploybook.py set-book), and the set's ML-DSA mode: on mldsa-on each
registry ML-DSA kind (0x0130 / 0x0131 / 0x0134) on a MldsaVerifier whose PRECOMPILE() is the chain's precompile, on mldsa-off
each on PRECOMPILE() 0 (the expanded-key cache). As reset 4 (run from smartcontracts/evm, cast on PATH):
the DeploySend broadcast's receipts (count, status, gas asked / used), every address of deployments/scaas-testnet.json has code,
every row of the release list (Deploy.s.sol's simulation on the RPC's fork) has that runtime code hash on chain, and the
factory's releases per kind (0-13), the DEX and PqChat (class 3, kind 0). Prints rows; exit 1 on any bad row.
  python3 -I runs/2026-11-16-scaas-testnet-reset5/check5.py <rpc> <mldsa-on | mldsa-off>"""
import json, os, subprocess, sys

sys.path.insert(0, "script")
import deploybook  # noqa: E402

RPC, SET = sys.argv[1], deploybook.set_label(sys.argv[2])  # no default: the RPC and the set are always named
bad = 0


def cast(*a):
    return subprocess.run(["cast", *a, "--rpc-url", RPC], check=True, capture_output=True, text=True).stdout.strip()


def rpc(method, params):
    return json.loads(cast("rpc", method, *[json.dumps(p) if not isinstance(p, str) else p for p in params]))


def row(*c):
    print(" | ".join(str(x) for x in c))


b = json.load(open(f"broadcast/DeploySend.s.sol/7622/run-batches-{SET}.json"))
rs = b["receipts"]
asked = [int(t["transaction"]["gas"], 16) for t in b["transactions"]]
used = [int(r["gasUsed"], 16) for r in rs]
ok = sum(int(r["status"], 16) == 1 for r in rs)
blocks = [int(r["blockNumber"], 16) for r in rs]
row("deploy txs", len(b["transactions"]), "receipts", len(rs), "status 1", ok, "max asked", max(asked), "max used", max(used),
    "gasUsed total", sum(used), "blocks", f"{min(blocks)}-{max(blocks)}")
if not (len(rs) == len(b["transactions"]) == ok) or max(asked) > 60_000_000:
    bad += 1
    print("BAD: a receipt missing, a status 0 or an asked gas above 60 M")

d = deploybook.set_book(json.load(open("deployments/scaas-testnet.json")), SET)
row("set", SET, "mldsa_precompile", d.get("mldsa_precompile"), "releases", d["releases_json"])
bad += d.get("mldsa_precompile") != deploybook.SETS[SET]
g = rpc("eth_getBlockByNumber", ["0x0", False])["hash"]
row("chain_uid", d["chain_uid"], "genesis", g, "equal" if d["chain_uid"] == g else "BAD")
bad += d["chain_uid"] != g
for k in sorted(d):
    v = d[k]
    if not (isinstance(v, str) and v.startswith("0x") and len(v) == 42):
        continue
    n = (len(cast("code", v)) - 2) // 2
    row("book", k, v, f"{n} B", "ok" if n else "BAD: no code")
    bad += n == 0

rel = {k: v for k, v in json.load(open(d["releases_json"])).items() if isinstance(v, dict)}  # rows, not the header
eq = 0
for name in sorted(rel):
    r = rel[name]
    code = cast("code", r["address"])
    if code == "0x":
        row("release", name, r["address"], "EOA" if name in ("registrar", "admin") else "BAD: no code")
        bad += name not in ("registrar", "admin")  # the factory admin (round 3r) is the deployer EOA
        continue
    h = subprocess.run(["cast", "keccak", code], check=True, capture_output=True, text=True).stdout.strip()
    same = h.lower() == r["codeHash"].lower()
    eq += same
    if not same:
        bad += 1
        row("release", name, r["address"], f"{(len(code) - 2) // 2} B", "BAD: code hash", h, "want", r["codeHash"])
row("release list rows", len(rel), "code hash equal", eq)

f = d["token_factory"]
names = ["NORMAL", "WRAPPED", "NORMAL_ZETHER", "WRAPPED_ZETHER", "NORMAL_PQZ", "WRAPPED_PQZ", "RETIRED_6", "RETIRED_7",
         "NORMAL_REGULATED", "WRAPPED_REGULATED", "NORMAL_ZETHER_REGULATED", "WRAPPED_ZETHER_REGULATED",
         "NORMAL_PQZ_REGULATED", "WRAPPED_PQZ_REGULATED"]
for k, nm in enumerate(names):
    v = int(cast("call", f, "latestVersion(uint8)(uint64)", str(k)).split()[0])
    en = cast("call", f, "tokenKindEnabled(uint8)(bool)", str(k))
    impl = cast("call", f, "implementationOf(uint8,uint64)(address)", str(k), str(v)) if v else "-"
    good = nm.startswith("RETIRED") or (v >= 1 and en == "true")  # reset 4 (owner 2026-11-15): every token kind released
    row("kind", k, nm, "latest version", v, "enabled", en, "implementation", impl, "" if good else "BAD: no enabled release")
    bad += not good
v = int(cast("call", f, "latestDexVersion()(uint64)").split()[0])
row("dex", "latest version", v, "implementation", cast("call", f, "dexImplementationOf(uint64)(address)", str(v)) if v else "-")
v = int(cast("call", f, "latestClassVersion(uint16,uint16)(uint64)", "3", "0").split()[0])
row("class 3 kind 0 (PqChat)", "latest version", v, "enabled", cast("call", f, "classKindEnabled(uint16,uint16)(bool)", "3", "0"))
reg = d["ua_registry"]
for kind, nm in ((0x0142, "pqz-mlwe"), (0x0134, "mldsa87")):  # the gen-1 kind rule (owner 2026-11-15)
    en = cast("call", reg, "kindEnabled(uint16)(bool)", str(kind))
    cap = cast("call", reg, "verifyCap(uint16)(uint64)", str(kind)).split()[0]
    row("registry kind", hex(kind), nm, "enabled", en, "cap", cap, "" if en == "true" else "BAD: missing")
    bad += en != "true"
PRE = {0x0130: "0x000000000000000000000000000000005caa0012", 0x0131: "0x000000000000000000000000000000005caa0013",
       0x0134: "0x000000000000000000000000000000005caa0014"}
for kind, nm in ((0x0130, "mldsa44"), (0x0131, "mldsa65"), (0x0134, "mldsa87")):  # the set's ML-DSA mode
    v = d.get(f"{nm}_verifier")  # the verifier DeployBase gave the registry (the book; OnchainBase._mldsaCache reads it too)
    if not v:
        row("ml-dsa", hex(kind), nm, "BAD: no verifier in the book")
        bad += 1
        continue
    p = cast("call", v, "PRECOMPILE()(address)").lower()
    want = PRE[kind] if SET == "mldsa-on" else "0x" + "00" * 20
    row("ml-dsa", hex(kind), nm, "verifier", v, "PRECOMPILE()", p, "" if p == want else f"BAD: want {want}")
    bad += p != want
print(f"check5 {SET}:", "all checks passed" if not bad else f"{bad} BAD")
sys.exit(1 if bad else 0)
