# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""SCaaS testnet reset 3 (reset 2's check2.py, books by the chain key), the read-only checks after the deploy (run from smartcontracts/evm, cast on PATH):
the DeploySend broadcast's receipts (count, status, gas asked / used), every address of deployments/scaas-testnet.json has code,
every row of the release list (Deploy.s.sol's simulation on the RPC's fork) has that runtime code hash on chain, and the
factory's releases per kind (0-13), the DEX and PqChat (class 3, kind 0). Prints rows; exit 1 on any bad row.
  python3 -I runs/2026-11-12-scaas-testnet-reset3/check3.py <rpc>"""
import json, subprocess, sys

RPC = sys.argv[1]  # no default: the RPC is always named
bad = 0


def cast(*a):
    return subprocess.run(["cast", *a, "--rpc-url", RPC], check=True, capture_output=True, text=True).stdout.strip()


def rpc(method, params):
    return json.loads(cast("rpc", method, *[json.dumps(p) if not isinstance(p, str) else p for p in params]))


def row(*c):
    print(" | ".join(str(x) for x in c))


b = json.load(open("broadcast/DeploySend.s.sol/7622/run-latest.json"))
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

d = json.load(open("deployments/scaas-testnet.json"))
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

rel = {k: v for k, v in json.load(open("deployments/scaas-testnet-t66b-releases.json")).items() if isinstance(v, dict)}  # rows, not the header
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
    row("kind", k, nm, "latest version", v, "enabled", en, "implementation", impl)
v = int(cast("call", f, "latestDexVersion()(uint64)").split()[0])
row("dex", "latest version", v, "implementation", cast("call", f, "dexImplementationOf(uint64)(address)", str(v)) if v else "-")
v = int(cast("call", f, "latestClassVersion(uint16,uint16)(uint64)", "3", "0").split()[0])
row("class 3 kind 0 (PqChat)", "latest version", v, "enabled", cast("call", f, "classKindEnabled(uint16,uint16)(bool)", "3", "0"))
print("check3:", "all checks passed" if not bad else f"{bad} BAD")
sys.exit(1 if bad else 0)
