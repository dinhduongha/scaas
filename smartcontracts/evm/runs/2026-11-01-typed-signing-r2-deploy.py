#!/usr/bin/env python3
"""typed-signing R2: a real `forge script` broadcast with `UARegistryLib` on anvil: every transaction, and which block gas limits the
gates and the chain let through. Anvil's readiness is its own "Listening on" line, read from its stdout; no polling.
  python3 -I runs/2026-11-01-typed-signing-r2-deploy.py > runs/2026-11-01-typed-signing-r2-deploy.txt
Flags as smartcontracts/scripts/deploy.sh. anvil does not charge EIP-8037: `sim` is forge's simulation, tx.gas / 1.05 (see
runs/2026-11-01-typed-signing-deploy-gas.sh)."""
import json, os, re, subprocess, threading

PORT = 31993
RPC = f"http://127.0.0.1:{PORT}"
KEY = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"  # anvil's dev account 0
SENDER = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
PROBE = "runs/2026-11-01-typed-signing-deploy-gas.s.sol"
ENV = dict(os.environ, PRIVATE_KEY=KEY, FOUNDRY_PROFILE="scaas-testnet", NOTICE_PERIOD="0",
           FOUNDRY_FS_PERMISSIONS='[{"access":"read-write","path":"./"}]')


class Anvil:
    def __init__(self, limit):
        self.limit = limit

    def __enter__(self):
        self.p = subprocess.Popen(["anvil", "--chain-id", "31337", "--hardfork", "amsterdam", "--gas-limit", str(self.limit),
                                   "--code-size-limit", "65536", "--port", str(PORT)], stdout=subprocess.PIPE, text=True)
        for line in self.p.stdout:
            if "Listening on" in line:
                break
        else:
            raise SystemExit("anvil ended before listening")
        threading.Thread(target=lambda: [None for _ in self.p.stdout], daemon=True).start()
        return self

    def __exit__(self, *a):
        self.p.terminate()
        self.p.wait()


def script(target, zether, broadcast):
    cmd = ["../../scripts/capped", "forge", "script", target, "--rpc-url", RPC, "--disable-code-size-limit",
           "--gas-estimate-multiplier", "105", "--sender", SENDER]
    if broadcast:
        cmd += ["--broadcast", "--slow"]
    return subprocess.run(cmd, env=dict(ENV, DEPLOY_ZETHER="true" if zether else "false"), stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True)


print(f"# at {subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD'], text=True).strip()}, profile scaas-testnet")
with Anvil(200_000_000):
    r = script(f"{PROBE}:DeployGasProbe", True, True)
    print(f"# broadcast rc={r.returncode} (200 M)")
    if r.returncode:
        print(r.stdout[-1500:])
d = f"broadcast/{os.path.basename(PROBE)}/31337"
j = json.load(open(f"{d}/run-latest.json"))
print("| # | tx | to | input B | anvil gasUsed (no 8037) | sim total (tx.gas/1.05) | tx.gas x1.05 |\n|---|---|---|---|---|---|---|")
reg = None
for i, (t, r) in enumerate(zip(j["transactions"], j["receipts"])):
    tx, n = t["transaction"], t.get("contractName") or "?"
    if t.get("function"):
        n += "." + t["function"].split("(")[0]
    g = int(tx["gas"], 16)
    print(f"| {i} | {n} | {t.get('contractAddress')} | {len(tx['input']) // 2:,} | {int(r['gasUsed'], 16):,} | {round(g / 1.05):,} | {g:,} |")
for l in (100_000_000, 80_000_000, 65_000_000, 60_000_000):
    for z in (False, True):
        with Anvil(l):
            r = script("script/Deploy.s.sol", z, True)
        why = re.search(r"block gas limit \d+ < \d+ needed to deploy the \w+", r.stdout)
        why = why[0] if why else next((x.strip()[:120] for x in r.stdout.splitlines() if "OutOfGas" in x or "intrinsic gas" in x), "")
        print(f"# Deploy.s.sol block limit {l:,} DEPLOY_ZETHER={z}: rc={r.returncode}: {why}")
