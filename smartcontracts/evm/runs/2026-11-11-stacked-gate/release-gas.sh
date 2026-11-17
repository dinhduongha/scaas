#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# The stacked gate's release-gas row (NET-EVM-11): a fresh anvil whose block gas limit is 60 M (so no transaction may ask
# more), deploy.sh evm on it in the CTR-GOV-23 deploy order with every option (wrapped, regulated, Zether, PqChat) under the
# public gate (each release measured, (regular + state) x 1.05 within the block), then a table of every plan transaction:
# DeploySend's measured regular and state, the asked (regular + state) x 1.05, the limit sent, the receipt's status and
# gasUsed. The PQZ kinds 4, 5, 12, 13 are not deploy.sh's (script/pqz/e2e.py deploys them): the release-probe step and the
# matrix's pq group cover them. Run under scripts/capped (gates.sh release-gas); anvil stops on exit. Writes
# release-gas.txt beside this file. Local only; anvil's dev key 0.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE/../.."
PORT=${PORT:-18641}
RPC=http://127.0.0.1:$PORT
T=$(mktemp -d)
A=
trap '[ -z "$A" ] || kill "$A" 2> /dev/null; rm -rf "$T"' EXIT
trap 'exit 1' INT TERM
anvil --chain-id 31337 --hardfork amsterdam --gas-limit 60000000 --code-size-limit 131072 --port "$PORT" > "$T/anvil.log" 2>&1 &
A=$!
for i in $(seq 60); do
  cast chain-id --rpc-url "$RPC" > /dev/null 2>&1 && break
  [ "$i" -lt 60 ] || { cat "$T/anvil.log"; echo "anvil did not start"; exit 1; }
  sleep 1
done
echo "anvil up: chain 31337, block gas limit $(cast block latest --field gasLimit --rpc-url "$RPC"), port $PORT"
rm -f deployments/local-releasegas-testnet-releases.json
env PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 DEPLOY_NAME=local-releasegas-testnet \
  RELEASES_JSON=deployments/local-releasegas-testnet-releases.json RELEASES_WRITE=true \
  FOUNDRY_OUT=out/onchain-deploy FOUNDRY_CACHE_PATH=cache/onchain-deploy RELEASE_GAS_GATE=public CHAIN_CODE_LIMIT=131072 \
  DEPLOY_WRAPPED=1 DEPLOY_REGULATED=1 DEPLOY_ZETHER=1 DEPLOY_PQCHAT=1 NOTICE_PERIOD=0 DEMO_SUPPLY=1000000000000 VERIFY_TARGET=local \
  DEPLOY_SALT="$(cast keccak scaas.deploy.stacked-gate.release-gas)" \
  COMPLIANCE_ADMIN=0x0000000000000000000000004e59b44847b379578588920ca78fbf26c0b4956c \
  ../scripts/deploy.sh evm "$RPC" > "$T/deploy.out" 2>&1 || { tail -40 "$T/deploy.out"; echo "deploy.sh failed"; exit 1; }
grep -E '^ *(release gas|tx gas) \|' "$T/deploy.out" | sed 's/^ *//' > "$T/gas.txt"
python3 -I - "$T/gas.txt" broadcast/Deploy.s.sol/31337/dry-run/run-latest.json broadcast/DeploySend.s.sol/31337 "$HERE/release-gas.txt" <<'PY'
import glob, json, os, re, sys
gas, plan, sent, out = sys.argv[1:]
P = json.load(open(plan))["transactions"]
B = json.load(open(max(glob.glob(os.path.join(sent, "*latest.json")), key=os.path.getmtime)))
rc = B.get("receipts", [])
lines = open(gas).read().splitlines()
rel = [l for l in lines if l.startswith("release gas |")]
tx = {int(m[1]): (int(m[2]), int(m[3]), int(m[4])) for l in lines
      if (m := re.match(r"tx gas \| (\d+) \| regular (\d+) \| state (\d+) \| limit (\d+)", l))}
def what(t):
    n, f = t.get("contractName") or "", t.get("function") or ""
    a = t.get("arguments") or []
    if f.startswith("deployTokenImplementation"):
        return f"release kind {a[0]}" if a else "release"
    if f.startswith(("deployDexImplementation", "deployImplementation")):
        return f.split("(")[0]
    if f == "deploy" or not f:
        return n or "create2"
    return f"{n} {f.split('(')[0]}".strip()
rows, bad, mx = [], 0, (0, "")
for i, t in enumerate(P):
    r, s, lim = tx.get(i, (0, 0, 0))
    asked = (r + s) * 105 // 100
    ok = asked <= 60_000_000 and r * 105 // 100 < 1 << 24
    bad += not ok and i in tx
    if asked > mx[0]: mx = (asked, what(t))
    rows.append(f"{i} | {what(t)} | {r:,} | {s:,} | {asked:,} | {lim:,} | {'yes' if ok else 'NO'}" if i in tx else f"{i} | {what(t)} | done (not sent)")
st = [int(x["status"], 16) for x in rc]
with open(out, "w") as f:
    f.write("# release gas on anvil (chain 31337, block gas limit 60,000,000), deploy.sh evm, RELEASE_GAS_GATE=public, every option\n")
    f.write(f"plan txs {len(P)} | measured {len(tx)} | receipts {len(st)}, status 1: {sum(st)} | asked > 60 M or regular x 1.05 >= 2^24: {bad} | max asked {mx[0]:,} ({mx[1]})\n\n")
    f.write("## the public gate's release lines (Deploy.s.sol simulation)\n" + "\n".join(rel) + "\n\n")
    f.write("## every plan transaction (DeploySend: i | what | regular | state | asked = (regular + state) x 1.05 | limit sent | asked <= 60 M and regular x 1.05 < 2^24)\n")
    f.write("\n".join(rows) + "\n")
print(f"release-gas: plan {len(P)}, measured {len(tx)}, receipts {len(st)} ({sum(st)} status 1), over the line {bad}, max asked {mx[0]:,} ({mx[1]})")
sys.exit(1 if bad or sum(st) != len(st) or not st else 0)
PY
