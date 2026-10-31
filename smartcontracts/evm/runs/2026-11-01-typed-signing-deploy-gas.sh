#!/bin/bash
# typed-signing: the real gas of the deploy, by transaction, and which block gas limits hold it. Measurement only.
#   smartcontracts/evm/runs/2026-11-01-typed-signing-deploy-gas.sh > smartcontracts/evm/runs/2026-11-01-typed-signing-deploy-gas.txt
# Flags as smartcontracts/scripts/deploy.sh (--gas-estimate-multiplier 105), DEPLOY_ZETHER=true, plus WRAPPED_PQZ (.s.sol here).
# anvil 1.8.5 `--hardfork amsterdam` does NOT charge EIP-8037 (a 1,000 B creation = 253,190 gas at every --gas-limit: code
# deposit 200/byte; receipt, cumulative, block gasUsed and the balance decrease all agree), so its gasUsed is the classic
# figure. Forge's own EVM charges EIP-8037; a tx's `gas` is forge's simulation x the multiplier and anvil enforces
# tx.gas <= block gas limit, which is what a real chain checks. So: `sim` = tx.gas / 1.05 (regular + state), `state` / `frame`
# = vm.lastCallGas() of the replay (the call frame, without the intrinsic and calldata).
set -u
cd "$(dirname "$0")/.." || exit 2
PORT=31992 RPC=http://127.0.0.1:31992 S=runs/2026-11-01-typed-signing-deploy-gas.s.sol
export PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 # anvil's dev account 0
export FOUNDRY_PROFILE=scaas-testnet CAPPED_MEM=${CAPPED_MEM:-6G} NOTICE_PERIOD=0
export FOUNDRY_FS_PERMISSIONS='[{"access":"read-write","path":"./"}]' # the broadcast dry-run file, read by split()
SENDER=0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266
A=
anvil_at() { # <block gas limit>
  anvil --chain-id 31337 --hardfork amsterdam --gas-limit "$1" --code-size-limit 65536 --port $PORT --silent & A=$!
  for _ in $(seq 50); do cast chain-id --rpc-url $RPC >/dev/null 2>&1 && break; sleep 0.2; done
}
anvil_stop() { kill "$A" 2>/dev/null; wait "$A" 2>/dev/null; A=; }
trap anvil_stop EXIT
fs() { ../../scripts/capped forge script "$@" --rpc-url $RPC --disable-code-size-limit --gas-estimate-multiplier 105 --sender $SENDER; }

D=broadcast/$(basename $S)/31337
split_at() { # <block gas limit>: dry run + replay on a fresh chain
  anvil_at "$1"
  DEPLOY_ZETHER=true fs $S:DeployGasProbe --silent >/dev/null 2>&1
  rm -f "$D/dry-run/split.txt"
  fs $S:DeployGasProbe --sig 'split(string)' "$D/dry-run/run-latest.json" 2>&1 | grep -E '^ *SPLIT ' > "$D/dry-run/split.txt"
  anvil_stop
}
echo "# at $(git rev-parse --short HEAD), $(forge --version | head -1), solc via foundry.toml, profile scaas-testnet"
split_at 200000000
anvil_at 200000000
DEPLOY_ZETHER=true fs $S:DeployGasProbe --broadcast --slow --silent >/dev/null 2>&1; echo "# broadcast rc=$? (200 M)"
python3 -I - "$D" <<'P'
import json, re, sys, os
d = sys.argv[1]
j = json.load(open(f"{d}/run-latest.json"))
sp = {int(a): (int(b), int(c)) for a, b, c in (l.split()[1:] for l in open(f"{d}/dry-run/split.txt"))}
print("| # | tx | input B | anvil gasUsed (no 8037) | sim total (tx.gas/1.05) | state | regular (total-state) | tx.gas x1.05 |")
print("|---|---|---|---|---|---|---|---|")
for i, (t, r) in enumerate(zip(j["transactions"], j["receipts"])):
    tx = t["transaction"]; g = int(tx["gas"], 16); sim = round(g / 1.05); st = sp.get(i, (0, 0))[1]
    n = t.get("contractName") or "?"
    if t.get("function"): n += "." + t["function"].split("(")[0]
    print(f"| {i} | {n} | {len(tx['input']) // 2:,} | {int(r['gasUsed'], 16):,} | {sim:,} | {st:,} | {sim - st:,} | {g:,} |")
P
anvil_stop
for l in 100000000 60000000 36000000; do for z in false true; do
  anvil_at "$l"
  o=$(DEPLOY_ZETHER=$z fs script/Deploy.s.sol --broadcast --slow 2>&1); rc=$?
  n=$(cast block-number --rpc-url $RPC)
  why=$(grep -m1 -oE 'block gas limit [0-9]+ < [0-9]+ needed to deploy the [A-Za-z]+|intrinsic gas too high[^"]{0,60}' <<<"$o")
  [ -n "$why" ] || why=$(grep -m1 -B1 OutOfGas <<<"$o" | grep -oE 'new [A-Za-z0-9]+' | sed 's/^new \(.*\)/simulation: OutOfGas in the creation of \1/')
  echo "# Deploy.s.sol block limit $l DEPLOY_ZETHER=$z: rc=$rc, blocks mined $n: $why"
  anvil_stop
done; done
