#!/usr/bin/env bash
# Classical Zether e2e (UA-3, CTR-ZTH-52; UA-6: BLS12-381 only, no `authRef`), script/ZetherE2E.s.sol through --ffi:
#   run()   (broadcast) six `zether-bls12381` UAs registered with clientkeys PoPs (UA-8: portable, relayed by the
#           deployer), a NORMAL_ZETHER token: shield, roll-over, a single transfer, a multi-recipient Compact M = 4 and a
#           BUNDLE M = 2 transfer with decoys, roll-over, unshield, the disclosure view; a WRAPPED_ZETHER token over a
#           test ERC-20 (MockERC20): wrap-shield, roll-over; every step checked by decryption (zether-cli) in the simulation;
#   check() (no broadcast) the final balances by decryption and the disclosure view against the chain;
#   then one row per transaction of the broadcast: gasUsed from its receipt, calldata bytes; and gasSplit(): each call
#   re-run isolated on a fork just before it for the regular / EIP-8037 state split (receipts carry only the sum).
# usage: scripts/e2e-zether.sh                         a fresh anvil (chain 31337, amsterdam, 64 KiB code, 200 M gas
#                                                      (the WRAPPED_ZETHER release needs ~110 M, NET-EVM-06), PORT default
#                                                      18545) and `deploy.sh evm` with DEPLOY_ZETHER=1 first
#        RPC=<url> PRIVATE_KEY=… scripts/e2e-zether.sh on a chain deployed with DEPLOY_ZETHER=1 (deployments/<chainid>.json;
#                                                      the SCaaS testnet: the deployer of that json; its releases must
#                                                      be past the factory's notice period)
# Needs forge, cast, jq, node (clients/clientkeys with its node_modules), anvil (local run), zether-cli
# (`cargo build --release --bin zether-cli` in clients/zether-prover; ZETHER_CLI overrides the path).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export ZETHER_CLI="${ZETHER_CLI:-$ROOT/clients/zether-prover/target/release/zether-cli}"
[ -x "$ZETHER_CLI" ] || { echo "no $ZETHER_CLI: cargo build --release --bin zether-cli (clients/zether-prover)" >&2; exit 2; }
if [ -z "${RPC:-}" ]; then
  PORT="${PORT:-18545}"
  RPC="http://127.0.0.1:$PORT"
  anvil --chain-id 31337 --hardfork amsterdam --gas-limit 200000000 --code-size-limit 65536 --port "$PORT" --silent &
  ANVIL=$!
  trap 'kill "$ANVIL" 2>/dev/null || true' EXIT
  for _ in $(seq 50); do cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 0.2; done
  export PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 # anvil's dev account 0
  DEPLOY_ZETHER=1 "$ROOT/smartcontracts/scripts/deploy.sh" evm "$RPC" --silent >/dev/null
fi
: "${PRIVATE_KEY:?PRIVATE_KEY (the deployer of deployments/<chainid>.json)}"
cd "$ROOT/smartcontracts/evm"
CHAIN="$(cast chain-id --rpc-url "$RPC")"
SENDER="$(cast wallet address --private-key "$PRIVATE_KEY")"
# forge's output, the Logs section only (all of it on a failure)
forge_logs() {
  local out
  if ! out="$(forge script script/ZetherE2E.s.sol --rpc-url "$RPC" --ffi --disable-code-size-limit "$@" 2>&1)"; then
    echo "$out" >&2; exit 1
  fi
  sed -n '/^== Logs ==/,/^$/{/^== Logs ==/d;/^$/d;s/^  //;p}' <<< "$out"
}
echo "## run (broadcast, chain $CHAIN, sender $SENDER)"
forge_logs --broadcast --slow --sender "$SENDER"
echo "## check (the chain's state)"
forge_logs --sig 'check()'
B="broadcast/ZetherE2E.s.sol/$CHAIN/run-latest.json"
echo "## gas per transaction ($B; gasUsed = the receipt's: regular + state on Nethermind, not on anvil)"
jq -r 'def hex: ltrimstr("0x") | explode | reduce .[] as $c (0; . * 16 + (if $c >= 97 then $c - 87 elif $c >= 65 then $c - 55 else $c - 48 end));
  (.receipts | map({key: .transactionHash, value: .}) | from_entries) as $r
  | .transactions[] | $r[.hash] as $x
  | "\(if $x.status == "0x1" then "ok  " else "FAIL" end)  tx \(.function // .transactionType) -> \(.contractAddress // .transaction.to): \(.hash) block \($x.blockNumber | hex) gasUsed \($x.gasUsed | hex) (calldata \((.transaction.input | length) / 2 - 1 | floor) B)"' "$B"
jq -e '[.receipts[].status] | all(. == "0x1")' "$B" >/dev/null
echo "## regular / state gas per call (each re-run isolated on a fork just before it; net = regular + state - refund = a Nethermind receipt's gasUsed)"
RPC="$RPC" forge_logs --sig 'gasSplit(string)' "$B" --isolate
echo "e2e-zether: passed"
