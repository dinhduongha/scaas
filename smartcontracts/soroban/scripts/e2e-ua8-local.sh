#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# UA-8 local e2e on the pinned Protocol 30 quickstart (plan ua8-soroban B7, C15): a UA record copied EVM -> Soroban -> EVM.
# Build the Wasm and the EVM deploy (capped), start the quickstart and two anvil chains (taken down on every exit), then
# the node's `e2e_ua8` (capped, one slot, -j2). Refuses to start under 6 GB available (oomd kills the terminal).
# env: STELLAR_URL, STELLAR_PASSPHRASE, STELLAR_FRIENDBOT, STELLAR_BIN (as e2e-local.sh); QS_PORT (quickstart.sh);
# UA8_ANVIL_PORT (first of two, default 31981; each port is its chain id). usage: e2e-ua8-local.sh [cargo test filter]
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$here/../../.." && pwd)"
QS="$here/quickstart.sh"
port="${QS_PORT:-31980}"
a="${UA8_ANVIL_PORT:-31981}"
b=$((a + 1))
export STELLAR_BIN="${STELLAR_BIN:-stellar}"
export STELLAR_URL="${STELLAR_URL:-http://127.0.0.1:$port/rpc}"
export STELLAR_PASSPHRASE="${STELLAR_PASSPHRASE:-Standalone Network ; February 2017}"
export STELLAR_FRIENDBOT="${STELLAR_FRIENDBOT:-http://127.0.0.1:$port/friendbot}"
export UA8_EVM_A="$a,http://127.0.0.1:$a" UA8_EVM_B="$b,http://127.0.0.1:$b"

# the node's chain id on $1, empty when nothing answers there
chain_id() {
  curl -s -m 1 -X POST -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}' "http://127.0.0.1:$1" 2>/dev/null \
    | python3 -I -c 'import json,sys; print(int(json.load(sys.stdin)["result"], 16))' 2>/dev/null || true
}
for p in "$a" "$b"; do
  if [ -n "$(chain_id "$p")" ] || ss -ltn "sport = :$p" | grep -q LISTEN; then
    echo "e2e-ua8-local: port $p is taken: a stale anvil would answer for ours, not started" >&2; exit 5
  fi
done
avail=$(awk '/MemAvailable/ {print int($2 / 1048576)}' /proc/meminfo)
if [ "$avail" -lt 6 ]; then
  echo "e2e-ua8-local: ${avail} GB available, under 6 GB: not started" >&2; exit 4
fi
# the commit under test; "+uncommitted" when the tree (run logs aside) differs from it
rev="$(git -C "$ROOT" rev-parse --short HEAD)"
git -C "$ROOT" diff --quiet HEAD -- . ':!smartcontracts/soroban/runs' || rev="$rev+uncommitted"
echo "== e2e-ua8-local: $rev $(date -u +%FT%TZ); $("$STELLAR_BIN" --version | head -1); ${avail} GB available"
echo "== build Wasm"
CARGO_BUILD_JOBS=2 "$ROOT/scripts/capped" "$ROOT/smartcontracts/scripts/build.sh" soroban
echo "== EVM deploy build"
(cd "$ROOT/smartcontracts/evm" && FOUNDRY_PROFILE=scaas-testnet "$ROOT/scripts/capped" forge build script/Deploy.s.sol)

pids=()
down() {
  [ ${#pids[@]} -eq 0 ] || kill "${pids[@]}" 2>/dev/null || true
  "$QS" down
  # the anvils' books (NET-EVM-13: e2e_ua8.rs deploys each with DEPLOY_NAME=local-<chain id>-testnet)
  rm -f "$ROOT/smartcontracts/evm/deployments/local-$a-testnet.json" "$ROOT/smartcontracts/evm/deployments/local-$b-testnet.json"
}
echo "== quickstart"
"$QS" up   # exit 3 when a scaas-stellar container already exists: never ours to remove
trap down EXIT
trap 'exit 130' INT TERM
"$QS" wait
echo "== anvil $a, $b"
for p in "$a" "$b"; do
  anvil --chain-id "$p" --hardfork amsterdam --gas-limit 200000000 --code-size-limit 65536 --port "$p" --silent >/dev/null 2>&1 &
  pids+=($!)
  up=
  for _ in $(seq 1 50); do
    [ "$(chain_id "$p")" = "$p" ] && { up=1; break; }
    sleep 0.2
  done
  [ -n "$up" ] || { echo "e2e-ua8-local: anvil on $p did not answer as chain $p" >&2; exit 6; }
done

cd "$ROOT/scaas-node"
echo "== cargo test --test e2e_ua8"
CAPPED_SLOTS=1 "$ROOT/scripts/capped" cargo test -j2 --test e2e_ua8 -- --ignored --test-threads=1 --nocapture "$@"
echo "== e2e-ua8-local: PASS"
