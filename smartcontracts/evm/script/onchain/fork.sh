#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# T66b Step 5b: <cmd> against an anvil fork of the SCaaS testnet RPC (FORK_RPC, default RPC_7622) on 127.0.0.1:$PORT,
# started for this command only and stopped after; RPC is exported to <cmd>. From smartcontracts/evm, through
# scripts/capped, in the foreground:  PORT=18615 ../../scripts/capped script/onchain/fork.sh <cmd> [args]
set -eu
command -v anvil > /dev/null || PATH=$HOME/.foundry/bin:$PATH
RPC_7622=${RPC_7622:-http://127.0.0.1:8545}
PORT=${PORT:-18615}
T=$(mktemp -d)
A=
trap '[ -n "$A" ] && kill "$A" 2>/dev/null; rm -rf "$T"' EXIT INT TERM
anvil --fork-url "${FORK_RPC:-$RPC_7622}" --port "$PORT" --hardfork amsterdam > "$T/anvil.log" 2>&1 &
A=$!
for i in $(seq 90); do
  cast chain-id --rpc-url "http://127.0.0.1:$PORT" > /dev/null 2>&1 && break
  [ "$i" -lt 90 ] || { echo "anvil did not start"; cat "$T/anvil.log"; exit 1; }
  sleep 1
done
export RPC=http://127.0.0.1:$PORT
"$@"
