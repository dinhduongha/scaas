#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# T66b Step 5b: run one group script (script/onchain/<Group>.s.sol) and record its transactions for coverage.py. From
# smartcontracts/evm, through scripts/capped, in the foreground:
#   ../../scripts/capped script/onchain/run.sh local <Group> [forge args]   an anvil fork of the SCaaS testnet RPC on
#                                                                           127.0.0.1:$PORT for this run only, stopped after
#   ../../scripts/capped script/onchain/run.sh 7622 <Group> [forge args]    the SCaaS testnet RPC itself (RPC_7622)
# Each group builds into its own out/onchain-<group> and cache/onchain-<group> (groups run side by side). Every
# transaction asks forge's estimate x ONCHAIN_GAS_MULTIPLIER / 100 (default 130, forge's own): the estimate is the
# simulated gasUsed after the storage refund, so a call that frees storage needs headroom above it (at 110 the
# GovernanceRouter's mtxCancelGrant ran out of gas on chain); 130 also covers anvil's low estimate of a CREATE.
# Output: <runs>/<group>-<net>.log (git-ignored) and the records.
set -eu
net=$1
g=$2
shift 2
RPC_7622=${RPC_7622:-http://127.0.0.1:8545}
OUTD=runs/2026-11-10-ua-mtx-merge-t66b-step5b
lg=$(echo "$g" | tr 'A-Z' 'a-z')
T=$(mktemp -d)
A=
trap '[ -n "$A" ] && kill "$A" 2>/dev/null; rm -rf "$T"' EXIT INT TERM
if [ "$net" = local ]; then
  PORT=${PORT:-18601}
  anvil --fork-url "${FORK_RPC:-$RPC_7622}" --port "$PORT" --hardfork amsterdam > "$T/anvil.log" 2>&1 &
  A=$!
  for i in $(seq 90); do
    cast chain-id --rpc-url "http://127.0.0.1:$PORT" > /dev/null 2>&1 && break
    [ "$i" -lt 90 ] || { echo "anvil did not start"; cat "$T/anvil.log"; exit 1; }
    sleep 1
  done
  RPC=http://127.0.0.1:$PORT
else
  RPC=$RPC_7622
fi
B=broadcast/$g.s.sol/$(cast chain-id --rpc-url "$RPC")/run-latest.json
rm -f "$B"
rc=0
ONCHAIN_NET=$net forge script "script/onchain/$g.s.sol" --rpc-url "$RPC" --broadcast --slow \
  --out "out/onchain-$lg" --cache-path "cache/onchain-$lg" --gas-estimate-multiplier "${ONCHAIN_GAS_MULTIPLIER:-130}" "$@" \
  > "$OUTD/$lg-$net.log" 2>&1 || rc=$?
tail -40 "$OUTD/$lg-$net.log"
if [ -f "$B" ]; then
  python3 -I script/onchain/coverage.py forge "$net" "deployments/onchain-$net-$lg.json" "$B"
  [ "$net" != local ] || python3 -I script/onchain/coverage.py trace "$net" "$lg" "$RPC"
  python3 -I script/onchain/coverage.py neg "$net" "$lg" "$RPC" || rc=1
fi
exit $rc
