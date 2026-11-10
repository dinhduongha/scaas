#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# T66b Step 5b: run one group script (script/onchain/<Group>.s.sol) and record its transactions for coverage.py. From
# smartcontracts/evm, through scripts/capped, in the foreground:
#   ONCHAIN_RPC=<url> … run.sh <target> <Group> [forge args]   the target's node (matrix.sh sets it: a fresh local chain,
#                                                              the SCaaS testnet, another testnet); DEPLOY_JSON its deploy
#   … run.sh local <Group>   without ONCHAIN_RPC: an anvil fork of FORK_RPC (default RPC_7622) on 127.0.0.1:$PORT for
#                            this run only (an option; the local target of matrix.sh needs no other chain)
#   … run.sh 7622 <Group>    without ONCHAIN_RPC: the SCaaS testnet RPC (RPC_7622)
# Each group builds into its own out/onchain-<group> and cache/onchain-<group> (groups run side by side). Every
# transaction asks forge's estimate x ONCHAIN_GAS_MULTIPLIER / 100 (default 130, forge's own): the estimate is the
# simulated gasUsed after the storage refund, so a call that frees storage needs headroom above it (at 110 the
# GovernanceRouter's mtxCancelGrant ran out of gas on chain); 130 also covers anvil's low estimate of a CREATE.
# ONCHAIN_REMOTE=1 (matrix.sh, a remote target: compiled under scripts/capped first, this under a 1 G scope): forge must
# print "No files changed, compilation skipped"; a recompile is killed and fails the group.
# Output: <runs>/<group>-<net>.log (git-ignored: forge's output, the records' and negatives' lines) and the records;
# stdout one short line per event (start, a heartbeat every 30 s, ok / FAIL with the named error).
set -eu
net=$1
g=$2
shift 2
RPC_7622=${RPC_7622:-http://127.0.0.1:8545}
OUTD=runs/2026-11-10-ua-mtx-merge-t66b-step5b
lg=$(echo "$g" | tr 'A-Z' 'a-z')
T=$(mktemp -d)
A=
F=
trap '[ -z "$F" ] || kill "$F" 2> /dev/null; [ -n "$A" ] && kill "$A" 2>/dev/null; rm -rf "$T"' EXIT INT TERM
if [ -n "${ONCHAIN_RPC:-}" ]; then
  RPC=$ONCHAIN_RPC
elif [ "$net" = local ]; then
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
CHAIN=$(cast chain-id --rpc-url "$RPC")
B=broadcast/$g.s.sol/$CHAIN/run-latest.json
L=$OUTD/$lg-$net.log
rm -f "$B"
rc=0
# stdout: short lines only ([net/group] start, a heartbeat every 30 s, ok / FAIL); forge's output in $L
echo "[$net/$lg] forge $g.s.sol on chain $CHAIN …"
t0=$(date +%s)
ONCHAIN_NET=$net forge script "script/onchain/$g.s.sol" --rpc-url "$RPC" --broadcast --slow \
  --out "out/onchain-$lg" --cache-path "cache/onchain-$lg" --gas-estimate-multiplier "${ONCHAIN_GAS_MULTIPLIER:-130}" "$@" \
  > "$L" 2>&1 &
F=$!
i=0
while kill -0 "$F" 2> /dev/null; do
  sleep 1
  i=$((i + 1))
  [ $((i % 30)) != 0 ] || echo "[$net/$lg] … forge, $(($(date +%s) - t0))s"
  # a remote target (ONCHAIN_REMOTE=1, matrix.sh: compiled under scripts/capped first): no compile here, fail closed
  if [ "${ONCHAIN_REMOTE:-0}" = 1 ] && grep -q '^Compiling' "$L"; then
    kill "$F" 2> /dev/null
    echo "[$net/$lg] FAIL forge recompiles (compile first)"
    break
  fi
done
wait "$F" || rc=$?
F=
if [ "${ONCHAIN_REMOTE:-0}" = 1 ] && ! grep -q 'No files changed, compilation skipped' "$L"; then
  rc=1
  echo "[$net/$lg] FAIL forge did not skip compilation: a remote run compiles under scripts/capped first"
fi
[ $rc = 0 ] || echo "[$net/$lg] FAIL forge: $(grep -E '^Error|revert' "$L" | tail -1 | cut -c1-160)"
if [ -f "$B" ]; then
  python3 -I script/onchain/coverage.py forge "$net" "deployments/onchain-$net-$lg.json" "$B" >> "$L" 2>&1
  [ "${ONCHAIN_TRACE:-$([ "$net" = local ] && echo 1)}" != 1 ] ||
    python3 -I script/onchain/coverage.py trace "$net" "$lg" "$RPC" >> "$L" 2>&1
  python3 -I script/onchain/coverage.py neg "$net" "$lg" "$RPC" >> "$L" 2>&1 || rc=1
  grep -E '^BAD' "$L" | sed "s/^/[$net\/$lg] FAIL /" || true
  echo "[$net/$lg] $([ $rc = 0 ] && echo ok || echo FAIL) $(grep -c . "$OUTD/records-$net-$lg.jsonl") records, \
$(grep '^negatives:' "$L" | tail -1) ($(($(date +%s) - t0))s)"
fi
exit $rc
