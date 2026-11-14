#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Group `pqzkeys` (spec 2026-11-13-pqz-three-keys §15.2): PqzKeys.s.sol in two forge runs on one node, `PqzKeysSetup.setup()`
# then, after ROLL_AGE + 1 blocks, `PqzKeysRoll.roll()` (its signed rollovers bind the pending slots as they are on chain).
# Each run's negatives checked by `coverage.py neg` against the chain at its end; both runs' transactions recorded for the
# matrix's table (records-<net>-pqzkeys.jsonl in matrix.sh's run dir). From smartcontracts/evm, under matrix.sh (local only:
# the blocks between the runs are mined by anvil). Short lines on stdout; forge's output in the git-ignored log.
# PQZW=1: the group `pqzwallet` the same way (PqzWallet.s.sol, PqzWalletSetup.setup() then PqzWalletRoll.roll()).
set -eu
: "${NET:?}" "${RPC:?}" "${ONCHAIN_K1:?}"
GN=pqzkeys SCR=PqzKeys TS=PqzKeysSetup TR=PqzKeysRoll
[ -z "${PQZW:-}" ] || GN=pqzwallet SCR=PqzWallet TS=PqzWalletSetup TR=PqzWalletRoll
if [ "$NET" != local ]; then
  echo "not run: $GN on $NET (local only: the run mines the blocks its rollovers wait for)"
  exit 0
fi
OUTD=${MATRIX_OUT:-runs/$(date +%Y-%m-%d)-matrix}
CHAIN=$(cast chain-id --rpc-url "$RPC")
B=broadcast/$SCR.s.sol/$CHAIN
R=$OUTD/records-$NET-$GN.jsonl
SENDER=$(cast wallet address --private-key "$ONCHAIN_K1")
L=$OUTD/$GN-$NET.log
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT INT TERM
mkdir -p "$OUTD"
: > "$L"
rm -f "$R"
rc=0 runs=
for p in setup roll; do
  if [ "$p" = roll ]; then
    for i in 1 2 3 4 5 6; do cast rpc --rpc-url "$RPC" evm_mine > /dev/null; done
  fi
  tc=$TR
  [ "$p" != setup ] || tc=$TS
  echo "[$NET/$GN] $p: forge $tc …"
  t0=$(date +%s)
  rm -f "$B/$p-latest.json"
  # the simulation runs the whole script as one call: its ML-DSA verifications and ~600 ops pass foundry.toml's 2^33 budget
  # (a late CREATE starved); the transactions sent still ask each its own estimate
  FOUNDRY_GAS_LIMIT=${PQZKEYS_SIM_GAS:-40000000000} ONCHAIN_NET=$NET forge script script/onchain/$SCR.s.sol --tc "$tc" --sig "$p()" --rpc-url "$RPC" --broadcast --slow \
    --ffi --sender "$SENDER" --disable-code-size-limit --gas-estimate-multiplier "${ONCHAIN_GAS_MULTIPLIER:-200}" \
    --out out/onchain-pqzkeys --cache-path cache/onchain-pqzkeys > "$T/$p.log" 2>&1 &
  F=$!
  i=0
  while kill -0 "$F" 2> /dev/null; do
    sleep 1
    i=$((i + 1))
    [ $((i % 30)) != 0 ] || echo "[$NET/$GN] … $p, $(($(date +%s) - t0))s"
  done
  wait "$F" || rc=$?
  cat "$T/$p.log" >> "$L"
  if [ "$rc" != 0 ]; then
    echo "[$NET/$GN] FAIL $p: $(grep -E '^Error|revert' "$T/$p.log" | tail -1 | cut -c1-160)"
    break
  fi
  runs="$runs $B/$p-latest.json"
  python3 -I script/onchain/coverage.py neg "$NET" $GN "$RPC" > "$T/neg.txt" 2>&1 || rc=1
  cat "$T/neg.txt" >> "$L"
  grep '^BAD' "$T/neg.txt" | sed "s/^/[$NET\/$GN] FAIL /" || true
  echo "[$NET/$GN] $p ok ($(($(date +%s) - t0))s), $(grep '^negatives' "$T/neg.txt" | tail -1)"
  [ ! -f "$R" ] || mv "$R" "$T/neg-$p.jsonl"
done
[ -n "$runs" ] || exit 1
python3 -I script/onchain/coverage.py forge "$NET" "deployments/onchain-$NET-$GN.json" $runs >> "$L" 2>&1
for f in "$T"/neg-*.jsonl; do [ ! -f "$f" ] || cat "$f" >> "$R"; done
python3 -I script/onchain/coverage.py trace "$NET" $GN "$RPC" >> "$L" 2>&1
echo "[$NET/$GN] $([ $rc = 0 ] && echo ok || echo FAIL) $(grep -c . "$R" 2> /dev/null || echo 0) records"
exit $rc
