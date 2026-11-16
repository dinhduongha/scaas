#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Group `pqzkeys` (spec 2026-11-13-pqz-three-keys §15.2): PqzKeys.s.sol in two forge runs on one node, `PqzKeysSetup.setup()`
# then, after ROLL_AGE + 1 blocks, `PqzKeysRoll.roll()` (its signed rollovers bind the pending slots as they are on chain).
# Each run's negatives checked by `coverage.py neg` against the chain at its end; both runs' transactions recorded for the
# matrix's table (records-<net>-pqzkeys.jsonl in matrix.sh's run dir). From smartcontracts/evm, under matrix.sh (local only:
# anvil mines the blocks between the runs; a remote chain makes them: the run waits for them, bounded). Short lines on stdout; forge's output in the git-ignored log.
# Owner 2026-11-16 (D1): first `PqzKeysPublic.pub()`, the rows with no ML-DSA signer and no R_REG proof (they send on any chain,
# the SCaaS testnet's set mldsa-off too); PQZK_PHASES names the runs (default `public setup roll`; a remote target `public`:
# its ML-DSA / 0x0142 rows are mldsa_on.py's, README-mldsa-on.md).
# PQZW=1: the group `pqzwallet` the same way (PqzWallet.s.sol, PqzWalletSetup.setup() then PqzWalletRoll.roll()).
set -eu
# --slow (one transaction per receipt) on a local chain only; a remote target sends each forge run at once (owner 2026-11-15:
# a run is one unit, the groups stay sequential)
SLOW=--slow; [ "${ONCHAIN_REMOTE:-0}" != 1 ] || SLOW=
. script/onchain/fee.sh
: "${NET:?}" "${RPC:?}" "${ONCHAIN_K1:?}"
GN=pqzkeys SCR=PqzKeys TS=PqzKeysSetup TR=PqzKeysRoll PH=${PQZK_PHASES:-public setup roll}
[ -z "${PQZW:-}" ] || GN=pqzwallet SCR=PqzWallet TS=PqzWalletSetup TR=PqzWalletRoll PH="setup roll"
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
# remote: the 30 s heartbeat counts the transactions on chain by the senders' nonce deltas (no --slow, runs never silent)
SENT_A=
if [ "${ONCHAIN_REMOTE:-0}" = 1 ]; then
  for k in "${PRIVATE_KEY:-}" "${ONCHAIN_K1:-}" "${ONCHAIN_K2:-}" "${ONCHAIN_K3:-}"; do
    [ -n "$k" ] && SENT_A="$SENT_A $(cast wallet address --private-key "$k")"
  done
  SENT_A=$(printf '%s\n' $SENT_A | sort -u | tr '\n' ' ')
fi
nonces() { for a in $SENT_A; do cast nonce --rpc-url "$RPC" "$a" 2> /dev/null || echo 0; done | paste -sd+ | bc 2> /dev/null || echo 0; }
SENT0=$( [ -n "$SENT_A" ] && nonces || echo 0)
sent() { [ -n "$SENT_A" ] && echo ", $(( $(nonces) - SENT0 )) tx on chain" || true; }
rc=0 runs=
for p in $PH; do
  if [ "$p" = roll ]; then
    if [ "$NET" = local ]; then
      for i in 1 2 3 4 5 6; do cast rpc --rpc-url "$RPC" evm_mine > /dev/null; done
    else
      # a remote chain: wait for 6 new blocks (ROLL_AGE + 1), at most 20 tries of 10 s (Clique period 5 s: ~30 s)
      h0=$(cast block-number --rpc-url "$RPC"); w=0
      while [ "$(cast block-number --rpc-url "$RPC")" -lt $((h0 + 6)) ]; do
        w=$((w + 1)); [ "$w" -le 20 ] || { echo "[$NET/$GN] FAIL roll: 6 blocks did not come in 200 s"; exit 1; }
        sleep 10
      done
      echo "[$NET/$GN] 6 blocks past setup ($h0 -> $(cast block-number --rpc-url "$RPC"))"
    fi
  elif [ "$NET" = local ]; then
    # a fresh head: anvil mines on demand, so after a long group before this one (pq on the copy: ~40 min) the latest
    # block's timestamp is stale, and the simulation's `block.timestamp + 1 hours` (a pause's end) is already past on chain
    cast rpc --rpc-url "$RPC" evm_mine > /dev/null
  fi
  tc=$TR sig="$p()"
  [ "$p" != setup ] || tc=$TS
  [ "$p" != public ] || tc=PqzKeysPublic sig="pub()"
  bf=${sig%"()"} # forge's broadcast file: the entry's name
  echo "[$NET/$GN] $p: forge $tc …"
  t0=$(date +%s)
  rm -f "$B/$bf-latest.json"
  remote_fee "$RPC" # a remote target: a fee with headroom (fee.sh)
  # the simulation runs the whole script as one call: its ML-DSA verifications and ~600 ops pass foundry.toml's 2^33 budget
  # (a late CREATE starved); the transactions sent still ask each its own estimate
  FOUNDRY_GAS_LIMIT=${PQZKEYS_SIM_GAS:-40000000000} ONCHAIN_NET=$NET forge script script/onchain/$SCR.s.sol --tc "$tc" --sig "$sig" --rpc-url "$RPC" --broadcast $SLOW \
    --ffi --sender "$SENDER" --disable-code-size-limit --gas-estimate-multiplier "${ONCHAIN_GAS_MULTIPLIER:-200}" \
    --out out/onchain-pqzkeys --cache-path cache/onchain-pqzkeys > "$T/$p.log" 2>&1 &
  F=$!
  i=0
  while kill -0 "$F" 2> /dev/null; do
    sleep 1
    i=$((i + 1))
    [ $((i % 30)) != 0 ] || echo "[$NET/$GN] … $p, $(($(date +%s) - t0))s$(sent)"
  done
  wait "$F" || rc=$?
  cat "$T/$p.log" >> "$L"
  if [ "$rc" != 0 ]; then
    echo "[$NET/$GN] FAIL $p: $(grep -E '^Error|revert' "$T/$p.log" | tail -1 | cut -c1-160)"
    break
  fi
  runs="$runs $B/$bf-latest.json"
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
