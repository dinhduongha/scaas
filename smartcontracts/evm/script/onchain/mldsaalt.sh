#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Group `mldsaalt` (round 3zh, owner 2026-11-15, MD-8): script/onchain/MldsaAlt.s.sol, a throwaway gen-1 UA registry built by
# DeployBase in the OPPOSITE `MLDSA_PRECOMPILE` mode of the target's main deploy (its deploy JSON's `mldsa_precompile`; a book
# from before 3zh: `on`), with its own DEPLOY_SALT per run (F-10), and the same ML-DSA cases (cache parts, register, verify, the
# UAKeyNotCached refusals; on a precompile the cache's UAKeyCache refusal). For `on`, script/pq_verifiers.py (PQ_VERIFIERS=mldsa)
# builds the precompile verifiers first with that salt; where no ML-DSA precompile answers (anvil) the `on` side is not run, by
# name. From smartcontracts/evm, under matrix.sh (compiled there: out/onchain-mldsaalt). Short lines on stdout; full output in
# the git-ignored logs of run.sh / this group.
set -eu
: "${NET:?}" "${RPC:?}" "${DEPLOY_JSON:?}" "${PRIVATE_KEY:?}"
OUTD=${MATRIX_OUT:-runs/$(date +%Y-%m-%d)-matrix}
mkdir -p "$OUTD"
L=$OUTD/mldsaalt-$NET.log
main=$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1])).get("mldsa_precompile", "on"))' "$DEPLOY_JSON")
alt=on
[ "$main" = on ] && alt=off
MLDSAALT_SALT=$(cast keccak "scaas.onchain.mldsaalt.$NET.$(date +%s).$$")
export MLDSAALT_SALT MLDSA_PRECOMPILE=$alt
echo "[$NET/mldsaalt] main deploy MLDSA_PRECOMPILE=$main: the throwaway registry $alt"
if [ "$alt" = on ]; then
  PV=$(FOUNDRY_OUT=out/onchain-mldsaalt DEPLOY_SALT=$MLDSAALT_SALT PQ_VERIFIERS=mldsa python3 -I script/pq_verifiers.py "$RPC" 2>> "$L") \
    || { echo "[$NET/mldsaalt] FAIL pq_verifiers.py: $(tail -1 "$L")"; exit 1; }
  printf '%s\n' "$PV" | grep '^\[deploy\]' | sed "s/^/[$NET\/mldsaalt] /" || true
  n=0
  for kv in $(printf '%s\n' "$PV" | grep -E '^MLDSA(44|65|87)_VERIFIER=0x[0-9a-fA-F]{40}$'); do export "${kv?}"; n=$((n + 1)); done
  if [ "$n" = 0 ]; then
    echo "[$NET/mldsaalt] not run: the on side needs an ML-DSA precompile, none answers here"
    exit 0
  fi
fi
sh script/onchain/run.sh "$NET" MldsaAlt --tc MldsaAlt
