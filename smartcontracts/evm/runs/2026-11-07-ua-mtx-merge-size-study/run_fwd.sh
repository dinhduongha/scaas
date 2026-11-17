#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Token-side forward spikes (fwd_spike.py), one `forge build src` per move set, on a scratch worktree of HEAD.
# usage: run_fwd.sh <solc-output.json> <evm dir> <outdir> <name>=<domains> ...   (foreground; heavy steps through scripts/capped)
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd); solc_out=$1; evm=$2; outdir=$3; shift 3
mkdir -p "$outdir"
for v in "$@"; do
  name=${v%%=*}; doms=${v#*=}
  [[ -s "$outdir/fwd-$name.json" ]] && { echo "skip $name (done)"; continue; }
  git -C "$evm" checkout -q -- src; rm -f "$evm/src/FwdSpike.sol"
  python3 "$here/fwd_spike.py" "$solc_out" "$evm" "$doms" > "$outdir/fwd-$name.txt"
  (cd "$evm" && git add -N src/FwdSpike.sol && git diff -- src > "$outdir/fwd-$name.patch" && git reset -q src/FwdSpike.sol)
  (cd "$evm" && "$evm/../../scripts/capped" forge build src --sizes --json > "$outdir/fwd-$name.json.tmp" 2> "$outdir/fwd-$name.log")
  rc=$?
  git -C "$evm" checkout -q -- src; rm -f "$evm/src/FwdSpike.sol"
  [[ $rc -eq 0 ]] && mv "$outdir/fwd-$name.json.tmp" "$outdir/fwd-$name.json"
  echo "$name rc=$rc"
done
