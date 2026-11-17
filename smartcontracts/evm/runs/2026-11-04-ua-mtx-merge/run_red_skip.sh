#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# T0: the test recount on the merged tree (plan T0 step 10). <copy> = a scratch copy of smartcontracts/evm at M (src and
# test as at the M commit, lib/ real); passes of `forge build --format-json` until no error, each moving the files with an
# error to <copy>/_moved/ (red_skip.py). Then counts what moved and what is left.
#   runs/2026-11-04-ua-mtx-merge/run_red_skip.sh <copy> <capped>
set -uo pipefail
copy=$1; capped=$2
here=$(cd "$(dirname "$0")" && pwd)
export PATH="$HOME/.foundry/bin:$PATH"
rec="$here/red_skip.jsonl"; : > "$rec"
cd "$copy"
for pass in $(seq 1 40); do
  "$capped" forge build --format-json > "$here/red_skip-pass$pass.log" 2>&1
  python3 "$here/red_skip.py" "$copy" "$here/red_skip-pass$pass.log" "$rec" > "$here/red_skip-pass$pass.txt"
  rc=$?
  echo "pass $pass: $(head -1 "$here/red_skip-pass$pass.txt") (rc $rc)"
  [ $rc -eq 1 ] && break
  [ $rc -eq 2 ] && { echo "a src file has an error: stop"; break; }
done
