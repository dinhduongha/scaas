#!/bin/sh
# P6-SV differential test runs (pqz_verify against pqz_verify_fast, test/pqz_sv_diff.c), under scripts/capped:
# the portable build and the optional x86-64-v3 build, deterministic seeds; JSON lines into sv/runs/<label>-*.jsonl.
#   sv/diff.sh <label> [n_reg n_tx muts fuzz]        (defaults 40 20 3 20; the x86-64-v3 run uses half)
set -eu
cd "$(dirname "$0")/.."
CAPPED=${CAPPED:-$(git rev-parse --show-toplevel)/scripts/capped}
L=$1 NR=${2:-40} NT=${3:-20} MU=${4:-3} FZ=${5:-20}
./build.sh native >/dev/null 2>&1
./build.sh native-x86v3 >/dev/null 2>&1
$CAPPED build/native/pqz_sv_diff "$NR" "$NT" "$MU" 1 "$FZ" > "sv/runs/$L-portable.jsonl" || echo "portable rc=$?"
$CAPPED build/native-x86v3/pqz_sv_diff $((NR / 2)) $((NT / 2)) "$MU" 2 "$FZ" > "sv/runs/$L-x86v3.jsonl" || echo "x86v3 rc=$?"
grep -h -e '"seed"' -e '"mismatch"' -e prg -e arena "sv/runs/$L-portable.jsonl" "sv/runs/$L-x86v3.jsonl"
