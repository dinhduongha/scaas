#!/bin/sh
# Rerun LaZer's codegen on every relation spec into <out dir> and diff each header against the checked-in one
# (P6e D1: the headers are reproducible; new specs, e.g. tx0, are generated there and copied by hand):
#   scripts/capped pqz-core/pqzl/params/regen.sh <LaZer 3330e48 checkout> <out dir> [specs] > pqz-core/pqzl/params/codegen-<label>.txt
set -u
cd "$(dirname "$0")/.."
LZ=$(cd "$1" && pwd) OUT=$2
shift 2
[ $# -gt 0 ] || set -- reg tx burn ds dr
mkdir -p "$OUT"
echo "LaZer $(git -C "$LZ" rev-parse HEAD); image $(grep -o 'sha256:[0-9a-f]*' params/codegen/run.sh)"
rc=0
for r in "$@"; do
  t0=$(date +%s)
  params/codegen/run.sh "$LZ" params/${r}_params.sage > "$OUT/pqz_${r}_params.h" 2> "$OUT/$r.err" || rc=1
  echo "== $r: $(( $(date +%s) - t0 )) s, $(wc -c < "$OUT/pqz_${r}_params.h") B, sha256 $(sha256sum < "$OUT/pqz_${r}_params.h" | cut -c1-16)"
  if [ -f params/pqz_${r}_params.h ]; then
    if cmp -s params/pqz_${r}_params.h "$OUT/pqz_${r}_params.h"; then echo "   identical to params/pqz_${r}_params.h"
    else echo "   DIFFERENT from params/pqz_${r}_params.h"; diff params/pqz_${r}_params.h "$OUT/pqz_${r}_params.h" | head -40; rc=1; fi
  else echo "   new (no checked-in header)"; fi
  sed 's/^/   stderr: /' "$OUT/$r.err" | head -20
done
echo "regen rc=$rc"
exit $rc
