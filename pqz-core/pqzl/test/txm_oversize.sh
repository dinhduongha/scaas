#!/bin/sh
# R_TXM16 regression: the OVERSIZE bench (M = 16, measurement only) ends each shape in its own report on the default
# 8 MiB soft stack limit, native and wasm32. A shape proves (fails 0) or is refused with PQZ_ERR_INPUT (3: its encoding
# is over PQZ_MAX_PROOF, as the Rust core's Input); a signal or a wasm trap (no "fails" line) is a failure. Per set:
#   [PQZ_SET=<set>] scripts/capped pqz-core/pqzl/test/txm_oversize.sh
set -eu
cd "$(dirname "$0")/.."
B=build${PQZ_BUILD_TAG:+/$PQZ_BUILD_TAG}/ov
export B OVERSIZE=1 PQZ_ARENA_MB=3900 # the largest R_TXM16 arena peak: 3,830 MiB, n2048-kmax1024 (16, on)
./build.sh native > /dev/null
./build.sh wasm > /dev/null
ulimit -S -s 8192 # soft only: the bench raises its own limit
fail=0
one() { # <label> <command...>
  l=$1
  shift
  rc=0
  o=$("$@" 2>&1) || rc=$?
  if printf '%s\n' "$o" | grep -Eq '"fails": ?0\}' \
    || { printf '%s\n' "$o" | grep -Eq '"prove_rc": ?3' && printf '%s\n' "$o" | grep -Eq '"fails": ?[0-9]+\}'; }; then
    echo "ok   $l (rc=$rc): $(printf '%s\n' "$o" | grep -E '"proof_bytes_max"' | tail -1 | cut -c1-80)"
  else
    echo "FAIL $l (rc=$rc): $(printf '%s\n' "$o" | grep -E 'RuntimeError|rror:' | head -1 | cut -c1-100)"
    fail=1
  fi
}
for m in 16384 32768; do # (16, on), (16, off)
  one "native generic mask $m" "$B/native/pqz_bench" 1 1 $m
  one "native fast mask $m" env PQZ_VERIFY=fast "$B/native/pqz_bench" 1 1 $m
  one "wasm32 generic mask $m" env PQZ_WASM_FILE="$B/wasm/pqz.wasm" node test/run_wasm.mjs 1 1 $m
done
exit $fail
