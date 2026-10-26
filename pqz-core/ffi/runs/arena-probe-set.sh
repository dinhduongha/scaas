#!/bin/sh
# per-set arena-exhaustion probe for tests/fault.rs on an already built test binary (R0 review fix round m8):
#   scripts/capped sh -c "cd pqz-core/ffi && runs/arena-probe-set.sh target/<set>-c/release/deps/fault-<hash> 14 16 18 ..."
b=$1; shift
for m in "$@"; do
  out=$(PQZ_FAULT_ARENA_MIB=$m $b --nocapture 2>&1); rc=$?
  echo "arena $m MiB: rc=$rc $(echo "$out" | grep -o -E 'panicked at [^ ]*|SIGILL|SIGSEGV|signal: [0-9]+' | head -1) $(echo "$out" | grep -E 'node faults' | head -1)"
done
