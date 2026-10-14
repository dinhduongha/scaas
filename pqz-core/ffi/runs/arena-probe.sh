#!/bin/sh
# arena-exhaustion probe for tests/fault.rs: which fixed arena sizes fail gracefully (status 4) vs crash
#   scripts/capped pqz-core/ffi/runs/arena-probe.sh > pqz-core/ffi/runs/<label>-arena-probe.txt
cd "$(dirname "$0")/.."
cargo test --release --offline --features prove --test fault --no-run 2>&1 | tail -1
for m in 4 8 10 12 14 16 18 20 24 32 48 64; do
  PQZ_FAULT_ARENA_MIB=$m cargo test --release --offline --features prove --test fault -- --nocapture > target/run/probe.txt 2>&1
  rc=$?
  echo "arena $m MiB: rc=$rc $(grep -oE 'SIGSEGV|SIGABRT|node faults: [^;]*|panicked at [^ ]*|left: [^ ]*' target/run/probe.txt | tr '\n' ' ')"
done
