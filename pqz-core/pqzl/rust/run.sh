#!/bin/sh
# pqzl (Rust port of the PQZL C core): every check in one job under scripts/capped, as ffi/run.sh:
#   scripts/capped pqz-core/pqzl/rust/run.sh <label>      -> pqzl/rust/runs/<label>-*.txt
# tests (native, release, the C oracle and the test hooks), clippy's float lint (no float in the crate), the wasm32
# build (default features: no C).
set -u
cd "$(dirname "$0")"
L=runs/$1
mkdir -p runs
OUT() { echo "\$ $*"; "$@"; echo "[rc=$?]"; }

OUT cargo test -j2 --release --offline --features c-oracle,test-hooks -- --nocapture > "$L-test.txt" 2>&1

{
  echo "# clippy: no float arithmetic in the crate (default features, then with the oracle and the hooks)"
  OUT cargo clippy -j2 --release --offline --lib -- -D clippy::float_arithmetic
  OUT cargo clippy -j2 --release --offline --features c-oracle,test-hooks --lib --tests -- -D clippy::float_arithmetic
  echo "# wasm32 (default features)"
  OUT cargo build -j2 --release --offline --lib --target wasm32-unknown-unknown
} > "$L-build.txt" 2>&1

grep -hE "^test result|FAILED|panicked|^test .* (ok|FAILED)$|\[rc=" "$L-test.txt"
grep -hE "^(warning|error)|\[rc=" "$L-build.txt"
