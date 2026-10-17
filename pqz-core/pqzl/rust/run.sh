#!/bin/sh
# pqzl (Rust port of the PQZL C core): every check in one job under scripts/capped, as ffi/run.sh:
#   scripts/capped pqz-core/pqzl/rust/run.sh <label>      -> pqzl/rust/runs/<label>-*.txt
# tests (native, release, the C oracle and the test hooks), the arithmetic KAT (kat_dump vs pqzl/kat's golden file),
# the keys KAT (keys_kat vs smartcontracts/vectors/pqz/pqz_kat.py --c-keys),
# clippy's float lint (no float in the crate), the wasm32 build (default features: no C).
set -u
cd "$(dirname "$0")"
L=runs/$1
mkdir -p runs
OUT() { echo "\$ $*"; "$@"; echo "[rc=$?]"; }

OUT cargo test -j2 --release --offline --features c-oracle,test-hooks -- --nocapture > "$L-test.txt" 2>&1
{
  echo "# arithmetic KAT: kat_dump vs the upstream LaZer golden file"
  OUT cargo build -j2 --release --offline --bin kat_dump
  ./target/release/kat_dump > target/kat-rust.json
  OUT python3 -I ../kat/check.py ../kat/lazer-3330e48.json target/kat-rust.json
  echo "# keys KAT: keys_kat (pqzl/test/pqz_keys_kat.c's JSON lines) vs the independent Python check"
  OUT cargo build -j2 --release --offline --bin keys_kat
  OUT sh -c './target/release/keys_kat 1000 > target/keys-rust.jsonl'
  OUT python3 -I ../../../smartcontracts/vectors/pqz/pqz_kat.py --c-keys target/keys-rust.jsonl
} >> "$L-test.txt" 2>&1

{
  echo "# clippy: no float arithmetic in the crate (default features, then with the oracle and the hooks)"
  OUT cargo clippy -j2 --release --offline --lib -- -D clippy::float_arithmetic
  OUT cargo clippy -j2 --release --offline --features c-oracle,test-hooks --lib --tests -- -D clippy::float_arithmetic
  echo "# wasm32 (default features)"
  OUT cargo build -j2 --release --offline --lib --target wasm32-unknown-unknown
} > "$L-build.txt" 2>&1

grep -hE "^test result|FAILED|panicked|^test .* (ok|FAILED)$|cases equal|MISMATCH|pqz_kat:|\[rc=" "$L-test.txt"
grep -hE "^(warning|error)|\[rc=" "$L-build.txt"
