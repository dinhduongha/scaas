#!/bin/sh
# pqzl (Rust port of the PQZL C core): every check in one job under scripts/capped, as ffi/run.sh:
#   scripts/capped pqz-core/pqzl/rust/run.sh <label>      -> pqzl/rust/runs/<label>-*.txt
# tests (native, release, the C oracle and the test hooks), the arithmetic KAT (kat_dump vs pqzl/kat's golden file),
# the keys KAT (keys_kat vs smartcontracts/vectors/pqz/pqz_kat.py --c-keys), the generated params (to_rust.py --check),
# the prover's proofs_fnv (bench natively, wasm/ in node) against the C core's runs, clippy's float lint (no float in
# the crate), the wasm32 build (default features: no C).
set -u
cd "$(dirname "$0")"
L=runs/$1
mkdir -p runs
OUT() { echo "\$ $*"; "$@"; echo "[rc=$?]"; }
# FNV label file want: the file's proofs_fnv values in order = want (the C core's, ../../research/pqzl-measure/runs)
FNV() {
  got=$(grep -o '"proofs_fnv": *"[0-9a-f]*"' "$2" | grep -o '[0-9a-f]\{8\}' | tr '\n' ' ')
  [ "$got" = "$3 " ] && echo "fnv $1: equal ($3)" || echo "fnv $1: MISMATCH: $got, want $3"
}

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
  echo "# params (plan D8): src/params = pqzl/params/to_rust.py's text from the committed headers"
  OUT python3 -I ../params/to_rust.py --check
  echo "# prover: bench proofs_fnv = the C core's (tx0c-fnv-native: 5 5 63; l3a-native-fast: 2 2 16320, the op 7 shapes)"
  OUT cargo build -j2 --release --offline --bin bench
  OUT sh -c "./target/release/bench 5 5 63 > $L-bench-63.jsonl"
  FNV "bench 5 5 63" "$L-bench-63.jsonl" "8bd69f2d b9bbf854 0a5976da b4aa2e26 c800f2c6 a29a5747"
  OUT sh -c "./target/release/bench 2 2 16320 > $L-bench-16320.jsonl"
  FNV "bench 2 2 16320" "$L-bench-16320.jsonl" "ee87e7a4 4294a892 4ff8974f cd21b056 bba9cd96 2fef961b 74c6be73 90c8fc70"
  echo "# specialised verifier: the same bench runs with PQZ_VERIFY=fast (honest and adversarial verify_fast, fails 0)"
  OUT sh -c "PQZ_VERIFY=fast ./target/release/bench 5 50 63 > $L-bench-fast-63.jsonl"
  FNV "bench fast 5 50 63" "$L-bench-fast-63.jsonl" "8bd69f2d b9bbf854 0a5976da b4aa2e26 c800f2c6 a29a5747"
  OUT sh -c "PQZ_VERIFY=fast ./target/release/bench 2 50 16320 > $L-bench-fast-16320.jsonl"
  FNV "bench fast 2 50 16320" "$L-bench-fast-16320.jsonl" "ee87e7a4 4294a892 4ff8974f cd21b056 bba9cd96 2fef961b 74c6be73 90c8fc70"
  grep -H '"fails"' "$L-bench-63.jsonl" "$L-bench-16320.jsonl" "$L-bench-fast-63.jsonl" "$L-bench-fast-16320.jsonl"
  echo "# prover in wasm32: wasm/ in node = the C core's wasm32 run (tx0c-fnv-wasm: 3 1 63)"
  OUT sh -c "cd wasm && cargo build -j2 --release --offline --target wasm32-unknown-unknown"
  OUT sh -c "node wasm/run_wasm.mjs 3 1 63 > $L-wasm-63.jsonl"
  FNV "wasm 3 1 63" "$L-wasm-63.jsonl" "e70b5dc4 9304299b 0ea1c7a6 f39a8e64 96a6e906 a0afafc7"
} >> "$L-test.txt" 2>&1

{
  echo "# clippy: no float arithmetic in the crate (default features, then with the oracle and the hooks)"
  OUT cargo clippy -j2 --release --offline --lib --bins -- -D clippy::float_arithmetic
  OUT cargo clippy -j2 --release --offline --features c-oracle,test-hooks --lib --tests -- -D clippy::float_arithmetic
  echo "# wasm32 (default features)"
  OUT cargo build -j2 --release --offline --lib --target wasm32-unknown-unknown
} > "$L-build.txt" 2>&1

grep -hE "^test result|FAILED|panicked|^test .* (ok|FAILED)$|cases equal|cases over the six|MISMATCH|pqz_kat:|to_rust.py|^fnv |\"fails\"|\[rc=" "$L-test.txt"
grep -hE "^(warning|error)|\[rc=" "$L-build.txt"
