#!/bin/sh
# pqzl (Rust port of the PQZL C core): every check in one job under scripts/capped, as ffi/run.sh:
#   scripts/capped pqz-core/pqzl/rust/run.sh <label>      -> pqzl/rust/runs/<label>-*.txt
# tests (native, release, the C oracle and the test hooks; --no-fail-fast: every test binary runs and reports), the arithmetic KAT (kat_dump vs pqzl/kat's golden file),
# the keys KAT (keys_kat vs smartcontracts/vectors/pqz/pqz_kat.py --c-keys), the generated params (to_rust.py --check),
# the prover's proofs_fnv (bench natively, wasm/ in node) against the C core's runs, native = wasm32 on the vectors
# (wasm/run_vectors.mjs, with the wasm32 stack use), clippy's float lint (no float in the crate; also wasm/), the
# wasm32 build (default features: no C, no test entry points, no bench).
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

OUT cargo test -j2 --release --offline --no-fail-fast --features c-oracle,test-hooks,bench -- --nocapture > "$L-test.txt" 2>&1
{
  echo "# arithmetic KAT: kat_dump vs the upstream LaZer golden file"
  OUT cargo build -j2 --release --offline --features test-hooks --bin kat_dump
  ./target/release/kat_dump > target/kat-rust.json
  OUT python3 -I ../kat/check.py ../kat/lazer-3330e48.json target/kat-rust.json
  echo "# keys KAT: keys_kat (pqzl/test/pqz_keys_kat.c's JSON lines) vs the independent Python check"
  OUT cargo build -j2 --release --offline --features test-hooks --bin keys_kat
  OUT sh -c './target/release/keys_kat 1000 > target/keys-rust.jsonl'
  OUT python3 -I ../../../smartcontracts/vectors/pqz/pqz_kat.py --c-keys target/keys-rust.jsonl
  echo "# keys KAT through the Ctx methods (Ctx::keygen / enc_seed, the cached A): the same lines"
  OUT sh -c './target/release/keys_kat 1000 ctx > target/keys-rust-ctx.jsonl'
  OUT cmp target/keys-rust.jsonl target/keys-rust-ctx.jsonl
  OUT python3 -I ../../../smartcontracts/vectors/pqz/pqz_kat.py --c-keys target/keys-rust-ctx.jsonl
  echo "# params (plan D8): src/params = pqzl/params/to_rust.py's text from the committed headers"
  OUT python3 -I ../params/to_rust.py --check
  echo "# prover: bench proofs_fnv = the C core's (fs4-fnv-native: 5 5 63; fs4-fnv-native-16320: 2 2 16320, the op 7 shapes)"
  OUT cargo build -j2 --release --offline --features bench --bin bench
  OUT sh -c "./target/release/bench 5 5 63 > $L-bench-63.jsonl"
  FNV "bench 5 5 63" "$L-bench-63.jsonl" "b935013d 258418fb 85ab8aa8 cd5eccf7 b3cb29a2 06c6a4a5"
  OUT sh -c "./target/release/bench 2 2 16320 > $L-bench-16320.jsonl"
  FNV "bench 2 2 16320" "$L-bench-16320.jsonl" "e839a31e 4c63cef7 e88b6a9f 62e81d1d 40131675 ad7a159c 024ffaf8 f22cc134"
  echo "# specialised verifier: the same bench runs with PQZ_VERIFY=fast (honest and adversarial verify_fast, fails 0)"
  OUT sh -c "PQZ_VERIFY=fast ./target/release/bench 5 50 63 > $L-bench-fast-63.jsonl"
  FNV "bench fast 5 50 63" "$L-bench-fast-63.jsonl" "b935013d 258418fb 85ab8aa8 cd5eccf7 b3cb29a2 06c6a4a5"
  OUT sh -c "PQZ_VERIFY=fast ./target/release/bench 2 50 16320 > $L-bench-fast-16320.jsonl"
  FNV "bench fast 2 50 16320" "$L-bench-fast-16320.jsonl" "e839a31e 4c63cef7 e88b6a9f 62e81d1d 40131675 ad7a159c 024ffaf8 f22cc134"
  grep -H '"fails"' "$L-bench-63.jsonl" "$L-bench-16320.jsonl" "$L-bench-fast-63.jsonl" "$L-bench-fast-16320.jsonl"
  echo "# prover in wasm32: wasm/ in node = the C core's wasm32 run (fs4-fnv-wasm: 3 1 63)"
  OUT sh -c "cd wasm && cargo build -j2 --release --offline --target wasm32-unknown-unknown"
  OUT sh -c "node wasm/run_wasm.mjs 3 1 63 > $L-wasm-63.jsonl"
  FNV "wasm 3 1 63" "$L-wasm-63.jsonl" "c5d0e8c6 da580d8a 581fda3e 12c24f8f 1fc860f7 3ff37043"
  OUT sh -c "PQZ_VERIFY=fast node wasm/run_wasm.mjs 3 10 63 > $L-wasm-fast-63.jsonl"
  FNV "wasm fast 3 10 63" "$L-wasm-fast-63.jsonl" "c5d0e8c6 da580d8a 581fda3e 12c24f8f 1fc860f7 3ff37043"
  grep -H '"fails"' "$L-wasm-63.jsonl" "$L-wasm-fast-63.jsonl"
  echo "# native = wasm32 on the vectors: wasm/run_vectors.mjs's digest lines = tests/vectors.rs wasm_replay_inputs'"
  OUT sh -c "node wasm/run_vectors.mjs > $L-wasm-vectors.jsonl 2> $L-wasm-vectors-stderr.txt"
  cp target/wasm-replay/native.jsonl "$L-native-vectors.jsonl"
  if cmp -s "$L-native-vectors.jsonl" "$L-wasm-vectors.jsonl"; then echo "native = wasm32: $(wc -l < "$L-wasm-vectors.jsonl") digest lines equal"; else echo "native != wasm32 (MISMATCH)"; fi
  cat "$L-wasm-vectors-stderr.txt"
} >> "$L-test.txt" 2>&1

{
  echo "# clippy: no float arithmetic in the crate (the production build: default features; then with the oracle,"
  echo "# the hooks and the bench; then the wasm/ harness)"
  OUT cargo clippy -j2 --release --offline --lib -- -D clippy::float_arithmetic
  OUT cargo clippy -j2 --release --offline --features c-oracle,test-hooks,bench --lib --bins --tests -- -D clippy::float_arithmetic
  OUT cargo clippy -j2 --release --offline --manifest-path wasm/Cargo.toml --target wasm32-unknown-unknown -- -D warnings -D clippy::float_arithmetic
  echo "# the measurement build of wasm/ (d6.sh, reproduce.sh --multi-bench): features oversize and wasm-m8"
  OUT cargo clippy -j2 --release --offline --manifest-path wasm/Cargo.toml --target wasm32-unknown-unknown \
    --features pqzl/oversize,pqzl/wasm-m8 -- -D warnings -D clippy::float_arithmetic
  echo "# wasm32 (default features)"
  OUT cargo build -j2 --release --offline --lib --target wasm32-unknown-unknown
} > "$L-build.txt" 2>&1

grep -hE "^test result|FAILED|panicked|^test .* (ok|FAILED)$|cases equal|cases over the six|MISMATCH|pqz_kat:|to_rust.py|^fnv |\"fails\"|\[rc=|^native|^wasm32|R_TX prove|cold under|^keys \(" "$L-test.txt"
grep -hE "^(warning|error)|\[rc=" "$L-build.txt"
