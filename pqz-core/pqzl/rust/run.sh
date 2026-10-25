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
OUT() { echo "\$ $*"; "$@"; r=$?; echo "[rc=$r]"; return $r; }
# the parameter set of every step (PQZ_SET, default the crate's default n2304-kmax4096; review R0 fix round m9: the
# tests, kat_dump, keys_kat, bench and wasm/ all build for it, in target/<set>/)
S=${PQZ_SET:-n2304-kmax4096}
export PQZ_SET=$S PQZ_BUILD_TAG=$S CARGO_TARGET_DIR=target/$S
if [ "$S" = n2304-kmax4096 ]; then KF=""; else KF="--no-default-features --features sv,set-$S"; fi
T=$CARGO_TARGET_DIR/release
kat_fail=0
# the FNV expectations: the C core's pqz_bench at the same set and arguments (C = Rust = wasm32 on the bench proofs,
# as the gate's fnv step; were the n2304 values of t8a-fnv-native before the R0 id bump)
(cd .. && ./build.sh native > /dev/null)
CB=../build/$S/native/pqz_bench
fnvs() { grep -o '"proofs_fnv": *"[0-9a-f]*"' "$1" | grep -o '[0-9a-f]\{8\}' | tr '\n' ' '; }
# FNV label file np nv mask: the file's proofs_fnv values in order = the C core's bench np nv mask
FNV() {
  want=$(PQZ_ARENA_MB=2048 $CB "$3" "$4" "$5" > "$L-c-$3-$4-$5.jsonl" && fnvs "$L-c-$3-$4-$5.jsonl")
  got=$(fnvs "$2")
  [ -n "$got" ] && [ "$got" = "$want" ] && echo "fnv $1: equal to C ($got)" || echo "fnv $1: MISMATCH: $got, C $want"
}

OUT cargo test -j2 --release --offline --no-fail-fast $KF --features c-oracle,test-hooks,bench -- --nocapture > "$L-test.txt" 2>&1
{
  echo "# arithmetic KAT: kat_dump vs the set's upstream LaZer golden file (params/sets/<set>/lazer-3330e48-kat.json;"
  echo "# review R2-C9: the file moved there in 15c929b3, and a failed check fails this job)"
  OUT cargo build -j2 --release --offline $KF --features test-hooks --bin kat_dump
  $T/kat_dump > $CARGO_TARGET_DIR/kat-rust.json
  if ! OUT python3 -I ../kat/check.py "../../params/sets/$S/lazer-3330e48-kat.json" $CARGO_TARGET_DIR/kat-rust.json; then kat_fail=1; fi
  echo "# keys KAT: keys_kat (pqzl/test/pqz_keys_kat.c's JSON lines) vs the independent Python check"
  OUT cargo build -j2 --release --offline $KF --features test-hooks --bin keys_kat
  OUT sh -c "$T/keys_kat 1000 > $CARGO_TARGET_DIR/keys-rust.jsonl"
  OUT python3 -I ../../../smartcontracts/vectors/pqz/pqz_kat.py --c-keys $CARGO_TARGET_DIR/keys-rust.jsonl
  echo "# keys KAT through the Ctx methods (Ctx::keygen / enc_seed, the cached A): the same lines"
  OUT sh -c "$T/keys_kat 1000 ctx > $CARGO_TARGET_DIR/keys-rust-ctx.jsonl"
  OUT cmp $CARGO_TARGET_DIR/keys-rust.jsonl $CARGO_TARGET_DIR/keys-rust-ctx.jsonl
  OUT python3 -I ../../../smartcontracts/vectors/pqz/pqz_kat.py --c-keys $CARGO_TARGET_DIR/keys-rust-ctx.jsonl
  echo "# params (plan D8): src/params = pqzl/params/to_rust.py's text from the committed headers"
  OUT python3 -I ../params/to_rust.py --check
  echo "# prover: bench proofs_fnv = the C core's pqz_bench at the set (5 5 63: the six P6e forms; 2 2 16320: the op 7 shapes)"
  OUT cargo build -j2 --release --offline $KF --features bench --bin bench
  OUT sh -c "$T/bench 5 5 63 > $L-bench-63.jsonl"
  FNV "bench 5 5 63" "$L-bench-63.jsonl" 5 5 63
  OUT sh -c "$T/bench 2 2 16320 > $L-bench-16320.jsonl"
  FNV "bench 2 2 16320" "$L-bench-16320.jsonl" 2 2 16320
  echo "# specialised verifier: the same bench runs with PQZ_VERIFY=fast (honest and adversarial verify_fast, fails 0)"
  OUT sh -c "PQZ_VERIFY=fast $T/bench 5 50 63 > $L-bench-fast-63.jsonl"
  FNV "bench fast 5 50 63" "$L-bench-fast-63.jsonl" 5 5 63
  OUT sh -c "PQZ_VERIFY=fast $T/bench 2 50 16320 > $L-bench-fast-16320.jsonl"
  FNV "bench fast 2 50 16320" "$L-bench-fast-16320.jsonl" 2 2 16320
  grep -H '"fails"' "$L-bench-63.jsonl" "$L-bench-16320.jsonl" "$L-bench-fast-63.jsonl" "$L-bench-fast-16320.jsonl"
  echo "# prover in wasm32: wasm/ (built for the set) in node = the C core's bench 3 1 63 at the set"
  OUT sh -c "cd wasm && cargo build -j2 --release --offline --target wasm32-unknown-unknown --no-default-features --features set-$S"
  W="PQZL_WASM_FILE=wasm/$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/pqzl_wasm.wasm"
  OUT sh -c "$W node wasm/run_wasm.mjs 3 1 63 > $L-wasm-63.jsonl"
  FNV "wasm 3 1 63" "$L-wasm-63.jsonl" 3 1 63
  OUT sh -c "$W PQZ_VERIFY=fast node wasm/run_wasm.mjs 3 10 63 > $L-wasm-fast-63.jsonl"
  FNV "wasm fast 3 10 63" "$L-wasm-fast-63.jsonl" 3 1 63
  grep -H '"fails"' "$L-wasm-63.jsonl" "$L-wasm-fast-63.jsonl"
  echo "# native = wasm32 on the vectors: wasm/run_vectors.mjs's digest lines = tests/vectors.rs wasm_replay_inputs'"
  OUT sh -c "$W node wasm/run_vectors.mjs target/wasm-replay-$S/in.txt > $L-wasm-vectors.jsonl 2> $L-wasm-vectors-stderr.txt"
  cp target/wasm-replay-$S/native.jsonl "$L-native-vectors.jsonl"  # tests/vectors.rs: target/wasm-replay-<PQZ_BUILD_TAG>
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
[ $kat_fail = 0 ] || { echo "arithmetic KAT: FAILED (set $S)"; exit 1; }
