#!/bin/sh
# P6-ANON Track H round (docs/research/pqzh-ligero.md §15): op 7 R_TXM in Ligero, H1 (tests, cross-check) and H2
# (measurements, gate-B method). Run alone under the machine lock (so no other heavy job runs during the timings):
#   CARGO_BUILD_JOBS=2 scripts/capped pqz-core/pqzh/ligero/runs/txm.sh <tag>      (e.g. l16-txm)
# 1. cargo test (six forms as before + tests/multi.rs: every built shape)  2. the oversize shapes (M = 8, 16):
# tests/multi.rs with --features oversize  3. the production build: --no-default-features lib + unit tests
# 4. native FNV of the six P6e forms, seeds 0-4 (proofs unchanged: compare with runs/l15-tx0-proven.jsonl)
# 5. native bench, THE preset, every built op 7 shape: 10 proofs, 1,000 honest verifies, 12 x 80 mutations
# 6. the same for the oversize shapes (feature oversize; 3 proofs, 100 verifies, 12 x 10 mutations)
# 7. wasm32 build and run, every built shape (gate-B method): 2 proofs made in wasm32, 1,000 honest verifies, 12 x 4
# mutations  8. wasm32 with feature oversize (own target dir), every shape: 2 proofs, 100 verifies, 12 x 4 mutations
# 9. xcheck: op 7 statements / witnesses vs pqz_kat.py (kat_multi.py), the six forms vs pqz_bench.c (ligero.sh)
# 10. pqz-ffi still builds against the crate (cargo check, all targets).
set -u
cd "$(dirname "$0")/.."
tag=${1:-l16-txm}
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-2}
/usr/bin/time -v cargo test --release --offline -- --nocapture --test-threads 1 > runs/$tag-tests.txt 2>&1 || exit 1
cargo test --release --offline --features oversize --test multi -- --nocapture --test-threads 1 > runs/$tag-tests-oversize.txt 2>&1 || exit 1
cargo test --release --offline --no-default-features --lib > runs/$tag-nobench.txt 2>&1 || exit 1
runs/bench.sh $tag-native-fnv --rel all --regime proven --r431 1 --np 5 --nv 1 --nadv 1 || exit 1
runs/bench.sh $tag-proven --rel txm --regime proven --r431 1 --np 10 --nv 1000 --nadv 80 || exit 1
cargo build --release --offline --features oversize --bin ligero_bench --target-dir target/oversize 2> runs/$tag-oversize-build.txt || exit 1
/usr/bin/time -v target/oversize/release/ligero_bench --rel txm --regime proven --r431 1 --np 3 --nv 100 --nadv 10 \
  > runs/$tag-oversize.jsonl 2> runs/$tag-oversize-time.txt || exit 1
(cd wasm && cargo build --release --offline --target wasm32-unknown-unknown 2> ../runs/$tag-wasm-build.txt) || exit 1
/usr/bin/time -v node wasm/run_wasm.mjs 2 1000 4 1 1 txm > runs/$tag-proven-wasm.jsonl 2> runs/$tag-proven-wasm-time.txt || exit 1
(cd wasm && cargo build --release --offline --target wasm32-unknown-unknown --features oversize --target-dir target/oversize \
  2> ../runs/$tag-oversize-wasm-build.txt) || exit 1
PQZH_WASM_FILE=wasm/target/oversize/wasm32-unknown-unknown/release/pqzh_ligero_wasm.wasm /usr/bin/time -v \
  node wasm/run_wasm.mjs 2 100 4 1 1 txm > runs/$tag-oversize-wasm.jsonl 2> runs/$tag-oversize-wasm-time.txt || exit 1
mkdir -p target/xcheck/rust
cargo run --release --offline --quiet --example dump_setup -- target/xcheck/rust || exit 1
python3 -I ../xcheck/kat_multi.py target/xcheck/rust > runs/$tag-kat-multi.txt 2>&1 || exit 1
../xcheck/ligero.sh > runs/$tag-xcheck.txt 2>&1 || exit 1
(cd ../../ffi && cargo check --offline --all-targets) > runs/$tag-ffi-check.txt 2>&1 || exit 1
echo "txm.sh $tag: ok"
