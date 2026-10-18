#!/bin/sh
# D6 (port plan Task 12): the C core and this crate measured in ONE session on ONE machine, so the two sides are
# comparable (the t8-t10 Rust runs and the older C runs are not). One capped job, on an idle machine:
#   scripts/capped pqz-core/pqzl/rust/d6.sh <label>      -> pqzl/rust/runs/<label>/ (results-d6.md: the D6 table)
# Per relation (the six forms, then the eight built R_TXM shapes), one process per relation, core and backend, the C
# core then the crate each time (so drift hits both): native generic (NP proves, NV verifies), native verify_fast
# (2 / NF), wasm32 generic (NPW / NVW), wasm32 verify_fast (2 / NF/2), and the C wasm32 prove arena peak (the prover
# build without SV, as reproduce.sh). Then the crate's heap peak per operation (tests/memory.rs peak_per_op) and the
# wasm32 op 7 M = 8 question of Task 12: the wasm32 module is built with feature wasm-m8 (the limit lifted; its linear
# memory per shape is in rust-wasm-generic.jsonl), and native = wasm32 on every vector proof with M = 8 proved in
# wasm32 too. Also ffi_bench on both pqz-ffi backends (README §5.3). Sample sizes
# = reproduce.sh --full (NP= NV= NPW= NVW= NF= override).
set -u
cd "$(dirname "$0")" # pqzl/rust
mkdir -p "runs/$1"
D=$(pwd)/runs/$1
NP=${NP:-10} NV=${NV:-100} NPW=${NPW:-5} NVW=${NVW:-30} NF=${NF:-200}
C="--release --offline -j2"
CB=../build # the C core's build (pqzl/build.sh)
{
  (cd .. && ./build.sh all && SV=0 B=build/wasm-nosv ./build.sh wasm)
  cargo build $C --features bench --bin bench
  (cd wasm && cargo build $C --target wasm32-unknown-unknown --features pqzl/wasm-m8)
  echo "C: $(${CC:-clang} --version | head -1); Rust: $(rustc --version); node $(node --version)"
  echo "samples: NP=$NP NV=$NV NPW=$NPW NVW=$NVW NF=$NF"
} > "$D/build.txt" 2>&1 || { echo "d6: build failed, see $D/build.txt"; exit 1; }
for f in native-generic native-fast wasm-generic wasm-fast wasm-nosv; do : > "$D/c-$f.jsonl"; done
for f in native-generic native-fast wasm-generic wasm-fast; do : > "$D/rust-$f.jsonl"; done
: > "$D/rc.txt"
r() { "$@" || echo "rc=$? $*" >> "$D/rc.txt"; } # keep going; results.py counts the fails
for t in 0 1 2 3 4 5 6 7 8 9 10 11 12 13; do
  m=$((1 << t))
  r $CB/native/pqz_bench $NP $NV $m >> "$D/c-native-generic.jsonl"
  r target/release/bench $NP $NV $m >> "$D/rust-native-generic.jsonl"
  r env PQZ_VERIFY=fast $CB/native/pqz_bench 2 $NF $m >> "$D/c-native-fast.jsonl"
  r env PQZ_VERIFY=fast target/release/bench 2 $NF $m >> "$D/rust-native-fast.jsonl"
  r node ../test/run_wasm.mjs $NPW $NVW $m >> "$D/c-wasm-generic.jsonl"
  r node wasm/run_wasm.mjs $NPW $NVW $m >> "$D/rust-wasm-generic.jsonl"
  r env PQZ_VERIFY=fast node ../test/run_wasm.mjs 2 $((NF / 2)) $m >> "$D/c-wasm-fast.jsonl"
  r env PQZ_VERIFY=fast node wasm/run_wasm.mjs 2 $((NF / 2)) $m >> "$D/rust-wasm-fast.jsonl"
  r env PQZ_WASM_FILE=$CB/wasm-nosv/wasm/pqz.wasm node ../test/run_wasm.mjs 1 0 $m >> "$D/c-wasm-nosv.jsonl"
done
# the crate's heap peak per relation and operation (counting allocator; the C side's is the arena peak above)
r cargo test $C --test memory peak_per_op -- --exact --nocapture > "$D/rust-memory.txt" 2>&1
# README §5.3: the pqz-ffi path on both backends (ffi_bench, verify through the C ABI): the C backend is the opt-in one
# (pqzl-c), the Rust backend the default (pqzl-rust, CTR-PQZ-09)
(cd ../../ffi && r cargo run $C --no-default-features --features prove,test-hooks,pqzl-c --example ffi_bench 200) > "$D/c-ffi-bench.jsonl" 2>&1
(cd ../../ffi && r cargo run $C --features prove,test-hooks --example ffi_bench 200) > "$D/rust-ffi-bench.jsonl" 2>&1
# Task 12, wasm32 op 7 M = 8: both sides with WASM_MAX_LEGS = 8, so the M = 8 rows carry a proof digest on both
r cargo test $C --features wasm-m8 --test vectors wasm_replay_inputs > "$D/rust-m8-native.txt" 2>&1
cp target/wasm-replay/native.jsonl "$D/rust-m8-native-vectors.jsonl"
r env PQZL_WASM_MAX_LEGS=8 node wasm/run_vectors.mjs > "$D/rust-m8-wasm-vectors.jsonl" 2> "$D/rust-m8-wasm-vectors-stderr.txt"
python3 -I ../../artifact/results.py d6 "$D" > "$D/summary.txt"
cat "$D/rc.txt"
tail -n +$(grep -n '^## Checks' "$D/summary.txt" | cut -d: -f1) "$D/summary.txt"
