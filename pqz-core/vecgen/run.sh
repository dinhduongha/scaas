#!/bin/sh
# P6e Task 11, the vectors (plan R4, D9, D13): one job under scripts/capped:
#   scripts/capped pqz-core/vecgen/run.sh <label> [write]          -> vecgen/runs/<label>-*.txt
# write: regenerate smartcontracts/vectors/pqz/*.json first. Then: pqz-vectors --check (a second generation, byte for
# byte, every proof replayed through the precompile path incl. both PQZL verifiers and Ligero), pqz_kat.py --check
# (independent Python), tamper.py (each checker catches changed leaves), the wasm32 replay (same proof bytes).
set -eu
cd "$(dirname "$0")"
R=runs/$1 V=../../smartcontracts/vectors/pqz O=../build/wasm
mkdir -p runs
{ (cd .. && ./build.sh native && ./build.sh wasm)
  # the freestanding wasm32 objects of libpqz with the C ABI exported (no bench), for replay_wasm.mjs
  ${WASM_LD:-wasm-ld-18} --no-entry --export=pqz_init --export=pqz_prove --export=pqz_verify_fast --export=__heap_base \
    -z stack-size=8388608 --stack-first --max-memory=4294967296 -o $O/vec_pqzl.wasm \
    $O/pqz_lazer.o $O/pqz_ntt.o $O/pqz_arena.o $O/pqz_rel.o $O/pqz_keys.o $O/pqz_sv.o $O/pqz_wasm_rt.o
  cargo build --release --offline
  (cd wasm && cargo build --release --offline --target wasm32-unknown-unknown)
  ls -l $O/vec_pqzl.wasm wasm/target/wasm32-unknown-unknown/release/pqz_vectors_wasm.wasm; } > "$R-build.txt" 2>&1
if [ "${2:-}" = write ]; then
  /usr/bin/time -v target/release/pqz-vectors > "$R-generate.txt" 2>&1
fi
/usr/bin/time -v target/release/pqz-vectors --check > "$R-check.txt" 2>&1 || echo "pqz-vectors --check rc=$?"
{ time python3 -I $V/pqz_kat.py --check; } > "$R-pqz-kat.txt" 2>&1 || echo "pqz_kat --check rc=$?"
python3 -I tamper.py > "$R-tamper.txt" 2>&1 || echo "tamper rc=$?"
node replay_wasm.mjs $O/vec_pqzl.wasm wasm/target/wasm32-unknown-unknown/release/pqz_vectors_wasm.wasm > "$R-wasm.txt" 2>&1 \
  || echo "wasm replay rc=$?"
(cd $V && wc -c *.json README.md pqz_kat.py) > "$R-sizes.txt"
grep -h -e "pqz-vectors" -e "DIFF" -e "EXTRA" "$R-check.txt"
grep -h -e "^pqz_kat" -e "^FAIL" -e "^real" "$R-pqz-kat.txt"
tail -1 "$R-tamper.txt"
tail -1 "$R-wasm.txt"
