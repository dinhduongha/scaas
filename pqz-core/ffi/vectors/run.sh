#!/bin/sh
# P6e Task 11, the vectors (plan R4, D9, D13), pqz-ffi's pqz-vectors binary: one job under scripts/capped:
#   scripts/capped pqz-core/ffi/vectors/run.sh <label> [write]     -> ffi/vectors/runs/<label>-*.txt
#   PQZL=rust|c ...: the PQZL backend (CTR-PQZ-09) explicitly, alone (as ../run.sh); default: Cargo.toml's
# write: regenerate smartcontracts/vectors/pqz/*.json, then rebuild (the self-test compiles in the REGISTER proofs).
# Then: pqz-vectors --check (a second generation, byte for byte; every proof and negative input through
# pqz_precompile, the generic PQZL verifier agreeing), pqz_kat.py --check (independent Python), tamper.py (each
# checker catches changed leaves), pqz-ffi's tests (selftest_vectors: the compiled-in proofs), the wasm32 replay (same
# proof bytes, valid). Exit 1 if any step fails.
set -u
cd "$(dirname "$0")/.."
R=vectors/runs/$1
mkdir -p vectors/runs
fail=0
# PQZ_SET: the parameter set (pqz-core/params/sets/<set>, one per build; default the v3 set n2048-kmax1024, pqz-ffi's
# default feature); another set or an explicit backend: --no-default-features --features pqzl-<backend>,set-<set>
S=${PQZ_SET:-n2048-kmax1024}
[ -f "../params/sets/$S/pqz_set.h" ] || { echo "PQZ_SET=$S: no pqz-core/params/sets/$S" >&2; exit 2; }
case ${PQZL:-} in
  rust | c) BF="--no-default-features --features pqzl-$PQZL,set-$S" ;;
  "") if [ "$S" = n2048-kmax1024 ]; then BF=; else BF="--no-default-features --features pqzl-rust,set-$S"; fi ;;
  *) echo "PQZL=$PQZL: rust or c" >&2; exit 2 ;;
esac
# the set's vectors: v3 at the canonical path (the contracts' until plan 5h Task 8d), another set below it
V=../../smartcontracts/vectors/pqz; [ "$S" = n2048-kmax1024 ] || V=$V/$S
export PQZ_SET=$S
echo "set $S, vectors $V; PQZL backend: ${PQZL:-the default feature} (cargo flags: ${BF:-none})" > "$R-build.txt"
step() { name=$1; shift; "$@" || { echo "FAILED: $name (rc=$?)"; fail=1; }; }
B="cargo build --release --offline $BF --features prove --bin pqz-vectors"
step build sh -c "$B >> $R-build.txt 2>&1"
if [ "${2:-}" = write ]; then
  step write sh -c "/usr/bin/time -v target/release/pqz-vectors > $R-generate.txt 2>&1"
  step rebuild sh -c "$B >> $R-build.txt 2>&1"
fi
step check sh -c "/usr/bin/time -v target/release/pqz-vectors --check > $R-check.txt 2>&1"
step pqz_kat sh -c "/usr/bin/time -f '%M KB' python3 -I ../../smartcontracts/vectors/pqz/pqz_kat.py --check > $R-pqz-kat.txt 2>&1"
step tamper sh -c "python3 -I vectors/tamper.py > $R-tamper.txt 2>&1"
step ffi-test sh -c "cargo test --release --offline $BF --features prove,test-hooks -- --test-threads 4 > $R-ffi-test.txt 2>&1"
step wasm-build sh -c "(cd wasm && cargo build --release --offline $BF --target wasm32-unknown-unknown) >> $R-build.txt 2>&1"
step wasm-replay sh -c "node vectors/replay_wasm.mjs wasm/target/wasm32-unknown-unknown/release/pqz_ffi_wasm.wasm $V > $R-wasm.txt 2>&1"
(cd $V && wc -c *.json README.md) > "$R-sizes.txt"
head -1 "$R-build.txt"
grep -h -e "pqz-vectors" -e "DIFF" -e "EXTRA" -e "self-test proofs" "$R-check.txt"
grep -h -e "^pqz_kat" -e "^FAIL" -e " KB" "$R-pqz-kat.txt"
tail -1 "$R-tamper.txt"
grep -h -e "^test result" -e FAILED "$R-ffi-test.txt"
tail -1 "$R-wasm.txt"
echo "run.sh $1: $([ $fail = 0 ] && echo ok || echo FAILED)"
exit $fail
