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
R=vectors/runs/$1 V=../../smartcontracts/vectors/pqz
mkdir -p vectors/runs
fail=0
case ${PQZL:-} in
  rust | c) BF="--no-default-features --features pqzl-$PQZL" ;;
  "") BF= ;;
  *) echo "PQZL=$PQZL: rust or c" >&2; exit 2 ;;
esac
echo "PQZL backend: ${PQZL:-the default feature} (cargo flags: ${BF:-none})" > "$R-build.txt"
step() { name=$1; shift; "$@" || { echo "FAILED: $name (rc=$?)"; fail=1; }; }
B="cargo build --release --offline $BF --features prove --bin pqz-vectors"
step build sh -c "$B >> $R-build.txt 2>&1"
if [ "${2:-}" = write ]; then
  step write sh -c "/usr/bin/time -v target/release/pqz-vectors > $R-generate.txt 2>&1"
  step rebuild sh -c "$B >> $R-build.txt 2>&1"
fi
step check sh -c "/usr/bin/time -v target/release/pqz-vectors --check > $R-check.txt 2>&1"
step pqz_kat sh -c "/usr/bin/time -f '%e s %M KB' python3 -I $V/pqz_kat.py --check > $R-pqz-kat.txt 2>&1"
step tamper sh -c "python3 -I vectors/tamper.py > $R-tamper.txt 2>&1"
step ffi-test sh -c "cargo test --release --offline $BF --features prove,test-hooks -- --test-threads 4 > $R-ffi-test.txt 2>&1"
step wasm-build sh -c "(cd wasm && cargo build --release --offline $BF --target wasm32-unknown-unknown) >> $R-build.txt 2>&1"
step wasm-replay sh -c "node vectors/replay_wasm.mjs wasm/target/wasm32-unknown-unknown/release/pqz_ffi_wasm.wasm > $R-wasm.txt 2>&1"
(cd $V && wc -c *.json README.md pqz_kat.py) > "$R-sizes.txt"
head -1 "$R-build.txt"
grep -h -e "pqz-vectors" -e "DIFF" -e "EXTRA" -e "self-test proofs" "$R-check.txt"
grep -h -e "^pqz_kat" -e "^FAIL" -e " s .* KB" "$R-pqz-kat.txt"
tail -1 "$R-tamper.txt"
grep -h -e "^test result" -e FAILED "$R-ffi-test.txt"
tail -1 "$R-wasm.txt"
echo "run.sh $1: $([ $fail = 0 ] && echo ok || echo FAILED)"
exit $fail
