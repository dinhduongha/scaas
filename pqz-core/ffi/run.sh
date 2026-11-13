#!/bin/sh
# pqz-ffi (P6e Task 7): every check in one job under scripts/capped:
#   scripts/capped pqz-core/ffi/run.sh <label>           -> ffi/runs/<label>-*.txt / .jsonl
#   PQZL=rust|c scripts/capped pqz-core/ffi/run.sh <label>    the PQZL backend (CTR-PQZ-09) explicitly, alone
#                                                           (--no-default-features --features pqzl-<backend>)
# tests (native, release, feature prove; the crate's unit tests without it), the verify-only cdylib and its symbol
# scans, the C smoke test against pqz_ffi.h, the wasm32 builds and the native = wasm32 digest diff, the bench.
# Exit 1 if any part fails (review 3w u3-1): every command's status counts, the counts that must be 0 are checked, a
# native != wasm32 digest diff fails.
set -u
cd "$(dirname "$0")"
. ../resume.sh # under gate.sh: a block that ran to its end at this tree is skipped (owner 2026-10-23)
# PQZ_BUILD_TAG (gate.sh: the set): cargo target, wasm target and work files under target/<tag>/ so concurrent gates of
# different sets never share them; unset: the crate's default target/ (as before)
if [ -n "${PQZ_BUILD_TAG:-}" ]; then export CARGO_TARGET_DIR=$(pwd)/target/$PQZ_BUILD_TAG; WT=$CARGO_TARGET_DIR-wasm; else WT=$(pwd)/wasm/target; fi
TD=${CARGO_TARGET_DIR:-$(pwd)/target}
L=runs/$1 X=$TD/run
mkdir -p runs "$X"
rm -f "$X/fill.txt"
OUT() { echo "\$ $*"; "$@"; _r=$?; echo "[rc=$_r]"; return $_r; }
# ZERO <label> <count>: prints the count, fails unless it is 0
ZERO() { echo "$1: $2"; [ "$2" = 0 ] || { echo "[rc=1] $1 must be 0"; return 1; }; }
fail=0
# PQZ_SET: the parameter set (pqz-core/params/sets/<set>, one per build; default n2304-kmax4096, pqz-ffi's default
# feature since plan 5h Task 8d); another set or an explicit backend: --no-default-features --features pqzl-<backend>,set-<set>
S=${PQZ_SET:-n2304-kmax4096}
[ -f "../params/sets/$S/pqz_set.h" ] || { echo "PQZ_SET=$S: no pqz-core/params/sets/$S" >&2; exit 2; }
case ${PQZL:-} in
  rust | c) BF="--no-default-features --features pqzl-$PQZL,set-$S" ;;
  "") if [ "$S" = n2304-kmax4096 ]; then BF=; else BF="--no-default-features --features pqzl-rust,set-$S"; fi ;;
  *) echo "PQZL=$PQZL: rust or c" >&2; exit 2 ;;
esac

ffi_test() {
f=0
{
  echo "# PQZL backend: ${PQZL:-the default feature} (cargo flags: ${BF:-none})"
  OUT cargo test --release --offline $BF --lib || f=1
  PQZ_FFI_DIGESTS=$X/native.jsonl PQZ_FFI_FILL_OUT=$X/fill.txt OUT cargo test --release --offline $BF --features prove,test-hooks -- --nocapture --test-threads 4 || f=1
} > "$L-test.txt" 2>&1
return $f
}
part ffi/test ffi_test || fail=1
cp "$X/fill.txt" "$L-fill.txt" 2>/dev/null # C backend only (fill_determinism)

ffi_native() {
f=0
{
  echo "# verify-only build (no prove, no test-hooks): libpqz_ffi.so, and the C core archive if build.rs compiled one"
  OUT cargo build --release --offline $BF || f=1
  ZERO "test hooks in the production cdylib (must be 0)" "$(strings -a $TD/release/libpqz_ffi.so | grep -cE 'TEST_ARENA|TEST_FAIL_WORKER')" || f=1
  # positive check (fails closed): the C core is in the build exactly when pqz-ffi's feature pqzl-c is on
  F=$(cargo tree --offline $BF -e features -i pqz-ffi --prefix none) || { echo "cargo tree -e features -i pqz-ffi: [rc=1]"; f=1; }
  case $F in
    *'pqz-ffi feature "pqzl-c"'*)
      A=$(ls -t $TD/release/build/pqz-ffi-*/out/libpqz.a | head -1)
      OUT ../pqzl/check_symbols.sh "$A" || f=1 ;;
    *'pqz-ffi feature "pqzl-rust"'*)
      echo "C core in this build: none (feature pqzl-c off, pqzl-rust on: build.rs compiles no C)"
      echo "\$ cargo tree $BF -e normal,build --prefix none"; cargo tree --offline $BF -e normal,build --prefix none | sort -u ;;
    *) echo "C core in this build: unknown (no PQZL backend feature in cargo tree) [rc=1]"; f=1 ;;
  esac
  SO=$TD/release/libpqz_ffi.so
  OUT sha256sum "$SO" || f=1
  echo "\$ readelf -d $SO | grep NEEDED"; readelf -d "$SO" | grep NEEDED
  echo "\$ nm -D --undefined-only $SO"; nm -D --undefined-only "$SO"
  echo "\$ nm -D --defined-only $SO | grep ' T '"; nm -D --defined-only "$SO" | grep ' T '
  echo "# GMP / MPFR / HEXL names or strings (glic/absence.sh's pattern), libm and float imports"
  ZERO "symbols /gmp|mpfr|hexl/i" "$(nm -A "$SO" 2>/dev/null | grep -ciE 'gmp|mpfr|hexl')" || f=1
  ZERO "strings /gmp|mpfr|hexl/i" "$(strings -a "$SO" | grep -ciE 'gmp|mpfr|hexl')" || f=1
  ZERO "libm-style imports" "$(nm -D --undefined-only "$SO" | awk '{print $2}' | grep -cE '^(sin|cos|tan|exp|exp2|log|log2|log10|pow|sqrt|floor|ceil|round|fmod|ldexp|frexp)f?(@|$)')" || f=1
  echo "# C smoke test against pqz_ffi.h"
  # the set's precompile input limit (set.json max_input: 393,216 at n2048-kmax1024, 524,288 at the others): c_abi
  # checks the library's pqz_max_input () against it
  MI=$(python3 -I -c "import json, sys; print(json.load(open(sys.argv[1]))['max_input'])" "../params/sets/$S/set.json")
  OUT clang -std=c11 -Wall -Wextra -DPQZ_SET_MAX_INPUT="$MI" -o "$X/c_abi" tests/c_abi.c -L"$TD/release" -lpqz_ffi -Wl,-rpath,"$TD/release" || f=1
  OUT "$X/c_abi" || f=1
  echo "# clippy (the repository's toolchain, root rust-toolchain.toml): no float arithmetic in the crate"
  OUT cargo clippy --release --offline $BF --features prove,test-hooks --lib -- -D clippy::float_arithmetic || f=1
} > "$L-native.txt" 2>&1
return $f
}
part ffi/native ffi_native || fail=1

ffi_wasm() {
f=0
{
  echo "# wasm32: the verify-only lib, then the prove harness (wasm/) and the digest diff against native"
  OUT cargo build --release --offline $BF --lib --target wasm32-unknown-unknown || f=1
  (cd wasm && CARGO_TARGET_DIR=$WT OUT cargo build --release --offline $BF --target wasm32-unknown-unknown) || f=1
  W=$WT/wasm32-unknown-unknown/release/pqz_ffi_wasm.wasm
  OUT sha256sum "$W" || f=1
  ls -l "$W" | awk '{print "wasm bytes", $5}'
  echo "\$ llvm-nm-18 --undefined-only $W (imports)"; llvm-nm-18 --undefined-only "$W"
  ZERO "strings /gmp|mpfr|hexl/i" "$(strings -a "$W" | grep -ciE 'gmp|mpfr|hexl')" || f=1
  /usr/bin/time -v node wasm/run_wasm.mjs "$W" 3 > "$X/wasm.jsonl" 2> "$X/wasm-time.txt"
  r=$?; echo "node rc=$r"; [ $r = 0 ] || f=1; grep -E "wasm run|wasm PQZL|Maximum resident|Elapsed" "$X/wasm-time.txt"
  cp "$X/native.jsonl" "$L-digests-native.jsonl"; cp "$X/wasm.jsonl" "$L-digests-wasm.jsonl"
  if [ -s "$X/native.jsonl" ] && diff "$X/native.jsonl" "$X/wasm.jsonl"; then echo "native = wasm32: $(wc -l < "$X/wasm.jsonl") lines equal"; else echo "native != wasm32 [rc=1]"; f=1; fi
} > "$L-wasm.txt" 2>&1
return $f
}
part ffi/wasm ffi_wasm || fail=1

ffi_bench() {
/usr/bin/time -v cargo run --release --offline $BF --features prove,test-hooks --example ffi_bench "${N:-200}" > "$L-bench.jsonl" 2> "$L-bench-time.txt"
r=$?; echo "bench rc=$r" >> "$L-bench-time.txt"; return $r
}
part ffi/bench ffi_bench || fail=1

grep -hE "^# PQZL backend|^test result|FAILED|panicked|^test .* (ok|FAILED)$|rejection cases|differential:|op 7 largest|abort-freedom:|selftest hash|node faults:|verify-only |fill determinism:" "$L-test.txt"
grep -hE "^c_abi|symbols ok|forbidden|C core in this build|NEEDED|/gmp|libm-style|\[rc=[1-9]" "$L-native.txt"
grep -hE "native|wasm bytes|wasm run|\[rc=[1-9]" "$L-wasm.txt"
tail -2 "$L-bench.jsonl"; grep -E "bench rc|Maximum resident" "$L-bench-time.txt"
echo "ffi/run.sh $1: $([ $fail = 0 ] && echo ok || echo FAILED)"
exit $fail
