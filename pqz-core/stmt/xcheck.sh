#!/bin/sh
# pqz-stmt (P6e Task 5): unit tests, the cross-check against the C core's statements and the independent Python codec
# pqz_kat.py (xcheck.py, tests/xcheck.rs), and the wasm32-unknown-unknown build. One job under scripts/capped:
#   [PQZ_SET=<set>] scripts/capped pqz-core/stmt/xcheck.sh <label>          -> stmt/runs/<label>-*.txt
# PQZ_SET: a set with PQZH (default n2048-kmax1024, pqz-stmt's featureless build; R0 fix round m1: per set): the C
# build (build/<set>/), pqz_kat.py and pqz-stmt (feature set-<set>, target/xcheck-<set>) all at that set
set -eu
cd "$(dirname "$0")"
export PQZ_SET=${PQZ_SET:-n2048-kmax1024}
F="--no-default-features --features set-$PQZ_SET"
R=runs/$1 X=$(pwd)/target/xcheck-$PQZ_SET
export CARGO_TARGET_DIR=$X/cargo
mkdir -p runs "$X/c"
(cd ../pqzl && PQZ_BUILD_TAG=$PQZ_SET ./build.sh native) > "$R-build.txt" 2>&1
B=../pqzl/build/$PQZ_SET
${CC:-clang} -std=gnu11 -O2 -I../pqzl/src -I$B/include -o "$X/dump_setup" ../pqzh/xcheck/dump_setup.c $B/native/libpqz.a
"$X/dump_setup" "$X/c" pqzh
sha256sum "$X"/c/*_stmt.bin | sed "s#$X/##" > "$R-c-stmts.txt"
python3 -I xcheck.py "$X/c" "$X/py.txt" "${N:-4}" > "$R-xcheck-py.txt"
PQZ_STMT_XCHECK=$X cargo test --release --offline $F -- --nocapture > "$R-test.txt" 2>&1 || echo "cargo test rc=$?"
PQZ_STMT_XCHECK=$X cargo test --offline $F > "$R-test-debug.txt" 2>&1 || echo "cargo test (debug, overflow checks) rc=$?"
cargo test --release --offline --lib $F,oversize > "$R-test-oversize.txt" 2>&1 || echo "cargo test oversize rc=$?"
cargo build --release --offline --lib $F --target wasm32-unknown-unknown > "$R-wasm.txt" 2>&1 || echo "wasm rc=$?"
ls -l "$CARGO_TARGET_DIR"/wasm32-unknown-unknown/release/libpqz_stmt.rlib | awk '{print "rlib bytes", $5}' >> "$R-wasm.txt"
cargo tree --offline $F >> "$R-wasm.txt" 2>&1
cat "$R-xcheck-py.txt"
grep -h -e "test result" -e "^xcheck" -e panicked -e FAILED "$R-test.txt" "$R-test-debug.txt" "$R-test-oversize.txt"
tail -4 "$R-wasm.txt"
