#!/bin/sh
# pqz-stmt (P6e Task 5): unit tests, the cross-check against the C core's statements and the independent Python codec
# pqz_kat.py (xcheck.py, tests/xcheck.rs), and the wasm32-unknown-unknown build. One job under scripts/capped:
#   scripts/capped pqz-core/stmt/xcheck.sh <label>          -> stmt/runs/<label>-*.txt
set -eu
cd "$(dirname "$0")"
R=runs/$1 X=$(pwd)/target/xcheck
mkdir -p runs "$X/c"
(cd .. && ./build.sh native) > "$R-build.txt" 2>&1
${CC:-clang} -std=gnu11 -O2 -I../src -o "$X/dump_setup" ../pqzh/xcheck/dump_setup.c ../build/native/libpqz.a
"$X/dump_setup" "$X/c"
sha256sum "$X"/c/*_stmt.bin | sed "s#$X/##" > "$R-c-stmts.txt"
python3 -I xcheck.py "$X/c" "$X/py.txt" "${N:-4}" > "$R-xcheck-py.txt"
PQZ_STMT_XCHECK=$X cargo test --release --offline -- --nocapture > "$R-test.txt" 2>&1 || echo "cargo test rc=$?"
cargo build --release --offline --lib --target wasm32-unknown-unknown > "$R-wasm.txt" 2>&1 || echo "wasm rc=$?"
ls -l target/wasm32-unknown-unknown/release/libpqz_stmt.rlib | awk '{print "rlib bytes", $5}' >> "$R-wasm.txt"
cargo tree --offline >> "$R-wasm.txt" 2>&1
cat "$R-xcheck-py.txt"
grep -h -e "test result" -e "^xcheck" -e panicked -e FAILED "$R-test.txt"
tail -4 "$R-wasm.txt"
