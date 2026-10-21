#!/bin/sh
# Gate A (PQZL, both cores: the C core and, since the Rust port, the Rust crate pqzl) and gate B (PQZH) of the relations plan (docs/superpowers/plans/2026-10-14-p6e-relations.md, "Gate A /
# Gate B") with op 7 in the frozen set (P6-ANON), one job under scripts/capped (it calls capped jobs itself only through
# the step scripts; run alone):
#   [PQZ_SET=<set>] scripts/capped pqz-core/gate.sh <label> [fuzz-seconds]  -> runs/gate/<label>-*.txt, summary on stdout
#                                                                           and in runs/gate/<label>-summary.txt
# PQZ_SET: the parameter set (owner 2026-10-21: pqz-core/params/sets/<set>/, one set per library build; default
# n2304-kmax4096, the frozen v3 set is n2048-kmax1024); named in the summary.
# Steps: KAT 19/19 (against the set's upstream LaZer golden file), check_tbox_fixes, check_sv_fixes, the PQZL
# differential (SV vs generic, z21), C = Rust = wasm32 on the bench proofs (fnv), the vectors job (pqz-vectors --check,
# pqz_kat.py --check, tamper, pqz-ffi selftest vectors, wasm32 replay), the pqz-ffi job (tests, symbol scans, native =
# wasm32 digests), cargo test of pqz-stmt and Ligero, the STARK backup cross-check, the fuzz targets (build, then
# <fuzz-seconds> per target, default 60), and the Rust PQZL core pqzl/rust (step rust: its tests with the C oracle and
# the cheating fixtures, to_rust.py --check, gen_set.py --check). pqz-stmt, pqz-ffi, PQZH and the vectors exist for
# the set n2048-kmax1024 only until plan 5h Task 8c / 8d: for another set those five steps are not run (said in the
# summary, whose verdict is then PARTIAL, not PASS). Exit 1 if any step fails.
set -u
cd "$(dirname "$0")"
L=$1 FZ=${2:-60} R=runs/gate/$1
PQZ_SET=${PQZ_SET:-n2304-kmax4096}
export PQZ_SET
[ -f "params/sets/$PQZ_SET/pqz_set.h" ] || { echo "PQZ_SET=$PQZ_SET: no params/sets/$PQZ_SET" >&2; exit 2; }
V3=n2048-kmax1024
mkdir -p runs/gate
fail=0 partial=0
# the summary also goes to a file (review round 2: the PQZL Rust port's gate PASS line was on stdout only)
say() { echo "$*" | tee -a "$R-summary.txt"; }
echo "# gate $L (set $PQZ_SET): $(git rev-parse HEAD)$(git diff --quiet HEAD || echo ' + uncommitted changes'), $(date -u +%Y-%m-%dT%H:%MZ)" > "$R-summary.txt"
step() { name=$1; shift; say "== $name"; if "$@" > "$R-$name.txt" 2>&1; then say "   ok"; else say "   FAILED (rc=$?)"; fail=1; fi; }
v3only() { say "== $1"; say "   not run: set $PQZ_SET (pqz-stmt / pqz-ffi / PQZH / vectors are set $V3 only until plan 5h Task 8c / 8d)"; partial=1; }

# the pqzl crate's cargo flags for the set (one set-<set> feature, default-features off for a non-default set)
if [ "$PQZ_SET" = n2304-kmax4096 ]; then NODEF=""; FEAT=""; else NODEF="--no-default-features"; FEAT="sv,set-$PQZ_SET,"; fi
kat() { (cd pqzl && ./build.sh native && build/native/kat_dump > build/native/kat-pqz.json &&
  python3 -I kat/check.py "../params/sets/$PQZ_SET/lazer-3330e48-kat.json" build/native/kat-pqz.json); }
diffs() { (cd pqzl && CAPPED=env sv/diff.sh "gate-$L" 20 10 2 10 &&
  grep -q '"mismatches": 0, "other_fails": 0' "sv/runs/gate-$L-portable.jsonl" &&
  ! grep -h '"mismatch": ' "sv/runs/gate-$L-portable.jsonl" "sv/runs/gate-$L-x86v3.jsonl"); }
tbox() { (cd pqzl && ./check_tbox_fixes.sh); }
# the vector tests need the set's vectors; without them (any set but v3 until 8d) tests/common builds one honest row per
# bench relation, proved by the C core, so the crate also needs feature bench
rust() { (cd pqzl/rust && CARGO_TARGET_DIR=target/$PQZ_SET cargo test -j2 --release --offline $NODEF --features "${FEAT}c-oracle,test-hooks,bench" &&
  python3 -I ../params/to_rust.py --check && python3 -I ../../params/sets/gen_set.py --check); }
# C = Rust = wasm32 on the bench proofs: the C core's pqz_bench, the Rust bench and the Rust bench in wasm32 (node) print
# the same proofs_fnv per relation (2 proofs of each of the 14 relations, mask 16383)
fnv() { (cd pqzl && PQZ_ARENA_MB=2048 build/native/pqz_bench 2 1 16383 > "../$R-fnv-c.jsonl" &&
  cd rust && CARGO_TARGET_DIR=target/$PQZ_SET cargo build -j2 --release --offline $NODEF --features "${FEAT}bench" --bin bench &&
  "target/$PQZ_SET/release/bench" 2 1 16383 > "../../$R-fnv-rust.jsonl" &&
  (cd wasm && CARGO_TARGET_DIR=target/$PQZ_SET cargo build -j2 --release --offline --target wasm32-unknown-unknown \
     --no-default-features --features "set-$PQZ_SET") &&
  PQZL_WASM_FILE="wasm/target/$PQZ_SET/wasm32-unknown-unknown/release/pqzl_wasm.wasm" node wasm/run_wasm.mjs 2 1 16383 > "../../$R-fnv-wasm.jsonl" &&
  cd ../.. && for x in c rust wasm; do python3 -I -c "$FNVX" "$R-fnv-$x.jsonl" > "$R-fnv-$x.txt" || return 1; done &&
  test "$(wc -l < "$R-fnv-c.txt")" = 14 && cmp "$R-fnv-c.txt" "$R-fnv-rust.txt" && cmp "$R-fnv-c.txt" "$R-fnv-wasm.txt" &&
  cat "$R-fnv-c.txt"); }
# one "<rel> <proofs_fnv>" line per relation of a bench's JSON lines (the C / Rust benches print '": ', the wasm32 one
# '":'); exit 1 if any line reports fails > 0
FNVX='import json, sys
bad = 0
for l in open(sys.argv[1]):
    if l.startswith("{"):
        j = json.loads(l)
        bad += j.get("fails", 0) > 0
        if "proofs_fnv" in j:
            print(j["rel"], j["proofs_fnv"])
sys.exit(1 if bad else 0)'
sv() { (cd pqzl && sv/check_sv_fixes.sh); }
cargo_tests() { (cd stmt && cargo test --release --offline) && (cd pqzh/ligero && cargo test --release --offline); }
# a smoke run is too short to merge into the committed corpora (the 2 h campaigns'): restore them afterwards
fuzz() { fuzz/build.sh && for t in precompile mutate codec; do fuzz/run.sh "$t" "$FZ" "gate-$L" || return 1; done &&
  git checkout -- fuzz/corpus && git clean -fdq fuzz/corpus; }

say "set $PQZ_SET"
step kat kat
step tbox tbox
step sv sv
step diff diffs
step fnv fnv
if [ "$PQZ_SET" = $V3 ]; then
  step vectors ffi/vectors/run.sh "gate-$L"
  step ffi ffi/run.sh "gate-$L"
else
  v3only vectors
  v3only ffi
fi
step rust rust
if [ "$PQZ_SET" = $V3 ]; then
  step cargo cargo_tests
  step xcheck pqzh/xcheck/run.sh
  step fuzz fuzz
else
  v3only cargo
  v3only xcheck
  v3only fuzz
fi
say "gate $L (set $PQZ_SET): $( [ $fail = 0 ] && { [ $partial = 0 ] && echo PASS || echo 'PARTIAL (every step run passed; steps not run above)'; } || echo FAIL )"
exit $fail
