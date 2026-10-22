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
# the cheating fixtures, to_rust.py --check, gen_set.py --all --check). Every step runs at the set: its vectors are
# smartcontracts/vectors/pqz/ (n2048-kmax1024) or smartcontracts/vectors/pqz/<set>/ (pqz-vectors, pqz_kat.py, fuzz
# seeds and the Rust tests read the set's). PQZH (Ligero over F_q) exists for the sets whose set.json says pqzh (n2048-kmax1024 until plan 5h Task 8c): for
# another set the Ligero tests and the STARK / Ligero cross-check are "skipped (PQZH ...)" and pqz-ffi / pqz-vectors
# are built without PQZH (owner ruling 2026-10-21: skipped, not PARTIAL). A core_only set (set.toml, e.g. A') has no
# pqz-stmt / precompile build: vectors, ffi, cargo, xcheck and fuzz are "skipped (core_only)". Exit 1 if any step fails.
# Resume (owner 2026-10-23, every set): runs/gate/<label>-state records each step and each part of a long step (diff,
# fnv, vectors, ffi, rust, cargo, fuzz; resume.sh) that passed; re-running the same label at the same set and tree
# (HEAD + uncommitted changes, logs and the fuzz corpus excluded) skips them, so an interrupted gate restarts near
# where it stopped. A code change re-runs everything; GATE_FRESH=1 ignores the state. Milestones: every step and part
# logs start / ok (duration) / FAILED / resumed with a timestamp to runs/gate/<label>-progress.txt (tail -f it).
set -u
cd "$(dirname "$0")"
L=$1 FZ=${2:-60} R=runs/gate/$1
PQZ_SET=${PQZ_SET:-n2304-kmax4096}
export PQZ_SET
[ -f "params/sets/$PQZ_SET/pqz_set.h" ] || { echo "PQZ_SET=$PQZ_SET: no params/sets/$PQZ_SET" >&2; exit 2; }
V3=n2048-kmax1024
mkdir -p runs/gate
fail=0
. ./resume.sh
GATE_STATE=$(pwd)/$R-state
[ "${GATE_FRESH:-0}" = 1 ] && rm -f "$GATE_STATE"
TOP=$(git rev-parse --show-toplevel)
GATE_TREE=$PQZ_SET-$( { git rev-parse HEAD
  git -C "$TOP" diff HEAD -- . ':(exclude,glob)**/runs/**' ':(exclude)pqz-core/fuzz/corpus'
  git -C "$TOP" ls-files -o --exclude-standard -z -- . ':(exclude,glob)**/runs/**' ':(exclude)pqz-core/fuzz/corpus' |
    (cd "$TOP" && xargs -0r sha256sum); } | sha256sum | cut -c1-16)
GATE_LOG=$(pwd)/$R-progress.txt
export GATE_STATE GATE_TREE GATE_LOG
glog "gate $L (set $PQZ_SET) started at $(git rev-parse --short HEAD), tree $GATE_TREE"
# the summary also goes to a file (review round 2: the PQZL Rust port's gate PASS line was on stdout only)
say() { echo "$*" | tee -a "$R-summary.txt"; }
echo "# gate $L (set $PQZ_SET): $(git rev-parse HEAD)$(git diff --quiet HEAD || echo ' + uncommitted changes'), $(date -u +%Y-%m-%dT%H:%MZ)" > "$R-summary.txt"
step() {
  name=$1
  shift
  say "== $name"
  if grep -qxF "step/$name $GATE_TREE" "$GATE_STATE" 2>/dev/null; then say "   ok (resumed: passed earlier at this tree)"; glog "resumed step/$name"; return; fi
  glog "start   step/$name"
  t0=$(date +%s)
  if "$@" > "$R-$name.txt" 2>&1; then
    say "   ok"; echo "step/$name $GATE_TREE" >> "$GATE_STATE"; glog "ok      step/$name ($(dur "$t0"))"
  else
    rc=$?; say "   FAILED (rc=$rc)"; fail=1; glog "FAILED  step/$name rc=$rc ($(dur "$t0"))"
  fi
}
skip() { say "== $1"; say "   skipped ($2)"; glog "skipped step/$1 ($2)"; }
SJ=params/sets/$PQZ_SET/set.json
json() { python3 -I -c "import json, sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$SJ" "$1"; }
PQZH=$(json pqzh) CORE_ONLY=$(json core_only)
NOPQZH="PQZH is not built for set $PQZ_SET until plan 5h Task 8c"

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
# (one part per test binary: cargo builds them all, then each runs as cargo test would, from the crate directory)
rust() { (cd pqzl/rust && export CARGO_TARGET_DIR="target/$PQZ_SET" && rf=0 &&
  CF="-j2 --release --offline $NODEF --features ${FEAT}c-oracle,test-hooks,bench" &&
  cargo test $CF --no-run --message-format=json | python3 -I -c "$TESTX" > "$CARGO_TARGET_DIR/gate-tests.txt" &&
  while read -r n x; do echo "     Running $n ($x)"; part "rust/$n" "$x" < /dev/null || rf=1; done < "$CARGO_TARGET_DIR/gate-tests.txt" &&
  part rust/doc cargo test $CF --doc && [ $rf = 0 ] &&
  python3 -I ../params/to_rust.py --check && python3 -I ../../params/sets/gen_set.py --all --check); }
# "<kind>-<target> <executable>" per test binary of cargo's JSON messages
TESTX='import json, sys
for l in sys.stdin:
    j = json.loads(l)
    if j.get("reason") == "compiler-artifact" and j.get("executable") and j["profile"]["test"]:
        print(j["target"]["kind"][0] + "-" + j["target"]["name"], j["executable"])'
# C = Rust = wasm32 on the bench proofs: the C core's pqz_bench, the Rust bench and the Rust bench in wasm32 (node) print
# the same proofs_fnv per relation (2 proofs of each of the 14 relations, mask 16383)
fnv() { (cd pqzl && part fnv/c sh -c "PQZ_ARENA_MB=2048 build/native/pqz_bench 2 1 16383 > '../$R-fnv-c.jsonl'" &&
  cd rust && part fnv/rust sh -c "CARGO_TARGET_DIR=target/$PQZ_SET cargo build -j2 --release --offline $NODEF --features '${FEAT}bench' --bin bench &&
    target/$PQZ_SET/release/bench 2 1 16383 > '../../$R-fnv-rust.jsonl'" &&
  part fnv/wasm sh -c "(cd wasm && CARGO_TARGET_DIR=target/$PQZ_SET cargo build -j2 --release --offline --target wasm32-unknown-unknown \
     --no-default-features --features 'set-$PQZ_SET') &&
    PQZL_WASM_FILE=wasm/target/$PQZ_SET/wasm32-unknown-unknown/release/pqzl_wasm.wasm node wasm/run_wasm.mjs 2 1 16383 > '../../$R-fnv-wasm.jsonl'" &&
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
# pqz-stmt at the set; Ligero's tests where the set has PQZH
cargo_tests() { (cd stmt && part cargo/stmt env CARGO_TARGET_DIR="target/$PQZ_SET" cargo test --release --offline --no-default-features --features "set-$PQZ_SET") &&
  if [ "$PQZH" = True ]; then (cd pqzh/ligero && part cargo/ligero cargo test --release --offline); else echo "Ligero: $NOPQZH"; fi; }
# a smoke run is too short to merge into the committed corpora (the 2 h campaigns'): restore them afterwards
fuzz() { fuzz/build.sh && for t in precompile mutate codec; do part "fuzz/$t" fuzz/run.sh "$t" "$FZ" "gate-$L" || return 1; done &&
  git checkout -- fuzz/corpus && git clean -fdq fuzz/corpus; }

say "set $PQZ_SET"
step kat kat
step tbox tbox
step sv sv
step diff diffs
step fnv fnv
if [ "$CORE_ONLY" = True ]; then
  skip vectors core_only; skip ffi core_only
else
  step vectors ffi/vectors/run.sh "gate-$L"
  step ffi ffi/run.sh "gate-$L"
fi
step rust rust
if [ "$CORE_ONLY" = True ]; then skip cargo core_only; else step cargo cargo_tests; fi
if [ "$PQZH" = True ]; then step xcheck pqzh/xcheck/run.sh; else skip xcheck "$NOPQZH"; fi
if [ "$CORE_ONLY" = True ]; then skip fuzz core_only; else step fuzz fuzz; fi
say "gate $L (set $PQZ_SET): $( [ $fail = 0 ] && echo PASS || echo FAIL )"
glog "gate $L (set $PQZ_SET): $( [ $fail = 0 ] && echo PASS || echo FAIL )"
exit $fail
