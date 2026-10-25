#!/bin/sh
# Gate A (PQZL, both cores: the C core and, since the Rust port, the Rust crate pqzl) and gate B (PQZH) of the relations plan (docs/superpowers/plans/2026-10-14-p6e-relations.md, "Gate A /
# Gate B") with op 7 in the frozen set (P6-ANON), one job under scripts/capped (it calls capped jobs itself only through
# the step scripts; run alone):
#   [PQZ_SET=<set>] scripts/capped pqz-core/gate.sh [label [fuzz-seconds]]  -> runs/gate/<label>-*.txt, summary on stdout
#                                                                           and in runs/gate/<label>-summary.txt
# label: optional, default the set's name (owner 2026-10-23: nothing to remember — re-running the same command resumes;
# progress in runs/gate/<set>-progress.txt). A run at another tree starts over and overwrites that label's logs.
# runs/gate/last names the latest run (set, label, start, status running / PASS / FAIL; owner 2026-10-23: a resumed
# session continues the right set): `scripts/capped pqz-core/gate.sh --last` re-runs it with its set and label;
# runs/gate/last-<set> is each set's latest run, `gate.sh --last <set>` re-runs that one (concurrent gates).
# PQZ_SET: the parameter set (owner 2026-10-21: pqz-core/params/sets/<set>/, one set per library build; default
# n2304-kmax4096, the frozen v3 set is n2048-kmax1024); named in the summary.
# Steps: KAT 19/19 (against the set's upstream LaZer golden file), check_tbox_fixes, check_sv_fixes, the PQZL
# differential (SV vs generic, z21), C = Rust = wasm32 on the bench proofs (fnv), the vectors job (pqz-vectors --check,
# pqz_kat.py --check, tamper, pqz-ffi selftest vectors, wasm32 replay), the pqz-ffi job (tests, symbol scans, native =
# wasm32 digests), cargo test of pqz-stmt and Ligero, the PQZH cross-checks (C = Rust statement / witness bytes: the
# STARK backup's at n2048-kmax1024, Ligero's at every set with PQZH), the fuzz targets (build, then
# <fuzz-seconds> per target, default 60), and the Rust PQZL core pqzl/rust (step rust: its tests with the C oracle and
# the cheating fixtures, to_rust.py --check, gen_set.py --all --check). Every step runs at the set: its vectors are
# smartcontracts/vectors/pqz/ (n2048-kmax1024) or smartcontracts/vectors/pqz/<set>/ (pqz-vectors, pqz_kat.py, fuzz
# seeds and the Rust tests read the set's). PQZH (Ligero over F_q) exists for the sets whose set.json says pqzh
# (n2048-kmax1024, n2304-kmax4096, n2560-kmax16384 since plan 5h Task 8c part 2): pqz-ffi / pqz-vectors / fuzz build it
# with the set (feature set-<set> forwards it), Ligero's tests run with --features set-<set>; for a set without it the
# Ligero tests and the cross-checks are "skipped (PQZH ...)" (owner ruling 2026-10-21: skipped, not PARTIAL; n2816-kmax65536,
# PQZL only since plan 5h Task 8d part 1b). A core_only set (set.toml; none today) has no pqz-stmt / precompile build:
# vectors, ffi, cargo, xcheck and fuzz are "skipped (core_only)". Exit 1 if any step fails.
# Resume (owner 2026-10-23, every set): runs/gate/<label>-state records each step and each part of a long step (diff,
# fnv, vectors, ffi, rust, cargo, fuzz; resume.sh) that passed; re-running the same label at the same set and tree
# skips them, so an interrupted gate restarts near where it stopped. The tree (GATE_TREE) is the file contents (binary
# files included, this script and resume.sh too; logs and the fuzz corpus excluded), the fuzz seconds and the
# variables in GATE_ENV that change what a step does. Any other tree clears the label's state, so every part re-runs
# and rewrites its outputs (they are named by the label only); GATE_FRESH=1 does the same. --last restores the set,
# the label, the fuzz seconds and GATE_ENV. Milestones: every step and part logs start / ok (duration) / FAILED /
# resumed with a timestamp to runs/gate/<label>-progress.txt (tail -f it).
set -u
cd "$(dirname "$0")"
# the environment the steps read (8b review I3 / m6): part of the resume key, recorded in runs/gate/last
GATE_ENV="RUSTFLAGS ZN PQZ_ARENA_MB PQZL N PQZ_FUZZ_MODE CC CLANG WASM_LD WASM_SIMD SV OVERSIZE"
if [ "${1:-}" = --last ]; then
  LF=runs/gate/last; [ -n "${2:-}" ] && LF=runs/gate/last-$2 # --last <set>: that set's latest run (concurrent gates)
  [ -f "$LF" ] || { echo "gate.sh --last: no $LF" >&2; exit 2; }
  PQZ_SET=$(sed -n 's/^set=//p' "$LF")
  set -- "$(sed -n 's/^label=//p' "$LF")" "$(sed -n 's/^fz=//p' "$LF")"
  for v in $GATE_ENV; do
    if grep -q "^env $v=" "$LF"; then export "$v=$(sed -n "s/^env $v=//p" "$LF")"; else unset "$v"; fi
  done
  echo "gate.sh --last: set $PQZ_SET, label $1, fuzz seconds ${2:-60}"
fi
PQZ_SET=${PQZ_SET:-n2304-kmax4096}
L=${1:-$PQZ_SET} FZ=${2:-60}
R=runs/gate/$L
export PQZ_SET
# every build / output path of the steps is per set (owner 2026-10-23: the four sets' gates run at the same time from
# one worktree, one scripts/capped slot each): the C builds under pqzl/build/<set>/ (build.sh and the harness scripts
# read PQZ_BUILD_TAG), the pqz-ffi / vectors / fuzz / xcheck cargo targets and work files under .../target/<set>/,
# build/fuzz-<set>/; logs are named by the label (default the set)
export PQZ_BUILD_TAG=$PQZ_SET
unset B # build.sh's directory comes from PQZ_BUILD_TAG only (an exported B split builds from harness links; re-review N1)
PB=build/$PQZ_SET
[ -f "params/sets/$PQZ_SET/pqz_set.h" ] || { echo "PQZ_SET=$PQZ_SET: no params/sets/$PQZ_SET" >&2; exit 2; }
V3=n2048-kmax1024
mkdir -p runs/gate
# one gate per label at a time (re-review N3: two gates on one label share state and output files)
exec 9> "runs/gate/$L.lock"
flock -n 9 || { echo "gate label $L: another gate is running it" >&2; exit 2; }
fail=0
. ./resume.sh
GATE_STATE=$(pwd)/$R-state
[ "${GATE_FRESH:-0}" = 1 ] && rm -f "$GATE_STATE"
TOP=$(git rev-parse --show-toplevel)
# the tree (resume.sh gate_tree): file contents, the fuzz seconds and GATE_ENV
export GATE_TOP=$TOP GATE_FZ=$FZ GATE_ENV
GATE_TREE=$(gate_tree)
# a state of another tree is dropped whole: a resumed part never pairs "passed" with another tree's output files
if [ -f "$GATE_STATE" ] && grep -qv " $GATE_TREE\$" "$GATE_STATE"; then rm -f "$GATE_STATE"; fi
GATE_LOG=$(pwd)/$R-progress.txt
export GATE_STATE GATE_TREE GATE_LOG
{ printf 'set=%s\nlabel=%s\nfz=%s\nstarted=%s\nstatus=running\n' "$PQZ_SET" "$L" "$FZ" "$(date +%FT%T)"
  for v in $GATE_ENV; do printenv "$v" > /dev/null && echo "env $v=$(printenv "$v")"; done; } > "runs/gate/last-$PQZ_SET"
cp "runs/gate/last-$PQZ_SET" runs/gate/last
glog "gate $L (set $PQZ_SET) started at $(git rev-parse --short HEAD), tree $GATE_TREE"
# the summary also goes to a file (review round 2: the PQZL Rust port's gate PASS line was on stdout only)
say() { echo "$*" | tee -a "$R-summary.txt"; }
# (the gate's own logs under runs/gate/ excluded: glog has already written this run's progress file; review 8c part 2 m9)
echo "# gate $L (set $PQZ_SET): $(git rev-parse HEAD)$(git diff --quiet HEAD -- . ':!runs/gate' || echo ' + uncommitted changes'), $(date -u +%Y-%m-%dT%H:%MZ)" > "$R-summary.txt"
step() {
  name=$1
  shift
  say "== $name"
  if grep -qxF "step/$name $GATE_TREE" "$GATE_STATE" 2>/dev/null; then say "   ok (resumed: passed earlier at this tree)"; glog "resumed step/$name"; return; fi
  glog "start   step/$name"
  t0=$(date +%s)
  if "$@" > "$R-$name.txt" 2>&1; then
    say "   ok"; gate_record "step/$name"; glog "ok      step/$name ($(dur "$t0"))"
  else
    rc=$?; say "   FAILED (rc=$rc)"; fail=1; glog "FAILED  step/$name rc=$rc ($(dur "$t0"))"
  fi
}
skip() { say "== $1"; say "   skipped ($2)"; glog "skipped step/$1 ($2)"; }
SJ=params/sets/$PQZ_SET/set.json
json() { python3 -I -c "import json, sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])" "$SJ" "$1"; }
PQZH=$(json pqzh) CORE_ONLY=$(json core_only)
NOPQZH="set $PQZ_SET has no PQZH (set.json pqzh)"

# the pqzl crate's cargo flags for the set (one set-<set> feature, default-features off for a non-default set)
if [ "$PQZ_SET" = n2304-kmax4096 ]; then NODEF=""; FEAT=""; else NODEF="--no-default-features"; FEAT="sv,set-$PQZ_SET,"; fi
kat() { (cd pqzl && ./build.sh native && $PB/native/kat_dump > $PB/native/kat-pqz.json &&
  python3 -I kat/check.py "../params/sets/$PQZ_SET/lazer-3330e48-kat.json" $PB/native/kat-pqz.json); }
# (diff.sh exits 1 when a run does; the z21diff summary must also show its relations crossing the set's own Bsq)
diffs() { (cd pqzl && CAPPED=env sv/diff.sh "gate-$L" 20 10 2 10 &&
  grep -q '"mismatches": 0, "other_fails": 0' "sv/runs/gate-$L-portable.jsonl" &&
  ! grep -h '"mismatch": ' "sv/runs/gate-$L-portable.jsonl" "sv/runs/gate-$L-x86v3.jsonl" &&
  grep -q '"disagreements": 0, "expect_mismatches": 0, "prove_errors": 0, .*"both_verdicts_every_relation": 1}' \
    "sv/runs/gate-$L-z21diff.jsonl"); }
tbox() { (cd pqzl && ./check_tbox_fixes.sh); }
# the vector tests need the set's vectors; without them (a core_only set) tests/common builds one honest row per
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
# the same proofs_fnv per relation (2 proofs of each of the 14 relations, mask 16383); a core_only set and n2816-kmax65536 also the C core
# in wasm32 (cwasm)
fnv() { (cd pqzl && part fnv/c sh -c "./build.sh native > /dev/null && PQZ_ARENA_MB=2048 $PB/native/pqz_bench 2 1 16383 > '../$R-fnv-c.jsonl'" &&
  cd rust && part fnv/rust sh -c "CARGO_TARGET_DIR=target/$PQZ_SET cargo build -j2 --release --offline $NODEF --features '${FEAT}bench' --bin bench &&
    target/$PQZ_SET/release/bench 2 1 16383 > '../../$R-fnv-rust.jsonl'" &&
  part fnv/wasm sh -c "(cd wasm && CARGO_TARGET_DIR=target/$PQZ_SET cargo build -j2 --release --offline --target wasm32-unknown-unknown \
     --no-default-features --features 'set-$PQZ_SET') &&
    PQZL_WASM_FILE=wasm/target/$PQZ_SET/wasm32-unknown-unknown/release/pqzl_wasm.wasm node wasm/run_wasm.mjs 2 1 16383 > '../../$R-fnv-wasm.jsonl'" &&
  cd ../.. && for x in c rust wasm; do python3 -I -c "$FNVX" "$R-fnv-$x.jsonl" > "$R-fnv-$x.txt" || return 1; done &&
  test "$(wc -l < "$R-fnv-c.txt")" = 14 && cmp "$R-fnv-c.txt" "$R-fnv-rust.txt" && cmp "$R-fnv-c.txt" "$R-fnv-wasm.txt" &&
  cat "$R-fnv-c.txt" && if [ "$CORE_ONLY" = True ] || [ "$(json log2q)" -gt 50 ]; then cwasm; fi); }
# a core_only set, and a set with log2 q > 50 (n2816-kmax65536, 54: the closest to the C core's PQZ_LOG2Q <= 56 limb
# bound; it kept this part when it stopped being core_only, plan 5h Task 8d part 1b; pqz-ffi's wasm32 build runs the
# Rust core): the C core's wasm32 build (its limb path, PQZ_MUL128 0) in its own build directory (not the native build's) must print
# the native C run's proofs_fnv (8b review I4)
cwasm() { (cd pqzl && part fnv/cwasm sh -c "B=$PB/cwasm ./build.sh wasm > /dev/null &&
    PQZ_WASM_FILE=$PB/cwasm/wasm/pqz.wasm PQZ_ARENA_MB=2048 node test/run_wasm.mjs 2 1 16383 \
    > '../$R-fnv-cwasm.jsonl'") && python3 -I -c "$FNVX" "$R-fnv-cwasm.jsonl" > "$R-fnv-cwasm.txt" &&
  cmp "$R-fnv-c.txt" "$R-fnv-cwasm.txt" && echo "C core wasm32 = C core native (14 relations)"; }
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
# pqz-stmt at the set; Ligero's tests at the set where it has PQZH (per-set target, plan 5h Task 8c part 2);
# --no-fail-fast: one failing test binary must not hide the others (R0 fix round I1)
cargo_tests() { (cd stmt && part cargo/stmt env CARGO_TARGET_DIR="target/$PQZ_SET" cargo test --release --offline --no-fail-fast --no-default-features --features "set-$PQZ_SET") &&
  if [ "$PQZH" = True ]; then (cd pqzh/ligero && part cargo/ligero env CARGO_TARGET_DIR="target/$PQZ_SET" cargo test --release --offline --no-fail-fast --features "set-$PQZ_SET"); else echo "Ligero: $NOPQZH"; fi; }
# PQZH cross-checks: the STARK backup's (R_REG / R_TX, Plonky3 crate: n2048-kmax1024 only) and Ligero's (all six forms
# and pqz_kat.py's statement rebuild, at the set)
xcheck() { if [ "$PQZ_SET" = $V3 ]; then part xcheck/stark pqzh/xcheck/run.sh || return 1; fi; part xcheck/ligero pqzh/xcheck/ligero.sh; }
# a smoke run is too short to merge into the committed corpora (the 2 h campaigns'): with PQZ_BUILD_TAG, run.sh merges
# into build/fuzz-<set>/corpus/ and only reads fuzz/corpus/
fuzz() { fuzz/build.sh && for t in precompile mutate codec; do part "fuzz/$t" fuzz/run.sh "$t" "$FZ" "gate-$L" || return 1; done; }

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
if [ "$PQZH" = True ]; then step xcheck xcheck; else skip xcheck "$NOPQZH"; fi
if [ "$CORE_ONLY" = True ]; then skip fuzz core_only; else step fuzz fuzz; fi
say "gate $L (set $PQZ_SET): $( [ $fail = 0 ] && echo PASS || echo FAIL )"
glog "gate $L (set $PQZ_SET): $( [ $fail = 0 ] && echo PASS || echo FAIL )"
st="status=$( [ $fail = 0 ] && echo PASS || echo FAIL ) $(date +%FT%T)"
sed -i "s/^status=.*/$st/" "runs/gate/last-$PQZ_SET"
# runs/gate/last: only while it still names this run (another set's gate may have started since)
grep -qx "label=$L" runs/gate/last && grep -qx "set=$PQZ_SET" runs/gate/last && sed -i "s/^status=.*/$st/" runs/gate/last
exit $fail
