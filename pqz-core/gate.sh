#!/bin/sh
# Gate A (PQZL, both cores: the C core and, since the Rust port, the Rust crate pqzl) and gate B (PQZH) of the relations plan (docs/superpowers/plans/2026-10-14-p6e-relations.md, "Gate A /
# Gate B") with op 7 in the frozen set (P6-ANON), one job under scripts/capped (it calls capped jobs itself only through
# the step scripts; run alone):
#   scripts/capped pqz-core/gate.sh <label> [fuzz-seconds]      -> runs/gate/<label>-*.txt, summary on stdout and in
#                                                                 runs/gate/<label>-summary.txt (with the PASS / FAIL line)
# Steps: KAT 19/19, check_tbox_fixes, check_sv_fixes, the PQZL differential (SV vs generic, z21), the vectors job
# (pqz-vectors --check, pqz_kat.py --check, tamper, pqz-ffi selftest vectors, wasm32 replay), the pqz-ffi job (tests,
# symbol scans, native = wasm32 digests), cargo test of pqz-stmt and Ligero, the STARK backup cross-check, the fuzz
# targets (build, then <fuzz-seconds> per target, default 60), and the Rust PQZL core pqzl/rust (step rust: its tests
# with the C oracle and the cheating fixtures, to_rust.py --check). Both PQZL cores: the C steps above, the Rust core
# through step rust and through pqz-ffi (its default backend) in the vectors, ffi and fuzz steps. Exit 1 if any step
# fails.
set -u
cd "$(dirname "$0")"
L=$1 FZ=${2:-60} R=runs/gate/$1
mkdir -p runs/gate
fail=0
# the summary also goes to a file (review round 2: the PQZL Rust port's gate PASS line was on stdout only)
say() { echo "$*" | tee -a "$R-summary.txt"; }
echo "# gate $L: $(git rev-parse HEAD)$(git diff --quiet HEAD || echo ' + uncommitted changes'), $(date -u +%Y-%m-%dT%H:%MZ)" > "$R-summary.txt"
step() { name=$1; shift; say "== $name"; if "$@" > "$R-$name.txt" 2>&1; then say "   ok"; else say "   FAILED (rc=$?)"; fail=1; fi; }

kat() { (cd pqzl && ./build.sh native && build/native/kat_dump > build/native/kat-pqz.json &&
  python3 -I kat/check.py kat/lazer-3330e48.json build/native/kat-pqz.json); }
diffs() { (cd pqzl && CAPPED=env sv/diff.sh "gate-$L" 20 10 2 10 &&
  grep -q '"mismatches": 0, "other_fails": 0' "sv/runs/gate-$L-portable.jsonl" &&
  ! grep -h '"mismatch": ' "sv/runs/gate-$L-portable.jsonl" "sv/runs/gate-$L-x86v3.jsonl"); }
tbox() { (cd pqzl && ./check_tbox_fixes.sh); }
rust() { (cd pqzl/rust && cargo test -j2 --release --offline --features c-oracle,test-hooks && python3 -I ../params/to_rust.py --check); }
sv() { (cd pqzl && sv/check_sv_fixes.sh); }
cargo_tests() { (cd stmt && cargo test --release --offline) && (cd pqzh/ligero && cargo test --release --offline); }
# a smoke run is too short to merge into the committed corpora (the 2 h campaigns'): restore them afterwards
fuzz() { fuzz/build.sh && for t in precompile mutate codec; do fuzz/run.sh "$t" "$FZ" "gate-$L" || return 1; done &&
  git checkout -- fuzz/corpus && git clean -fdq fuzz/corpus; }

step kat kat
step tbox tbox
step sv sv
step diff diffs
step vectors ffi/vectors/run.sh "gate-$L"
step ffi ffi/run.sh "gate-$L"
step rust rust
step cargo cargo_tests
step xcheck pqzh/xcheck/run.sh
step fuzz fuzz
say "gate $L: $( [ $fail = 0 ] && echo PASS || echo FAIL )"
exit $fail
