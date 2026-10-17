#!/bin/sh
# Gate A (PQZL) and gate B (PQZH) of the relations plan (docs/superpowers/plans/2026-10-14-p6e-relations.md, "Gate A /
# Gate B") with op 7 in the frozen set (P6-ANON), one job under scripts/capped (it calls capped jobs itself only through
# the step scripts; run alone):
#   scripts/capped pqz-core/gate.sh <label> [fuzz-seconds]      -> runs/gate/<label>-*.txt, summary on stdout
# Steps: KAT 19/19, check_tbox_fixes, check_sv_fixes, the PQZL differential (SV vs generic, z21), the vectors job
# (pqz-vectors --check, pqz_kat.py --check, tamper, pqz-ffi selftest vectors, wasm32 replay), the pqz-ffi job (tests,
# symbol scans, native = wasm32 digests), cargo test of pqz-stmt and Ligero, the STARK backup cross-check, the fuzz
# targets (build, then <fuzz-seconds> per target, default 60). Exit 1 if any step fails.
set -u
cd "$(dirname "$0")"
L=$1 FZ=${2:-60} R=runs/gate/$1
mkdir -p runs/gate
fail=0
step() { name=$1; shift; echo "== $name"; if "$@" > "$R-$name.txt" 2>&1; then echo "   ok"; else echo "   FAILED (rc=$?)"; fail=1; fi; }

kat() { (cd pqzl && ./build.sh native && build/native/kat_dump > build/native/kat-pqz.json &&
  python3 -I kat/check.py kat/lazer-3330e48.json build/native/kat-pqz.json); }
diffs() { (cd pqzl && CAPPED=env sv/diff.sh "gate-$L" 20 10 2 10 &&
  grep -q '"mismatches": 0, "other_fails": 0' "sv/runs/gate-$L-portable.jsonl" &&
  ! grep -h '"mismatch": ' "sv/runs/gate-$L-portable.jsonl" "sv/runs/gate-$L-x86v3.jsonl"); }
tbox() { (cd pqzl && ./check_tbox_fixes.sh); }
sv() { (cd pqzl && sv/check_sv_fixes.sh); }
cargo_tests() { (cd stmt && cargo test --release --offline) && (cd pqzh/ligero && cargo test --release --offline); }
fuzz() { fuzz/build.sh && for t in precompile mutate codec; do fuzz/run.sh "$t" "$FZ" "gate-$L" || return 1; done; }

step kat kat
step tbox tbox
step sv sv
step diff diffs
step vectors ffi/vectors/run.sh "gate-$L"
step ffi ffi/run.sh "gate-$L"
step cargo cargo_tests
step xcheck pqzh/xcheck/run.sh
step fuzz fuzz
echo "gate $L: $( [ $fail = 0 ] && echo PASS || echo FAIL )"
exit $fail
