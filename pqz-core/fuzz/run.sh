#!/bin/sh
# One fuzz campaign (P6e plan Task 10, D12), under scripts/capped, after build.sh:
#   scripts/capped pqz-core/fuzz/run.sh <target> <seconds> [label]       (target: precompile | mutate | codec)
#   PQZ_FUZZ_MODE=pqzl-diff ...: the mode's binaries (build.sh with the same variable): Rust core = C core
# Fuzzes pqz-core/build/fuzz/<target> on a work corpus plus the committed corpus/<target>/, the regression inputs
# regress/<target>/ and the run-time seeds (seeds.py, from the frozen vectors smartcontracts/vectors/pqz/), then
# merges the work corpus into a minimal set and commits its inputs of <= 512 B to corpus/<target>/.
# Log: runs/<label>-<target>.txt (label: the date).
# A crash input lands in pqz-core/build/fuzz/crash-<target>-*: copy it to regress/<target>/ with the fix.
set -u
cd "$(dirname "$0")"
T=$1 S=$2 L=${3:-$(date +%F)}
case ${PQZ_FUZZ_MODE:-} in
  "") X=$T ;;
  pqzl-diff) X=$T-pqzl-diff ;;
  *) echo "PQZ_FUZZ_MODE=$PQZ_FUZZ_MODE: unset or pqzl-diff" >&2; exit 2 ;;
esac
B=$(cd .. && pwd)/build/fuzz${PQZ_BUILD_TAG:+-$PQZ_BUILD_TAG} # as build.sh
W=$B/work/$T SEEDS=$B/seeds/$T M=$B/merged/$T LOG=runs/$L-$T.txt
# the merged set goes to the committed corpus/<target>/, or under gate.sh (PQZ_BUILD_TAG set: a smoke run, concurrent
# gates) to $B/corpus/<target>/ so corpus/ is only read
C=corpus/$T; [ -z "${PQZ_BUILD_TAG:-}" ] || C=$B/corpus/$T
mkdir -p "$W" "$SEEDS" runs "corpus/$T" "regress/$T" "$C"
# precompile: above the set's MAX_INPUT (set.json max_input: 393,216 at n2048-kmax1024, 524,288 at the other sets; plan
# 5h Task 8c part 2) so the revert path is reached and no honest seed is truncated; the others edit inputs in memory
MI=$(python3 -I -c "import json, sys; print(json.load(open(sys.argv[1]))['max_input'])" "../params/sets/${PQZ_SET:-n2048-kmax1024}/set.json")
case $T in precompile) ML=$((MI + 4096)) ;; *) ML=512 ;; esac
# memory: the C core's arenas (mode pqzl-diff: ARENA_SMALL 512 MiB; the C generic verifier's ARENA_BIG = 1 GiB is one
# malloc of exactly 1024 MiB, which -malloc_limit_mb=1024 reported as an OOM in P6-ANON S5); scripts/capped caps at 4 GB
LIM="-rss_limit_mb=3072 -malloc_limit_mb=1536"
export PQZ_FUZZ_HONEST=$B/honest.bin ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=print_stacktrace=1
python3 -I seeds.py "$B" > "$LOG" 2>&1 || { cat "$LOG"; exit 1; }
# a work corpus from other honest inputs holds valid proofs the oracle does not know (a false "wrong accept"): drop it
H=$(sha256sum "$B/honest.bin" | cut -c1-64)
[ "$(cat "$W.honest" 2>/dev/null)" = "$H" ] || { rm -rf "$W" && mkdir -p "$W" && echo "$H" > "$W.honest"; }
{
  echo "# fuzz $T (binary $X), $S s, $(date -Is), commit $(git rev-parse --short HEAD), $(clang-18 --version | head -1), $(rustc +1.97.1 --version)"
  "$B/$X" -max_total_time="$S" -max_len=$ML $LIM -timeout=120 -print_final_stats=1 \
    -artifact_prefix="$B/crash-$T-" "$W" "corpus/$T" "regress/$T" "$SEEDS"
  echo "[fuzz rc=$?]"
  rm -rf "$M" && mkdir -p "$M"
  # -artifact_prefix: without it a crash in the merge step lands in this directory (P6e smoke3: the stray crash file)
  "$B/$X" -merge=1 -artifact_prefix="$B/crash-$T-merge-" -max_len=$ML $LIM -timeout=120 "$M" "$W" "corpus/$T"
  echo "[merge rc=$?]"
  rm -f "$C"/*
  find "$M" -type f -size -513c -exec cp {} "$C/" \;
  echo "corpus/$T: $(ls "$C" | wc -l) inputs ($C), $(du -sb "$C" | cut -f1) B (merged set $(ls "$M" | wc -l) inputs, $(du -sb "$M" | cut -f1) B)"
} >> "$LOG" 2>&1
grep -E "pqz-fuzz (init|summary|FINDING)|^stat::|Done [0-9]+ runs|\[(fuzz|merge) rc|^corpus/|ERROR|SUMMARY" "$LOG"
