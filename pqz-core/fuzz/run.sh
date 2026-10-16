#!/bin/sh
# One fuzz campaign (P6e plan Task 10, D12), under scripts/capped, after build.sh:
#   scripts/capped pqz-core/fuzz/run.sh <target> <seconds> [label]       (target: precompile | mutate | codec)
# Fuzzes pqz-core/build/fuzz/<target> on a work corpus plus the committed corpus/<target>/, the regression inputs
# regress/<target>/ and the run-time seeds (seeds.py, from the frozen vectors smartcontracts/vectors/pqz/), then
# merges the work corpus into a minimal set and commits its inputs of <= 512 B to corpus/<target>/.
# Log: runs/<label>-<target>.txt (label: the date).
# A crash input lands in pqz-core/build/fuzz/crash-<target>-*: copy it to regress/<target>/ with the fix.
set -u
cd "$(dirname "$0")"
T=$1 S=$2 L=${3:-$(date +%F)}
B=$(cd .. && pwd)/build/fuzz
W=$B/work/$T SEEDS=$B/seeds/$T M=$B/merged/$T LOG=runs/$L-$T.txt
mkdir -p "$W" "$SEEDS" runs "corpus/$T" "regress/$T"
case $T in precompile) ML=400000 ;; *) ML=512 ;; esac
# memory: mutate's differential re-initialises the core on the generic verifier's arena, ARENA_BIG = 1 GiB since
# P6-ANON S3 (one malloc of exactly 1024 MiB, which -malloc_limit_mb=1024 reports as an OOM); scripts/capped caps at 4 GB
LIM="-rss_limit_mb=3072 -malloc_limit_mb=1536"
export PQZ_FUZZ_HONEST=$B/honest.bin ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=print_stacktrace=1
python3 -I seeds.py "$B" > "$LOG" 2>&1 || { cat "$LOG"; exit 1; }
# a work corpus from other honest inputs holds valid proofs the oracle does not know (a false "wrong accept"): drop it
H=$(sha256sum "$B/honest.bin" | cut -c1-64)
[ "$(cat "$W.honest" 2>/dev/null)" = "$H" ] || { rm -rf "$W" && mkdir -p "$W" && echo "$H" > "$W.honest"; }
{
  echo "# fuzz $T, $S s, $(date -Is), commit $(git rev-parse --short HEAD), $(clang-18 --version | head -1), $(rustc +1.97.1 --version)"
  "$B/$T" -max_total_time="$S" -max_len=$ML $LIM -timeout=120 -print_final_stats=1 \
    -artifact_prefix="$B/crash-$T-" "$W" "corpus/$T" "regress/$T" "$SEEDS"
  echo "[fuzz rc=$?]"
  rm -rf "$M" && mkdir -p "$M"
  # -artifact_prefix: without it a crash in the merge step lands in this directory (P6e smoke3: the stray crash file)
  "$B/$T" -merge=1 -artifact_prefix="$B/crash-$T-merge-" -max_len=$ML $LIM -timeout=120 "$M" "$W" "corpus/$T"
  echo "[merge rc=$?]"
  rm -f corpus/"$T"/*
  find "$M" -type f -size -513c -exec cp {} "corpus/$T/" \;
  echo "corpus/$T: $(ls "corpus/$T" | wc -l) inputs, $(du -sb "corpus/$T" | cut -f1) B (merged set $(ls "$M" | wc -l) inputs, $(du -sb "$M" | cut -f1) B)"
} >> "$LOG" 2>&1
grep -E "pqz-fuzz (init|summary|FINDING)|^stat::|Done [0-9]+ runs|\[(fuzz|merge) rc|^corpus/|ERROR|SUMMARY" "$LOG"
