#!/bin/sh
# fs3 Task 13 phase B3 (2026-10-31): reproduce.sh --multi-bench split into resumable steps, one docker run each (the
# shell tool keeps a command in the foreground for at most 10 minutes). Each step is one command of reproduce.sh's
# multi branch (or of the per-shape loop body of research/pqzl-measure/txm-bench.sh / the Rust loop) with the same
# sample sizes and output file names; sources and build trees live in the named volume fs3t13-src (filled from the
# image's /src on first use), output in runs/fs3-t13-docker-multi/ (= reproduce.sh's $OUT):
#   scripts/capped pqz-core/artifact/runs/2026-10-31-fs3-t13-multi-step.sh <step> '<sh command, cwd /src/pqz-core>'
# A step whose steps/<step>.txt ends in rc=0 is skipped (resume); log.txt has the host load before / after each step.
set -u
cd "$(dirname "$0")"
O=$(pwd)/fs3-t13-docker-multi
mkdir -p "$O/steps"
S=$O/steps/$1.txt
[ "$(tail -1 "$S" 2>/dev/null)" != rc=0 ] || { echo "skip $1 (done)"; exit 0; }
echo "== $(date -u +%T) $1 load before $(cut -d' ' -f1-3 /proc/loadavg)" >> "$O/log.txt"
# timed steps (GATE=1): not run while the 1-min load is > 1.5 (rc 3, run again after a pause); builds run ungated
L=$(cut -d' ' -f1 /proc/loadavg)
if [ "${GATE:-0}" = 1 ] && awk "BEGIN{exit !($L > 1.5)}"; then echo "   DEFERRED (1-min load $L > 1.5)" | tee -a "$O/log.txt"; exit 3; fi
docker run --rm --memory=4g --memory-swap=4g --network none -u "$(id -u):$(id -g)" -e OUT=/out \
  -e PQZ_SET=n2304-kmax4096 -v fs3t13-src:/src -v "$O:/out" -w /src/pqz-core --entrypoint sh pqz-core-artifact:fs3-t13 \
  -c "$2" > "$S" 2>&1 && r=0 || r=$?
echo "rc=$r" >> "$S"
echo "   $(date -u +%T) $1 rc=$r load after $(cut -d' ' -f1-3 /proc/loadavg)" >> "$O/log.txt"
echo "$1 rc=$r $(tail -2 "$O/log.txt" | tr '\n' ' ')"
[ $r = 0 ] || tail -5 "$S"
exit $r
