#!/bin/sh
# pqz-bench: R_REG / R_TX prove and verify, upstream LaZer vs the pqz-core fork (README.md).
#
#   ./run.sh [N] [binary ...]     N proves + N verifies per relation (default 5); default: every bench_* here
#   CPU=3 ./run.sh                pin to CPU 3 with taskset (default CPU 1; CPU= disables pinning)
#
# Writes results-<UTC stamp>.json (send that back) and raw-<stamp>/<binary>.txt. Needs only sh, grep, sed.
set -u
cd "$(dirname "$0")"
N=${1:-5}
[ $# -gt 0 ] && shift
BINS=${*:-bench_up_v3 bench_up_v4 bench_fork bench_fork_v3}
CPU=${CPU-1}
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
RAW=raw-$STAMP
OUT=results-$STAMP.json
mkdir -p "$RAW"

MODEL=$(grep -m1 '^model name' /proc/cpuinfo | sed 's/^[^:]*: *//')
FLAGS=$(grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n' | grep -xE 'aes|vaes|avx2|avx512f|avx512dq|avx512vl|avx512ifma|avx512vbmi2' | tr '\n' ' ' | sed 's/ $//')
KB=$(sed -n 's/^MemTotal: *\([0-9]*\).*/\1/p' /proc/meminfo)
MEM=$(( (${KB:-0} + 524288) / 1048576 ))
PFX=
if [ -n "$CPU" ] && taskset -c "$CPU" true 2>/dev/null; then PFX="taskset -c $CPU"; else CPU=; fi
export OMP_NUM_THREADS=1

echo "cpu:   $MODEL ($(grep -c ^processor /proc/cpuinfo) threads, $MEM GB)"
echo "flags: $FLAGS"
echo "N=$N, pinned to CPU ${CPU:-none}; medians in ms"
printf '%-14s %10s %10s %10s %10s %9s %9s\n' binary reg_prove reg_verify tx_prove tx_verify reg_bytes tx_bytes

p50() { grep "\"timing\": \"$1\"" "$2" | sed 's/.*"p50_ms": \([0-9.]*\).*/\1/'; }
bytes() { grep "\"rel\": \"$1\", \"proof_bytes_last\"" "$2" | sed 's/.*"proof_bytes_max": \([0-9]*\).*/\1/'; }

{
  printf '{"bundle": "%s", "date": "%s", "cpu": "%s", "flags": "%s", "threads": %s, "mem_gb": %s, ' \
    "$(basename "$(pwd)")" "$STAMP" "$MODEL" "$FLAGS" "$(grep -c ^processor /proc/cpuinfo)" "$MEM"
  printf '"kernel": "%s", "n": %s, "pinned_cpu": "%s", "results": [' "$(uname -r)" "$N" "$CPU"
} > "$OUT"
sep=
for b in $BINS; do
  why=
  [ -x "./$b" ] || why="missing"
  case $b in *v4*) case " $FLAGS " in *" avx512ifma "*) ;; *) why="no avx512ifma on this CPU" ;; esac ;; esac
  if [ -n "$why" ]; then
    printf '%-14s skipped: %s\n' "$b" "$why"
    printf '%s\n  {"bin": "%s", "skipped": "%s"}' "$sep" "$b" "$why" >> "$OUT"
  else
    f=$RAW/$b.txt
    $PFX "./$b" "$N" "$N" > "$f" 2>&1
    rc=$?
    fails=$(grep '"fails"' "$f" | sed 's/[^0-9]//g')
    rp=$(p50 "R_REG prove" "$f") rv=$(p50 "R_REG verify valid" "$f") tp=$(p50 "R_TX prove" "$f") tv=$(p50 "R_TX verify valid" "$f")
    rb=$(bytes R_REG "$f") tb=$(bytes R_TX "$f")
    printf '%-14s %10s %10s %10s %10s %9s %9s' "$b" "${rp:--}" "${rv:--}" "${tp:--}" "${tv:--}" "${rb:--}" "${tb:--}"
    [ "$rc" = 0 ] && [ "${fails:-1}" = 0 ] && echo || echo "  FAILED (exit $rc, fails ${fails:-?}; see $f)"
    printf '%s\n  {"bin": "%s", "reg_prove_ms": %s, "reg_verify_ms": %s, "tx_prove_ms": %s, "tx_verify_ms": %s, "reg_bytes_max": %s, "tx_bytes_max": %s, "fails": %s, "exit": %s}' \
      "$sep" "$b" "${rp:-null}" "${rv:-null}" "${tp:-null}" "${tv:-null}" "${rb:-null}" "${tb:-null}" "${fails:-null}" "$rc" >> "$OUT"
  fi
  sep=,
done
printf '\n]}\n' >> "$OUT"
echo "wrote $OUT (raw output in $RAW/)"
