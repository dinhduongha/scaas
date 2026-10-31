#!/bin/sh
# sample.sh <container> <seconds> <out>: every 30 s, cgroup anon/file (MiB) + docker stats mem, until <seconds> or exit
C=$1; END=$(( $(date +%s) + $2 )); OUT=$3
ID=$(docker inspect -f '{{.Id}}' "$C") || exit 1
ST=/sys/fs/cgroup/system.slice/docker-$ID.scope/memory.stat
T0=$(docker inspect -f '{{.State.StartedAt}}' "$C" | xargs -I{} date -d {} +%s)
while [ "$(date +%s)" -lt "$END" ] && [ "$(docker inspect -f '{{.State.Running}}' "$C")" = true ]; do
  M=$(awk '$1=="anon"{a=$2} $1=="file"{f=$2} END{printf "anon=%d file=%d", a/1048576, f/1048576}' "$ST" 2>/dev/null)
  D=$(docker stats --no-stream --format '{{.MemUsage}} cpu={{.CPUPerc}}' "$C")
  echo "t=$(( $(date +%s) - T0 ))s $M dstats=$D" | tee -a "$OUT"
  sleep 30
done
