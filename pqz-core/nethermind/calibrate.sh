#!/bin/sh
# P6f Task 6 (D7): ONE gas calibration run inside the calib image (build-image.sh with CALIB=1), on the chain host.
#   scripts/capped pqz-core/nethermind/calibrate.sh pqz1    -> runs/<date>-calib.txt, runs/<date>-calib-engine-pqz.json
# Writes chain/engine-pqz.json from the run (timestamp 0x0: patch-chainspec.py fills it in).
#   scripts/capped pqz-core/nethermind/calibrate.sh pqz2 --ops 7   (P6-ANON S8) only the op 7 rows; chain/engine-pqz.json
#   is left alone (the op 7 rows join the live rows in a second schedule).
set -eu
cd "$(dirname "$0")"
TAG=scaas/nethermind-pqz:2.2.0-${1:?label, e.g. pqz1}-calib
shift
D=$(date +%F)-calib${1:+-ops$(echo "$*" | tr -cd 0-9)}
mkdir -p runs
PRE="load before: $(cut -d" " -f1-3 /proc/loadavg)"
docker run --rm --memory 4g --cpus 4 -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$(pwd)/runs:/out" "$TAG" \
  run /opt/pqz-calibrate/data/corpus.jsonl /opt/pqz-calibrate/data/fresh.jsonl /opt/pqz-calibrate/data/ua /out --label "$D" "$@"
[ $# -gt 0 ] || cp "runs/$D-engine-pqz.json" chain/engine-pqz.json
echo "# image $TAG $(docker image inspect "$TAG" --format '{{.Id}}'); host $PRE, after: $(cut -d" " -f1-3 /proc/loadavg)" >> "runs/$D.txt"
tail -1 "runs/$D.txt"
