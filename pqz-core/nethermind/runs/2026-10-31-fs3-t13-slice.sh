#!/bin/sh
# fs3 Task 13 phase B (2026-10-31): one slice of runs/2026-10-30-fs3-t13-calib-step.sh with the host-load gate:
#   pqz-core/nethermind/runs/2026-10-31-fs3-t13-slice.sh <run> <a-b> [<cold processes>]
# Logs the load before / after into runs/fs3-t13-calib/host.txt; a slice whose 1-min load before it is > 1.5 is not
# run (rc 3, "DEFERRED") and is run again after a pause, so no slice is measured on a busy host.
W=$(cd "$(dirname "$0")/../../.." && pwd)
H=$W/pqz-core/nethermind/runs/fs3-t13-calib/host.txt
L=$(cut -d' ' -f1 /proc/loadavg)
echo "## run$1 k$2${3:+ cold$3} $(date -u +%FT%TZ) before $(cut -d' ' -f1-3 /proc/loadavg)" >> "$H"
if awk "BEGIN{exit !($L > 1.5)}"; then echo "  DEFERRED (1-min load $L > 1.5)" | tee -a "$H"; exit 3; fi
cd "$W" && scripts/capped pqz-core/nethermind/runs/2026-10-30-fs3-t13-calib-step.sh "$@"; rc=$?
echo "  after $(date -u +%T) $(cut -d' ' -f1-3 /proc/loadavg) rc=$rc" | tee -a "$H"
exit $rc
