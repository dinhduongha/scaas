#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# One fuzz run of one target (ua-rs-sign T11), under scripts/capped, foreground, after build.sh:
#   scripts/capped clients/ua-rs/fuzz/run.sh <target> <seconds> [label]
#   target: typed_data | expect | tx | vault | manifest | container | sealed | kem_pk | mnemonic
# Fuzzes target/fuzz/ua-fuzz on a work corpus (target/fuzz/work/<target>), the seeds rebuilt from the vector files
# (seeds.py, target/fuzz/seeds/<target>) and regress/<target>/ (the inputs past each cap, and any crash input with its fix).
# Log: runs/<label>-<target>.log (git-ignored; the record commits a summary). A crash input lands in
# target/fuzz/crash-<target>-*: minimise it (-minimize_crash=1), copy it to regress/<target>/ with the fix.
set -u
cd "$(dirname "$0")"
T=$1 S=$2 L=${3:-$(date +%F)}
B=$(cd .. && pwd)/target/fuzz${UA_FUZZ_TAG:+-$UA_FUZZ_TAG} # UA_FUZZ_TAG: a build of its own (the mutant harness)
W=$B/work/$T SEEDS=$B/seeds LOG=runs/$L-$T.log
mkdir -p "$W" runs "regress/$T"
# the JSON targets up to the 64 KiB typed-data cap (the 16 KiB caps are reached); the binary ones a little past their forms
case $T in kem_pk | sealed | mnemonic) ML=4096 ;; *) ML=65536 ;; esac
export UA_FUZZ_TARGET=$T ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=print_stacktrace=1
python3 -I seeds.py "$SEEDS" > "$LOG" 2>&1 || { cat "$LOG"; exit 1; }
{
  echo "# fuzz $T, $S s, $(date -Is), commit $(git rev-parse --short HEAD), $(clang-18 --version | head -1), $(rustc --version)"
  "$B/ua-fuzz" -max_total_time="$S" -max_len=$ML -rss_limit_mb=2048 -timeout=30 -print_final_stats=1 \
    -artifact_prefix="$B/crash-$T-" "$W" "regress/$T" "$SEEDS/$T"
  echo "[fuzz rc=$?]"
} >> "$LOG" 2>&1
grep -E "ua-fuzz FINDING|^stat::number_of_executed_units|^stat::peak_rss|Done [0-9]+ runs|\[fuzz rc|ERROR|SUMMARY|deadly signal" "$LOG"
