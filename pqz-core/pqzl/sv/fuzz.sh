#!/bin/sh
# P6-SV sanitizer runs, under scripts/capped:
#  1. ASan + UBSan, libc heap instead of the arena (-DPQZ_DEBUG_MALLOC): pqz_bench with the specialised verifier
#     (honest + adversarial verifies of both relations) -> sv/runs/<label>-asan.jsonl
#  2. libFuzzer (test/pqz_sv_fuzz.c, ASan + UBSan, arena build): edit scripts over honest proofs, the generic and
#     the specialised verifier must agree -> sv/runs/<label>-fuzz.txt
#   sv/fuzz.sh <label> [fuzz seconds]          (default 600)
set -eu
cd "$(dirname "$0")/.."
CAPPED=${CAPPED:-$(git rev-parse --show-toplevel)/scripts/capped}
L=$1 T=${2:-600}
./build.sh native >/dev/null 2>&1 # lazer.h
mkdir -p build/sv-san sv/runs
SRC="src/pqz_lazer.c src/pqz_ntt.c src/pqz_arena.c src/pqz_rel.c src/pqz_sv.c"
INC="-std=gnu11 -g -fno-omit-frame-pointer -w -DPQZ_SV -Ibuild/include -Isrc -Ilazer -Iparams"
# known upstream UBSan nits (STATUS.md): zero-length VLAs (M = 0 / nbin = 0), null + 0 in aes256ctr.c
SAN="-fsanitize=address,undefined -fno-sanitize=vla-bound,pointer-overflow -fno-sanitize-recover=all"
${CC:-clang} -O1 $INC $SAN -DPQZ_DEBUG_MALLOC -o build/sv-san/pqz_bench $SRC test/pqz_bench.c
ASAN_OPTIONS=detect_leaks=0 PQZ_VERIFY=fast $CAPPED build/sv-san/pqz_bench 1 3 > "sv/runs/$L-asan.jsonl" 2>&1 \
  || echo "asan rc=$?"
${CC:-clang} -O1 $INC $SAN -fsanitize=fuzzer -o build/sv-san/pqz_sv_fuzz $SRC test/pqz_sv_fuzz.c
mkdir -p build/sv-san/corpus
ASAN_OPTIONS=detect_leaks=0 $CAPPED build/sv-san/pqz_sv_fuzz -max_total_time="$T" -max_len=256 -seed=1 \
  -rss_limit_mb=3500 build/sv-san/corpus > "sv/runs/$L-fuzz.txt" 2>&1 || echo "fuzz rc=$?"
grep -h -e timing -e fails "sv/runs/$L-asan.jsonl"
grep -E "^#[0-9]+ +(DONE|pulse)|ERROR|Done" "sv/runs/$L-fuzz.txt" | tail -3
