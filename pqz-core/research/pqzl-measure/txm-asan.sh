#!/bin/sh
# P6-ANON Track L: ASan + UBSan (libc heap, -DPQZ_DEBUG_MALLOC) of the bench with the test hooks: R_REG / R_TX / R_TX0
# and every built R_TXM shape (generic and SV verifier), then txm_check one case per process (PQZ_TXM_CASE), so each
# process stays under scripts/capped's 4 GB (txm_check in one process was OOM-killed). Called by txm.sh; alone:
#   scripts/capped pqz-core/research/pqzl-measure/txm-asan.sh <label>        rel3/runs/<label>-asan.jsonl, -asan-stderr.txt
set -eu
cd "$(dirname "$0")/../../pqzl" # the PQZL core: build/, src/, test/, kat/
R=../research/pqzl-measure/runs/$1
export PQZ_ARENA_MB=${ARENA_MB:-2048}
mkdir -p build/asan
# known upstream UBSan nits (STATUS.md, sv/fuzz.sh): zero-length VLAs, null + 0 in aes256ctr.c; one process per shape
F="-std=gnu11 -O1 -g -fsanitize=address,undefined -fno-sanitize=vla-bound,pointer-overflow -fno-omit-frame-pointer -DPQZ_DEBUG_MALLOC -DPQZ_SV -DPQZ_TEST_HOOKS -w -Ibuild/include -Isrc -Ilazer -Iparams"
${CC:-clang} $F -o build/asan/pqz_bench src/pqz_lazer.c src/pqz_ntt.c src/pqz_arena.c src/pqz_rel.c src/pqz_keys.c src/pqz_sv.c test/pqz_bench.c
: > "$R-asan.jsonl"; : > "$R-asan-stderr.txt"
export ASAN_OPTIONS=detect_leaks=0:quarantine_size_mb=64:malloc_context_size=5 UBSAN_OPTIONS=print_stacktrace=1
for m in 35 64 128 256 512 1024 2048 4096 8192; do # R_REG + R_TX + R_TX0, then each R_TXM shape; generic and SV
  for v in generic fast; do
    PQZ_VERIFY=$v build/asan/pqz_bench 1 1 $m >> "$R-asan.jsonl" 2>> "$R-asan-stderr.txt" || echo "asan $m $v rc=$?"
  done
done
for k in 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17; do # txm_check, one case per process (17: the statement tampers)
  PQZ_TXM_CASE=$k build/asan/pqz_bench 0 0 0 1 >> "$R-asan.jsonl" 2>> "$R-asan-stderr.txt" || echo "asan txm_check $k rc=$?"
done
grep -h -e '"fails"' -e '"txm_check": [tf]' "$R-asan.jsonl" | sort | uniq -c
echo "sanitizer reports: $(grep -c "runtime error\|ERROR: AddressSanitizer" "$R-asan-stderr.txt" || true)"
