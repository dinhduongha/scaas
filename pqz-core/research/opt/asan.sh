#!/bin/sh
# P6d-2 sanitizer run of the current tree: libc heap instead of the arena (-DPQZ_DEBUG_MALLOC), ASan + UBSan,
# one prove + verify (+ adversarial verifies) per relation under scripts/capped.
#   opt/asan.sh            (output: opt/runs/asan.jsonl, sanitizer reports on stderr)
set -eu
cd "$(dirname "$0")/../../pqzl" # the PQZL core: build/, src/, test/, kat/
CAPPED=${CAPPED:-$(git rev-parse --show-toplevel)/scripts/capped}
./build.sh native >/dev/null # lazer.h
mkdir -p build/asan
F="-std=gnu11 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -DPQZ_DEBUG_MALLOC -w -Ibuild/include -Isrc -Ilazer -Iparams"
${CC:-clang} $F -o build/asan/pqz_bench src/pqz_lazer.c src/pqz_ntt.c src/pqz_arena.c src/pqz_rel.c test/pqz_bench.c
# detect_leaks=0: the relation layer (pqz_rel.c) frees its statement objects by arena release, which the
# malloc path does not have, so LSan reports them (also on main: ~650 MB in ~2 * 10^5 allocations)
ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=print_stacktrace=1 $CAPPED build/asan/pqz_bench 1 1 > ../research/opt/runs/asan.jsonl
cat ../research/opt/runs/asan.jsonl
