#!/bin/sh
# C core hardening tests (2026-10-18): test/pqz_ub_test.c under UBSan + ASan (clang, -fno-sanitize-recover=all,
# libc heap via -DPQZ_DEBUG_MALLOC), one process per part (a fixexp / rejection, b encrypt / decrypt, c poly_auto_self;
# review round 2: d .. f on the libc heap, g, h on the arena: test/pqz_ub_test.c) so a sanitizer abort in one part does
# not hide the others. Run from anywhere, under scripts/capped:
#   scripts/capped pqz-core/pqzl/test/ub_test.sh <label>       -> test/runs/ub-<label>.txt; exit 1 if a part fails
# RECOVER=1: UBSan reports every site and carries on (lists all of them on unfixed code; not a pass criterion)
set -u
cd "$(dirname "$0")/.." # pqzl
L=${1:?label}
O=test/runs/ub-$L.txt
mkdir -p test/runs build/ub
./build.sh native > /dev/null || exit 1 # lazer.h
CC=${CC:-clang-18}
F="-std=gnu11 -O1 -g -fsanitize=undefined,address -fno-omit-frame-pointer -DPQZ_SV"
[ "${RECOVER:-0}" = 1 ] || F="$F -fno-sanitize-recover=all"
# pointer-overflow on since review round 2 (Q-F fixed the upstream null + 0 in aes256ctr.c, STATUS.md Open 4)
F="$F -w -Ibuild/include -Isrc -Ilazer -Iparams"
SRC="src/pqz_lazer.c src/pqz_ntt.c src/pqz_arena.c src/pqz_rel.c src/pqz_keys.c src/pqz_sv.c test/pqz_ub_test.c"
{
  echo "# ub_test $L: $(git rev-parse --short HEAD)$(git diff --quiet HEAD -- src lazer || echo ' + uncommitted src/lazer changes'), $($CC --version | head -1)"
  echo "# $CC $F [-DPQZ_DEBUG_MALLOC]"
  # parts a .. f on the libc heap (ASan sees each block); g, h on the arena (pqz_ub_arena)
  $CC $F -DPQZ_DEBUG_MALLOC -o build/ub/pqz_ub_test $SRC 2>&1
  $CC $F -o build/ub/pqz_ub_arena $SRC 2>&1
} > "$O"
fail=0
for p in a b c d e f g h; do
  case $p in g | h) B=build/ub/pqz_ub_arena ;; *) B=build/ub/pqz_ub_test ;; esac
  echo "== part $p" >> "$O"
  ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=print_stacktrace=1 $B $p >> "$O" 2>&1
  rc=$?
  echo "== part $p rc=$rc" >> "$O"
  [ $rc = 0 ] || fail=1
done
echo "ub_test $L: $( [ $fail = 0 ] && echo PASS || echo FAIL )" | tee -a "$O"
exit $fail
