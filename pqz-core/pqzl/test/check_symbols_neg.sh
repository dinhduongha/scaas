#!/bin/sh
# check_symbols.sh's failure paths (STATUS Open 9), after ./build.sh native: a missing file and a non-object must give a
# non-zero exit; the library objects named relative to another directory must pass; test-hook objects must fail.
set -u
cd "$(dirname "$0")/.."
S=$(pwd)/check_symbols.sh rc=0
if "$S" build/native/no-such-object.o 2>/dev/null; then echo "FAIL: a missing file passed"; rc=1; fi
if "$S" check_symbols.sh 2>/dev/null; then echo "FAIL: a non-object passed"; rc=1; fi
(cd build && "$S" native/pqz_*.o) > /dev/null || { echo "FAIL: the library objects, relative to build/"; rc=1; }
# review round 2, Q-H: the objects built with -DPQZ_TEST_HOOKS (build/native/hooks) in place of the library's own fail
H=build/native
if "$S" $H/hooks/pqz_rel.o $H/hooks/pqz_sv.o $H/hooks/pqz_keys.o $H/pqz_lazer.o $H/pqz_ntt.o $H/pqz_arena.o 2> "$H/neg.txt"; then
  echo "FAIL: test-hook objects passed"; rc=1
elif ! grep -q "test hooks in library objects:.*pqz_test_mutate" "$H/neg.txt"; then
  echo "FAIL: test-hook objects refused for another reason: $(cat "$H/neg.txt")"; rc=1
fi
echo "check_symbols_neg: $([ $rc = 0 ] && echo ok || echo FAIL)"
exit $rc
