#!/bin/sh
# check_symbols.sh's failure paths (STATUS Open 9), after ./build.sh native: a missing file and a non-object must give a
# non-zero exit; the library objects named relative to another directory must pass.
set -u
cd "$(dirname "$0")/.."
S=$(pwd)/check_symbols.sh rc=0
if "$S" build/native/no-such-object.o 2>/dev/null; then echo "FAIL: a missing file passed"; rc=1; fi
if "$S" check_symbols.sh 2>/dev/null; then echo "FAIL: a non-object passed"; rc=1; fi
(cd build && "$S" native/pqz_*.o) > /dev/null || { echo "FAIL: the library objects, relative to build/"; rc=1; }
echo "check_symbols_neg: $([ $rc = 0 ] && echo ok || echo FAIL)"
exit $rc
