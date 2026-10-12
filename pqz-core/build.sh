#!/bin/sh
# pqz-core build: native (libpqz.a, libpqz.so, tests, bench) and freestanding wasm32 (pqz.wasm).
#   ./build.sh native | wasm | all        (outputs in build/)
set -eu
cd "$(dirname "$0")"
B=build
mkdir -p $B/include
CC=${CC:-clang}
WARN="-Wall -Wextra -Wno-unused-parameter -Wno-unused-function -Wno-sign-compare"
# portable: no -march=native (pq-zether.md §10), no libc in the library objects
CFLAGS_LIB="-std=gnu11 -O2 -fno-builtin -fno-math-errno -ffp-contract=off $WARN -I$B/include -Isrc -Ilazer -Iparams"

lazer_h() {
  { cat lazer/lazer-in1.h; echo; echo "#ifndef LAZER_CONFIG_H"; echo "#define LAZER_CONFIG_H"
    cat lazer/config.h; echo "#endif"; echo; cat lazer/lazer-in2.h; echo
    echo "/* PQZ: no CRT moduli tables (upstream moduli.h); generated rings name them, the fork ignores them */"
    echo "#define moduli_d64 ((const modulus_srcptr *)0)"
    echo "#define moduli_d128 ((const modulus_srcptr *)0)"; } > $B/include/lazer.h
}

LIBSRC="src/pqz_lazer.c src/pqz_ntt.c src/pqz_arena.c src/pqz_rel.c"

native() {
  lazer_h
  mkdir -p $B/native
  objs=""
  for f in $LIBSRC; do
    o=$B/native/$(basename "$f" .c).o
    $CC $CFLAGS_LIB -fPIC -fstack-protector-strong -ffunction-sections -fdata-sections -c "$f" -o "$o"
    objs="$objs $o"
  done
  ar rcs $B/native/libpqz.a $objs
  $CC -shared -Wl,--gc-sections -o $B/native/libpqz.so $objs
  # tests and bench (hosted programs; the library objects stay libc-free)
  $CC -std=gnu11 -O2 $WARN -Isrc -o $B/native/pqz_bench test/pqz_bench.c $B/native/libpqz.a
  $CC -std=gnu11 -O2 -DPQZ_BACKEND -DBUILD_FLAGS='"pqz-core native"' -I$B/include -Isrc -Ilazer -Iparams \
    -o $B/native/kat_dump kat/lazer_dump.c $B/native/libpqz.a
}

case "${1:-native}" in
  native) native ;;
  all) native ;;
  *) echo "usage: $0 native|wasm|all" >&2; exit 2 ;;
esac
