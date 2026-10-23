#!/bin/sh
# pqz-core build: native (libpqz.a, libpqz.so, tests, bench) and freestanding wasm32 (pqz.wasm).
#   ./build.sh native | wasm | all        (outputs in build/)
#   PQZ_SET=<set> ./build.sh ...           the parameter set, params/sets/<set>/ (default n2304-kmax4096; the frozen v3
#                                          set n2048-kmax1024); one set per build directory (B=build/<set> to keep several)
#   PQZ_BUILD_TAG=<tag> ./build.sh ...     the default build directory becomes build/<tag> (gate.sh: the set, so gates of
#                                          different sets run at the same time); the harness scripts (check_tbox_fixes.sh,
#                                          sz/, l2dom/, sv/, the cheating-fixture export) read the same variable
set -eu
cd "$(dirname "$0")"
B=${B:-build${PQZ_BUILD_TAG:+/$PQZ_BUILD_TAG}} # gate.sh: PQZ_BUILD_TAG = the set, so concurrent gates of different sets never share a build
mkdir -p $B/include
CC=${CC:-clang}
WARN="-Wall -Wextra -Wno-unused-parameter -Wno-unused-function -Wno-sign-compare"
# portable: no -march=native (pq-zero-knowledge.md §10), no libc in the library objects
CFLAGS_LIB="-std=gnu11 -O2 -fno-builtin -fno-math-errno -ffp-contract=off $WARN -I$B/include -Isrc -Ilazer -Iparams"

lazer_h() {
  . ./set.sh
  { cat lazer/lazer-in1.h; echo; echo "#ifndef LAZER_CONFIG_H"; echo "#define LAZER_CONFIG_H"
    cat lazer/config.h; echo "#endif"; echo; cat lazer/lazer-in2.h; echo
    echo "/* PQZ: no CRT moduli tables (upstream moduli.h); generated rings name them, the fork ignores them */"
    echo "#define moduli_d64 ((const modulus_srcptr *)0)"
    echo "#define moduli_d128 ((const modulus_srcptr *)0)"; } > $B/include/lazer.h
}

# SV=0: leave the specialised verifier (src/pqz_sv.c, pqz_verify_fast, its tables) out, e.g. the wallet's prover
# wasm (SV=0 B=build/wasm-nosv ./build.sh wasm); the default builds it (PQZ_SV). native-x86v3 needs it.
SV=${SV:-1}
LIBSRC="src/pqz_lazer.c src/pqz_ntt.c src/pqz_arena.c src/pqz_rel.c src/pqz_keys.c"
SVDEF=""
if [ "$SV" = 1 ]; then
  LIBSRC="$LIBSRC src/pqz_sv.c"
  SVDEF="-DPQZ_SV"
  CFLAGS_LIB="$CFLAGS_LIB $SVDEF"
fi
# OVERSIZE=1: also the R_TXM shapes that do not fit MAX_INPUT (M = 16, P6-ANON D3 / D20), for measurement only; never
# in a precompile build (pqz-ffi compiles the core itself, without -DPQZ_TXM_OVERSIZE)
if [ "${OVERSIZE:-0}" = 1 ]; then
  SVDEF="$SVDEF -DPQZ_TXM_OVERSIZE"
  CFLAGS_LIB="$CFLAGS_LIB -DPQZ_TXM_OVERSIZE"
fi

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
  ./check_symbols.sh $objs
  $CC -shared -Wl,--gc-sections -o $B/native/libpqz.so $objs
  # tests and bench (hosted programs; the library objects stay libc-free)
  $CC -std=gnu11 -O2 $WARN $SVDEF -I$B/include -Isrc -o $B/native/pqz_bench test/pqz_bench.c $B/native/libpqz.a
  $CC -std=gnu11 -O2 -DPQZ_BACKEND -DBUILD_FLAGS='"pqz-core native"' -I$B/include -Isrc -Ilazer -Iparams \
    -o $B/native/kat_dump kat/lazer_dump.c $B/native/libpqz.a
  # keys KAT: pqz_keys.c again with the test hooks (lowered thresholds), before the library's own object
  mkdir -p $B/native/hooks
  $CC $CFLAGS_LIB -DPQZ_TEST_HOOKS -c src/pqz_keys.c -o $B/native/hooks/pqz_keys.o
  $CC -std=gnu11 -O2 $WARN -I$B/include -Isrc -Ilazer -Iparams -o $B/native/pqz_keys_kat test/pqz_keys_kat.c \
    $B/native/hooks/pqz_keys.o $B/native/libpqz.a
  [ "$SV" = 1 ] || return 0
  # P6-SV differential test: the relation and specialised-verifier objects again, with the test hooks
  mkdir -p $B/native/hooks
  for f in pqz_rel pqz_sv; do
    $CC $CFLAGS_LIB -DPQZ_TEST_HOOKS -c src/$f.c -o $B/native/hooks/$f.o
  done
  $CC -std=gnu11 -O2 $WARN $SVDEF -I$B/include -Isrc -o $B/native/pqz_sv_diff test/pqz_sv_diff.c $B/native/hooks/pqz_rel.o \
    $B/native/hooks/pqz_sv.o $B/native/pqz_lazer.o $B/native/pqz_ntt.o $B/native/pqz_arena.o
  # the bench with the test-only cheating prover (pqz_bench_hooks n_p n_v mask 1: R_TXM negatives reach the verifiers)
  $CC -std=gnu11 -O2 $WARN $SVDEF -DPQZ_TEST_HOOKS -I$B/include -Isrc -o $B/native/pqz_bench_hooks test/pqz_bench.c \
    $B/native/hooks/pqz_rel.o $B/native/hooks/pqz_sv.o $B/native/pqz_lazer.o $B/native/pqz_ntt.o $B/native/pqz_arena.o
}

# wasm32: freestanding (no libc, no compiler-rt; src/pqz_wasm_rt.c), 8 MiB stack below the data, arena from
# __heap_base (test/run_wasm.mjs grows the memory)
wasm() {
  lazer_h
  mkdir -p $B/wasm
  W="--target=wasm32-unknown-unknown -ffreestanding -fno-builtin -DPQZ_FREESTANDING -Isrc/freestanding"
  [ "${WASM_SIMD:-0}" = 1 ] && W="$W -msimd128" # P6-SV measurement: the spec's -msimd128 target (pq-zero-knowledge.md 11)
  objs=""
  for f in $LIBSRC src/pqz_wasm_rt.c; do
    o=$B/wasm/$(basename "$f" .c).o
    ${CLANG:-clang} $W $CFLAGS_LIB -c "$f" -o "$o"
    objs="$objs $o"
  done
  ./check_symbols.sh $objs
  ${CLANG:-clang} $W $CFLAGS_LIB -DPQZ_WASM -c test/pqz_bench.c -o $B/wasm/pqz_bench.o
  ex=""
  for e in step_init step_prove step_len step_verify step_verify_bad step_hash step_arena_peak step_peak_reset step_set_fast step_nrel __heap_base; do
    ex="$ex --export=$e"
  done
  ${WASM_LD:-wasm-ld-18} --no-entry $ex -z stack-size=8388608 --stack-first --max-memory=4294967296 \
    -o $B/wasm/pqz.wasm $objs $B/wasm/pqz_bench.o
}

# optional x86-64 backend of the specialised verifier (P6-SV): the native library with pqz_sv.c built for
# x86-64-v3 (AVX2) + AES-NI, -O3; everything else as native. The portable build stays the reference.
native_x86v3() {
  [ "$SV" = 1 ] || { echo "native-x86v3 is the specialised verifier's backend: needs SV=1" >&2; exit 2; }
  native
  mkdir -p $B/native-x86v3
  cp $B/native/*.o $B/native-x86v3/
  $CC $CFLAGS_LIB -O3 -march=x86-64-v3 -maes -fPIC -fstack-protector-strong -c src/pqz_sv.c -o $B/native-x86v3/pqz_sv.o
  objs="$B/native-x86v3/pqz_lazer.o $B/native-x86v3/pqz_ntt.o $B/native-x86v3/pqz_arena.o $B/native-x86v3/pqz_rel.o $B/native-x86v3/pqz_keys.o"
  objs="$objs $B/native-x86v3/pqz_sv.o"
  ar rcs $B/native-x86v3/libpqz.a $objs
  ./check_symbols.sh $objs
  $CC -std=gnu11 -O2 $WARN $SVDEF -I$B/include -Isrc -o $B/native-x86v3/pqz_bench test/pqz_bench.c $B/native-x86v3/libpqz.a
  $CC $CFLAGS_LIB -O3 -march=x86-64-v3 -maes -DPQZ_TEST_HOOKS -c src/pqz_sv.c -o $B/native-x86v3/pqz_sv_hooks.o
  $CC -std=gnu11 -O2 $WARN $SVDEF -I$B/include -Isrc -o $B/native-x86v3/pqz_sv_diff test/pqz_sv_diff.c $B/native/hooks/pqz_rel.o \
    $B/native-x86v3/pqz_sv_hooks.o $B/native/pqz_lazer.o $B/native/pqz_ntt.o $B/native/pqz_arena.o
}

case "${1:-native}" in
  native) native ;;
  native-x86v3) native_x86v3 ;;
  wasm) wasm ;;
  all) native && wasm ;;
  *) echo "usage: $0 native|native-x86v3|wasm|all" >&2; exit 2 ;;
esac
