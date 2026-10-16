#!/bin/sh
# PQZL verifier floor microbenchmarks (docs/research/pqz-verifier-floor.md). Run from anywhere:
#   floor/build.sh            builds build/floor/{kern_portable,kern_native,count,kern.wasm} (runs ../build.sh
#                             native / wasm first if their outputs are missing)
#   floor/build.sh run        also runs them, one at a time, and writes floor/runs/*.json and the floor table
#                             floor/runs/model.md (floor/model.py: operation counts x measured unit costs)
#   KERN_QUICK=1 build/floor/kern_native   runs every kernel's self-check once, no timing
# Heavy: run under scripts/capped. kern_native needs AVX2 and OpenSSL 3 (libcrypto) headers.
set -eu
cd "$(dirname "$0")/../../pqzl" # the PQZL core: build/, src/, test/, kat/
B=build
O=$B/floor
mkdir -p $O ../research/floor/runs
[ -f $B/native/libpqz.a ] || ./build.sh native
[ -f $B/wasm/pqz_lazer.o ] || ./build.sh wasm
CC=${CC:-clang}
INC="-I$B/include -Isrc -Ilazer -Iparams"
WARN="-Wall -Wextra -Wno-unused-parameter -Wno-unused-function -Wno-sign-compare"

# unit costs: portable (as the fork ships: -O2, generic x86-64) and native (-O3 -march=native, AVX2, OpenSSL)
$CC -std=gnu11 -O2 $WARN $INC -o $O/kern_portable ../research/floor/kern.c $B/native/libpqz.a
$CC -std=gnu11 -O3 -march=native -mtune=native -DWITH_OPENSSL $WARN $INC -o $O/kern_native ../research/floor/kern.c \
  $B/native/libpqz.a -lcrypto

# operation counts of the fork's verifier: the library rebuilt with pqz_ntt.c's entry points renamed
CFLAGS_LIB="-std=gnu11 -O2 -fno-builtin -fno-math-errno -ffp-contract=off $WARN $INC"
REN="-Dpqz_red128=real_red128 -Dpqz_ntt_fwd=real_ntt_fwd -Dpqz_ntt_inv=real_ntt_inv -Dpqz_ntt_basemul=real_ntt_basemul"
$CC $CFLAGS_LIB $REN -c src/pqz_ntt.c -o $O/pqz_ntt_real.o
for f in pqz_lazer pqz_arena pqz_rel; do $CC $CFLAGS_LIB -c src/$f.c -o $O/$f.o; done
$CC -std=gnu11 -O2 $WARN -Isrc -Dmain=pqz_bench_main -c test/pqz_bench.c -o $O/pqz_bench_steps.o
$CC -std=gnu11 -O2 $WARN -Isrc -o $O/count ../research/floor/count.c $O/pqz_bench_steps.o $O/pqz_lazer.o $O/pqz_arena.o \
  $O/pqz_rel.o $O/pqz_ntt_real.o

# the portable kernels in freestanding wasm32 (same flags as ../build.sh wasm, no SIMD)
W="--target=wasm32-unknown-unknown -ffreestanding -fno-builtin -DPQZ_FREESTANDING -Isrc/freestanding"
${CLANG:-clang} $W $CFLAGS_LIB -c ../research/floor/wasm.c -o $O/wasm_kern.o
${WASM_LD:-wasm-ld-18} --no-entry --export=check --export=bench --allow-undefined -z stack-size=1048576 \
  -o $O/kern.wasm $O/wasm_kern.o $B/wasm/pqz_lazer.o $B/wasm/pqz_ntt.o $B/wasm/pqz_arena.o $B/wasm/pqz_wasm_rt.o

if [ "${1:-}" = run ]; then
  $O/kern_portable > ../research/floor/runs/kern_portable.json
  $O/kern_native > ../research/floor/runs/kern_native.json
  node ../research/floor/run_wasm.mjs > ../research/floor/runs/kern_wasm.json
  $O/count > ../research/floor/runs/count.json
  python3 -I ../research/floor/model.py > ../research/floor/runs/model.md
  cat ../research/floor/runs/*.json ../research/floor/runs/model.md
fi
