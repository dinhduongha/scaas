#!/bin/sh
# upstream LaZer + the fork's unchanged R_REG/R_TX statement builder (pqz_rel.c) and bench (pqz_bench.c)
set -eu
X=$(cd "$(dirname "$0")" && pwd)
docker run --rm --network none --memory=4g -u "$(id -u):$(id -g)" -v "$X":/w -w /w p6d-lazer-build:ubuntu24.04 sh -euc '
  F=/w/fork/pqz-core; L=/w/lazer-up
  CF="-std=gnu11 -O3 -march=native -mtune=native -fomit-frame-pointer -fno-strict-aliasing -DNDEBUG -w"
  INC="-I/w/shim -I$L -I$L/src -I$F/src -I$F/params"
  gcc $CF $INC -c /w/shim/up_rel.c -o /w/up_rel.o
  gcc $CF -c /w/shim/shim.c -o /w/up_shim.o
  gcc $CF -I$F/src -c /w/shim/bench.c -o /w/up_bench.o
  g++ -o /w/bench_up -static /w/up_bench.o /w/up_rel.o /w/up_shim.o $L/liblazer.a $L/third_party/hexl-development/build/hexl/lib/libhexl.a -lmpfr -lgmp -lstdc++ -lm -lpthread
'
ls -la "$X/bench_up"
