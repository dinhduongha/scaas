#!/bin/sh
set -eu
X=$(cd "$(dirname "$0")" && pwd)
F=$X/fork/pqz-core
docker run --rm --network none --memory=4g -u "$(id -u):$(id -g)" -v "$X":/w -w /w p6d-lazer-build:ubuntu24.04 sh -euc '
  L=/w/lazer-up
  gcc -std=gnu11 -O3 -march=native -mtune=native -fno-strict-aliasing -DNDEBUG -DUPSTREAM -w -I$L -I$L/src -I/w/fork/pqz-core/params -c /w/shim/micro.c -o /w/micro_up.o
  g++ -static -o /w/micro_up /w/micro_up.o $L/liblazer.a $L/third_party/hexl-development/build/hexl/lib/libhexl.a -lmpfr -lgmp -lstdc++ -lm -lpthread'
for v in as native; do
  clang -std=gnu11 -O2 -w -I$X/fork-$v/build/include -I$X/fork-$v/src -I$X/fork-$v/lazer -I$X/fork-$v/params -o $X/micro_fork_$v $X/shim/micro.c $X/fork-$v/build/native/libpqz.a
done
ls -la $X/micro_*
