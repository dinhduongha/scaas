#!/bin/sh
# gprof builds (perf is unavailable: kernel.perf_event_paranoid = 4): upstream liblazer C code and the fork's
# libpqz with -pg; HEXL / GMP / libc are not instrumented but still appear in the flat (sampled) profile.
set -eu
X=$(cd "$(dirname "$0")" && pwd)
rm -rf "$X/lazer-prof" && cp -a "$X/lazer-up" "$X/lazer-prof"
docker run --rm --network none --memory=4g -u "$(id -u):$(id -g)" -v "$X":/w -w /w p6d-lazer-build:ubuntu24.04 sh -euc '
  cd /w/lazer-prof && rm -f src/lazer_static.o liblazer.a
  make liblazer.a CFLAGS="-Wall -O3 -g -pg -march=native -mtune=native -DFALCON_FPNATIVE -DFALCON_AVX2 -DFALCON_FMA -DNDEBUG -fno-strict-aliasing" >/w/lazer-prof-build.log 2>&1
  F=/w/fork/pqz-core; L=/w/lazer-prof
  CF="-std=gnu11 -O3 -pg -march=native -mtune=native -fno-strict-aliasing -DNDEBUG -w"
  gcc $CF -I/w/shim -I$L -I$L/src -I$F/src -I$F/params -c /w/shim/up_rel.c -o /w/upp_rel.o
  gcc $CF -c /w/shim/shim.c -o /w/upp_shim.o
  gcc $CF -I$F/src -c /w/shim/bench.c -o /w/upp_bench.o
  g++ -pg -o /w/bench_up_prof -static /w/upp_bench.o /w/upp_rel.o /w/upp_shim.o $L/liblazer.a $L/third_party/hexl-development/build/hexl/lib/libhexl.a -lmpfr -lgmp -lstdc++ -lm -lpthread'
rm -rf "$X/fork-prof" && cp -a "$X/fork/pqz-core" "$X/fork-prof"
sed -i 's/^CFLAGS_LIB="-std=gnu11 -O2 /CFLAGS_LIB="-std=gnu11 -O2 -pg /' "$X/fork-prof/build.sh"
sed -i 's/ -fstack-protector-strong//; s/^  \$CC -shared.*$/  :/' "$X/fork-prof/build.sh"
(cd "$X/fork-prof" && ./build.sh native >/dev/null 2>&1 || true)
clang -std=gnu11 -O2 -pg -w -I"$X/fork-prof/src" -o "$X/bench_fork_prof" "$X/shim/bench.c" "$X/fork-prof/build/native/libpqz.a"
ls -la "$X/bench_up_prof" "$X/bench_fork_prof"
