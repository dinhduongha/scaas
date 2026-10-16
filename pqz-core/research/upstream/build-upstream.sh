#!/bin/sh
# Build upstream LaZer 3330e48 (+ HEXL from its third_party zip, static GMP/MPFR) inside the offline
# p6d-lazer-build image. Flags = upstream Makefile defaults (-O3 -march=native -mtune=native
# -fomit-frame-pointer) + -fno-strict-aliasing (aes256ctr-amd64.c bug) + -DNDEBUG.
set -eu
X=$(cd "$(dirname "$0")" && pwd)
docker run --rm --network none --memory=4g -u "$(id -u):$(id -g)" -v "$X":/w -w /w p6d-lazer-build:ubuntu24.04 sh -euc '
  cd /w/lazer-up/third_party
  rm -rf hexl-development && unzip -q hexl-development.zip
  (cd hexl-development && cmake -S . -B build -DHEXL_BENCHMARK=OFF -DHEXL_TESTING=OFF -DCpuFeatures_DIR=/w/stub/cpuf >/w/hexl-cmake.log 2>&1 \
     && cmake --build build -j4 >/w/hexl-build.log 2>&1)
  mkdir -p hexl-development/build/hexl/lib64 && cp hexl-development/build/hexl/lib/libhexl.a hexl-development/build/hexl/lib64/
  touch hexl-development
  cd /w/lazer-up
  make lazer.h liblazer.a CFLAGS="-Wall -O3 -g -march=native -mtune=native -fomit-frame-pointer -DFALCON_FPNATIVE -DFALCON_AVX2 -DFALCON_FMA -DNDEBUG -fno-strict-aliasing" >/w/lazer-build.log 2>&1
  { gcc --version | head -1; cmake --version | head -1; dpkg-query -W libgmp-dev libmpfr-dev; gcc -march=native -Q --help=target 2>/dev/null | grep -E "^\s+-march=|-mavx512f |-mavx2 "; } > /w/build-info-upstream.txt
'
cat "$X/build-info-upstream.txt"
