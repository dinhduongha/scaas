#!/bin/sh
# Build the upstream side of the arithmetic-layer KAT: a fully static x86-64 `lazer_dump` linked against
# LaZer 3330e48 (+ Intel HEXL from LaZer's third_party zip, distro static GMP / MPFR, static libstdc++).
#
#   kat/build-lazer-dump.sh <work dir> [v4|v3]      -> <work dir>/lazer_dump-<variant> + build-info-<variant>.txt
#
#   v4 (default): -march=x86-64-v4 -mavx512ifma -mavx512vbmi2 -maes -mpclmul, HEXL's AVX-512 kernels forced
#                 in (HEXL normally enables them only if its configure-time try_run succeeds on the build
#                 host). Runs only on an AVX-512 CPU or under Intel SDE:  sde64 -spr -- ./lazer_dump-v4
#   v3:           -march=x86-64-v3 -maes -mpclmul (HEXL's portable/AVX2 path), runs on any recent x86-64.
#
# -fno-strict-aliasing: upstream's AES-NI init reads the uint64_t nonce through an unsigned long long pointer
# (aes256ctr-amd64.c); gcc 13 -O2 then drops the rng domain separator (every dom gives the dom-0 stream).
# Then on the target machine:  ./lazer_dump-v4 > lazer-3330e48.json   and   python3 kat/check.py ...
# The binary and the fetched sources are build outputs: never commit them. A statically linked GMP / MPFR
# binary carries LGPL relinking duties if distributed (pqz-core/README.md).
# Needs docker and network (apt, the LaZer clone, HEXL's cpu_features clone).
set -eu
W=$(mkdir -p "$1" && cd "$1" && pwd)
V=${2:-v4}
HERE=$(cd "$(dirname "$0")/.." && pwd)
PIN=3330e487228f633eceb322807b13a596b516770f
IMG=ubuntu@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55   # ubuntu:24.04
case "$V" in
  v4) MARCH="-march=x86-64-v4 -mavx512ifma -mavx512vbmi2 -maes -mpclmul" ;;
  v3) MARCH="-march=x86-64-v3 -maes -mpclmul" ;;
  *) echo "variant must be v4 or v3" >&2; exit 2 ;;
esac

if [ ! -d "$W/lazer-$V/.git" ]; then
  git clone -q https://github.com/lazer-crypto/lazer "$W/lazer-$V"
fi
git -C "$W/lazer-$V" checkout -q "$PIN"
[ "$(git -C "$W/lazer-$V" rev-parse HEAD)" = "$PIN" ] || { echo "LaZer is not at $PIN" >&2; exit 1; }

cp "$HERE/kat/lazer_dump.c" "$HERE/params/pqz_tx_params.h" "$W/"

docker run --rm --memory=4g -e MARCH="$MARCH" -e V="$V" -v "$W":/w -w /w "$IMG" sh -euc '
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null
  apt-get install -y -qq build-essential cmake git unzip libgmp-dev libmpfr-dev >/dev/null
  cd /w/lazer-$V/third_party
  rm -rf hexl-development && unzip -q hexl-development.zip
  # HEXL: no -march=native; with v4 the AVX-512 kernels are compiled in (compile check instead of try_run)
  sed -i "s/-march=native/$MARCH/" hexl-development/hexl/CMakeLists.txt hexl-development/cmake/hexl/hexl-util.cmake
  if [ "$V" = v4 ]; then
    sed -i "s/if (CAN_COMPILE AND CAN_RUN STREQUAL 0)/if (CAN_COMPILE)/" hexl-development/cmake/hexl/hexl-util.cmake
  fi
  (cd hexl-development && cmake -S . -B build -DHEXL_BENCHMARK=OFF -DHEXL_TESTING=OFF >/w/hexl-cmake-$V.log 2>&1 \
     && cmake --build build -j4 >/w/hexl-build-$V.log 2>&1)
  mkdir -p hexl-development/build/hexl/lib64 && cp hexl-development/build/hexl/lib/libhexl.a hexl-development/build/hexl/lib64/
  touch hexl-development
  cd /w/lazer-$V
  make lazer.h liblazer.a CFLAGS="-O2 -g0 $MARCH -DNDEBUG -fno-strict-aliasing" >/w/lazer-build-$V.log 2>&1
  g++ -x c -std=gnu11 -O2 -fno-strict-aliasing $MARCH -DBUILD_FLAGS="\"lazer 3330e48 static $V: $MARCH\"" -I. -I/w /w/lazer_dump.c -x none \
    -o /w/lazer_dump-$V -static liblazer.a third_party/hexl-development/build/hexl/lib/libhexl.a \
    -lmpfr -lgmp -lstdc++ -lm -lpthread 2>/w/dump-build-$V.log || { cat /w/dump-build-$V.log; exit 1; }
  { echo "variant: $V"; echo "march: $MARCH"; echo "lazer: $(git -c safe.directory=* rev-parse HEAD)"
    grep -E "AVX512|Setting" /w/hexl-cmake-$V.log || true
    gcc --version | head -1; cmake --version | head -1
    dpkg-query -W libgmp-dev libmpfr-dev libstdc++-13-dev
    sha256sum /w/lazer_dump-$V; } > /w/build-info-$V.txt
'
cat "$W/build-info-$V.txt"
