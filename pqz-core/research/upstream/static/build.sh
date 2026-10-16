#!/bin/sh
# Static benchmark bundle: upstream LaZer 3330e48 vs the pqz-core fork on R_REG / R_TX (README.md).
#
#   pqz-core/research/upstream/static/build.sh <work dir> <LaZer clone at 3330e48>
#     -> <work dir>/pqz-bench-<sha>/  {bench_up_v3, bench_up_v4, bench_fork, bench_fork_v3, run.sh, README.md,
#                                       build-info.txt}
#        <work dir>/pqz-bench-<sha>.tar.gz
#
# Upstream: built offline (--network none) in p6d-lazer-build:ubuntu24.04 (../Dockerfile), gcc 13, static
# GMP / MPFR / libstdc++ / glibc, the cross-check shim (../shim: the fork's statement builder + bench).
# Fork: host clang (the fork's build.sh compiler), static glibc. Run it under scripts/capped.
set -eu
W=$(mkdir -p "$1" && cd "$1" && pwd)
LZ=$(cd "$2" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
XC=$(cd "$HERE/.." && pwd)
PQZ=$(cd "$XC/../../pqzl" && pwd) # the PQZL core (src/ params/ build.sh), copied as /w/src/pqz-core
PIN=3330e487228f633eceb322807b13a596b516770f
IMG=p6d-lazer-build:ubuntu24.04
SHA=$(git -C "$PQZ" rev-parse --short HEAD)
OUT=$W/pqz-bench-$SHA
[ "$(git -C "$LZ" rev-parse HEAD)" = "$PIN" ] || { echo "LaZer clone is not at $PIN" >&2; exit 1; }
rm -rf "$OUT" && mkdir -p "$OUT"

# ---- inputs, copied into the work dir (the container sees only /w)
rm -rf "$W/src" && mkdir -p "$W/src"
cp -a "$XC/shim" "$HERE/cpuf" "$W/src/"
cp -a "$PQZ" "$W/src/pqz-core" && rm -rf "$W/src/pqz-core/build"

# ---- upstream: v3 = x86-64-v3 (AVX2; HEXL portable path), v4 = x86-64-v4 + IFMA / VBMI2 (HEXL AVX-512 kernels
# compiled in; HEXL's own configure test would try_run them on the build host, which has no AVX-512, so the
# condition is relaxed to "compiles"). Both use cpuf/: real CPUID at run time, so v4 takes the IFMA kernels
# exactly when the CPU has them.
for V in v3 v4; do
  case $V in
    v3) MARCH="-march=x86-64-v3 -maes -mpclmul" ;;
    v4) MARCH="-march=x86-64-v4 -mavx512ifma -mavx512vbmi2 -maes -mpclmul" ;;
  esac
  rm -rf "$W/lazer-$V" && git clone -q "$LZ" "$W/lazer-$V" && git -C "$W/lazer-$V" -c advice.detachedHead=false checkout -q "$PIN"
  docker run --rm --network none --memory=4g -u "$(id -u):$(id -g)" -e V=$V -e MARCH="$MARCH" -v "$W":/w -w /w \
    "$IMG" sh -euc '
    L=/w/lazer-$V
    cd $L/third_party && unzip -q hexl-development.zip
    sed -i "s/-march=native/$MARCH/" hexl-development/hexl/CMakeLists.txt hexl-development/cmake/hexl/hexl-util.cmake
    [ "$V" = v3 ] || sed -i "s/if (CAN_COMPILE AND CAN_RUN STREQUAL 0)/if (CAN_COMPILE)/" hexl-development/cmake/hexl/hexl-util.cmake
    (cd hexl-development && cmake -S . -B build -DHEXL_BENCHMARK=OFF -DHEXL_TESTING=OFF -DCpuFeatures_DIR=/w/src/cpuf \
       >/w/hexl-cmake-$V.log 2>&1 && cmake --build build -j4 >/w/hexl-build-$V.log 2>&1)
    mkdir -p hexl-development/build/hexl/lib64 && cp hexl-development/build/hexl/lib/libhexl.a hexl-development/build/hexl/lib64/
    touch hexl-development
    # upstream Makefile defaults with -march=native -> $MARCH, + -fno-strict-aliasing (aes256ctr-amd64.c) + -DNDEBUG
    cd $L && make lazer.h liblazer.a CFLAGS="-Wall -O3 -g $MARCH -fomit-frame-pointer -DFALCON_FPNATIVE -DFALCON_AVX2 -DFALCON_FMA -DNDEBUG -fno-strict-aliasing" >/w/lazer-build-$V.log 2>&1
    F=/w/src/pqz-core
    CF="-std=gnu11 -O3 $MARCH -fomit-frame-pointer -fno-strict-aliasing -DNDEBUG -w"
    gcc $CF -I/w/src/shim -I$L -I$L/src -I$F/src -I$F/params -c /w/src/shim/up_rel.c -o /w/up_rel-$V.o
    gcc $CF -c /w/src/shim/shim.c -o /w/up_shim-$V.o
    gcc $CF -I$F/src -c /w/src/shim/bench.c -o /w/up_bench-$V.o
    g++ -static -o /w/bench_up_$V /w/up_bench-$V.o /w/up_rel-$V.o /w/up_shim-$V.o $L/liblazer.a \
      $L/third_party/hexl-development/build/hexl/lib/libhexl.a -lmpfr -lgmp -lstdc++ -lm -lpthread
    { echo "bench_up_$V: LaZer $(git -c safe.directory=* -C $L rev-parse --short HEAD), $MARCH"
      echo "  HEXL configure: $(grep -E "Setting HEXL|not found: HEXL" /w/hexl-cmake-$V.log | sed "s/.*-- //" | tr "\n" ";")"
      echo "  $(gcc --version | head -1); $(dpkg-query -W -f "\${Package} \${Version}; " libgmp-dev libmpfr-dev libc6-dev)"
    } > /w/info-$V.txt'
  mv "$W/bench_up_$V" "$OUT/"
done

# ---- fork: as shipped (pqz-core/pqzl/build.sh native: clang -O2, generic x86-64, PQZ_ASSERT=1) and v3 (-O3
# -march=x86-64-v3, asserts off). The bench harness itself is -O2 generic in both (it times library calls only).
for V in as v3; do
  rm -rf "$W/fork-$V" && cp -a "$W/src/pqz-core" "$W/fork-$V"
  [ $V = as ] || sed -i 's/^CFLAGS_LIB="-std=gnu11 -O2 /CFLAGS_LIB="-std=gnu11 -O3 -march=x86-64-v3 -DPQZ_ASSERT=0 /' "$W/fork-$V/build.sh"
  (cd "$W/fork-$V" && ./build.sh native >"$W/fork-build-$V.log" 2>&1)
  B=bench_fork; [ $V = as ] || B=bench_fork_$V
  clang -static -std=gnu11 -O2 -w -I"$W/fork-$V/src" -o "$OUT/$B" "$XC/shim/bench.c" "$W/fork-$V/build/native/libpqz.a"
  echo "$B: pqz-core $SHA, $(grep '^CFLAGS_LIB=' "$W/fork-$V/build.sh" | cut -c1-80)..., $(clang --version | head -1)" \
    > "$W/info-fork-$V.txt"
done

# ---- bundle
cp "$HERE/run.sh" "$HERE/README.md" "$OUT/"
{ echo "pqz-bench $SHA built $(date -u +%FT%TZ) on $(uname -m)"
  cat "$W/info-v3.txt" "$W/info-v4.txt" "$W/info-fork-as.txt" "$W/info-fork-v3.txt"
  echo "HEXL AVX-512 IFMA kernels linked into bench_up_v4: $(nm -C "$OUT/bench_up_v4" | grep -c 'AVX512.*<52')"
  echo; (cd "$OUT" && sha256sum bench_*; file bench_* | sed 's/, BuildID[^,]*//') ; } > "$OUT/build-info.txt"
cat "$OUT/build-info.txt"
for b in "$OUT"/bench_*; do file "$b" | grep -q 'statically linked' || { echo "not static: $b" >&2; exit 1; }; done
tar -C "$W" -czf "$OUT.tar.gz" "pqz-bench-$SHA"
ls -la "$OUT.tar.gz"
