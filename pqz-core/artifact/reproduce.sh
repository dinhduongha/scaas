#!/bin/sh
# pqz-core reproducibility run (README.md). Runs in the Docker image (Dockerfile) or on a local toolchain: clang 18,
# wasm-ld-18, node, python3 (x86-64 Linux; --upstream also gcc / g++, cmake, unzip, git, libgmp-dev, libmpfr-dev).
#
#   artifact/reproduce.sh              quick (minutes): build, KAT, check_tbox_fixes.sh, sv/check_sv_fixes.sh, the
#                                      differential test (v2-sized sample), five relations generic + SV, native + wasm,
#                                      wasm prove memory per op; tables + comparison with expected-results.json
#   artifact/reproduce.sh --full       the same with the frozen run's sample sizes (rel3/relfix.sh + sv/rel3.sh)
#   artifact/reproduce.sh --serve      build the wasm and serve a browser demo (R_TX prove + verify) on
#                                      http://$BIND:$PORT (default 127.0.0.1:8000); local only, never published
#   artifact/reproduce.sh --upstream [N]   build upstream LaZer 3330e48 from source (x86-64-v3 and AVX-512 IFMA
#                                      variants), golden KAT against kat/lazer-3330e48.json, R_REG / R_TX bench
#                                      upstream vs the fork (N proves + N verifies, default 3); the AVX-512 binaries
#                                      run only if /proc/cpuinfo has avx512ifma
#
# Output: $OUT (default artifact/out/<mode>-<UTC stamp>): results.md, results.json, every raw run file, log.txt.
# Exit 0 = every check passed (quick / full). Memory: up to ~0.8 GB (the bench arena is 768 MiB).
set -eu
cd "$(dirname "$0")/.."
MODE=quick
case "${1:-}" in
  "") ;;
  --full) MODE=full ;;
  --serve) MODE=serve ;;
  --upstream) MODE=upstream ;;
  *) sed -n '2,19p' "$0"; exit 2 ;;
esac
OUT=${OUT:-artifact/out/$MODE-$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$OUT"
echo "$MODE" > "$OUT/mode.txt"
cpu_has() { grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n' | grep -qx "$1"; }
step() { echo "== $(date -u +%T) $*" | tee -a "$OUT/log.txt"; }

if [ $MODE = serve ]; then
  step "build wasm"
  ./build.sh wasm > "$OUT/build.txt" 2>&1
  mkdir -p "$OUT/web"
  cp artifact/web/index.html build/wasm/pqz.wasm "$OUT/web/"
  step "serving $OUT/web on http://${BIND:-127.0.0.1}:${PORT:-8000}/ (Ctrl-C to stop)"
  exec python3 -m http.server "${PORT:-8000}" --bind "${BIND:-127.0.0.1}" -d "$OUT/web"
fi

if [ $MODE = upstream ]; then
  # Upstream LaZer 3330e48 + HEXL (its third_party zip) + the distro's GMP / MPFR, built from source here; flags as
  # xcheck/static/build.sh (upstream Makefile defaults with -march=native -> the variant's flags, -fno-strict-aliasing
  # for aes256ctr-amd64.c, -DNDEBUG). HEXL's cpu_features (a GitHub fetch) is replaced by xcheck/static/cpuf (real
  # CPUID through libgcc). v4: HEXL's AVX-512 kernels compiled in although the build host may lack AVX-512 (its
  # configure test relaxed from "compiles and runs" to "compiles"); building needs only the flags, running needs the CPU.
  N=${2:-3}
  PIN=3330e487228f633eceb322807b13a596b516770f
  U=$(pwd)/build/upstream
  SRC=${LAZER_SRC:-$U/lazer-src}
  [ -d "$SRC/.git" ] || git clone -q https://github.com/lazer-crypto/lazer "$SRC"
  [ "$(git -C "$SRC" rev-parse "$PIN^{commit}")" = $PIN ] || { echo "no LaZer $PIN in $SRC" >&2; exit 1; }
  P=$(pwd)
  for V in v3 v4; do
    case $V in
      v3) MARCH="-march=x86-64-v3 -maes -mpclmul" ;;
      v4) MARCH="-march=x86-64-v4 -mavx512ifma -mavx512vbmi2 -maes -mpclmul" ;;
    esac
    step "build upstream $V ($MARCH)"
    L=$U/lazer-$V
    rm -rf "$L" && git -c advice.detachedHead=false clone -q "$SRC" "$L" && git -C "$L" checkout -q $PIN
    (
      cd "$L/third_party" && unzip -q hexl-development.zip
      sed -i "s/-march=native/$MARCH/" hexl-development/hexl/CMakeLists.txt hexl-development/cmake/hexl/hexl-util.cmake
      [ $V = v3 ] || sed -i "s/if (CAN_COMPILE AND CAN_RUN STREQUAL 0)/if (CAN_COMPILE)/" hexl-development/cmake/hexl/hexl-util.cmake
      cd hexl-development
      cmake -S . -B build -DHEXL_BENCHMARK=OFF -DHEXL_TESTING=OFF -DCpuFeatures_DIR="$P/xcheck/static/cpuf" > "$U/hexl-cmake-$V.log" 2>&1
      cmake --build build -j4 > "$U/hexl-build-$V.log" 2>&1
      mkdir -p build/hexl/lib64 && cp build/hexl/lib/libhexl.a build/hexl/lib64/ && touch .
      cd "$L"
      make lazer.h liblazer.a CFLAGS="-Wall -O3 -g $MARCH -fomit-frame-pointer -DFALCON_FPNATIVE -DFALCON_AVX2 -DFALCON_FMA -DNDEBUG -fno-strict-aliasing" > "$U/lazer-build-$V.log" 2>&1
      LIBS="$L/liblazer.a $L/third_party/hexl-development/build/hexl/lib/libhexl.a -lmpfr -lgmp -lstdc++ -lm -lpthread"
      CF="-std=gnu11 -O3 $MARCH -fomit-frame-pointer -fno-strict-aliasing -DNDEBUG -w"
      # R_REG / R_TX bench: the fork's statement builder and bench through the cross-check shim (xcheck/README.md)
      gcc $CF -I"$P/xcheck/shim" -I"$L" -I"$L/src" -I"$P/src" -I"$P/params" -c "$P/xcheck/shim/up_rel.c" -o "$U/up_rel-$V.o"
      gcc $CF -c "$P/xcheck/shim/shim.c" -o "$U/up_shim-$V.o"
      gcc $CF -I"$P/src" -c "$P/xcheck/shim/bench.c" -o "$U/up_bench-$V.o"
      mkdir -p "$U/bin"
      g++ -o "$U/bin/bench_up_$V" "$U/up_bench-$V.o" "$U/up_rel-$V.o" "$U/up_shim-$V.o" $LIBS
      # arithmetic-layer KAT dump (kat/build-lazer-dump.sh, here dynamic)
      g++ -x c -std=gnu11 -O2 -fno-strict-aliasing $MARCH -DBUILD_FLAGS="\"lazer 3330e48 $V: $MARCH\"" -I. -I"$P/params" \
        "$P/kat/lazer_dump.c" -x none -o "$U/bin/lazer_dump-$V" $LIBS
      echo "$V: $MARCH; HEXL: $(grep -E 'Setting HEXL|not found: HEXL' "$U/hexl-cmake-$V.log" | sed 's/.*-- //' | tr '\n' ';')"
    ) >> "$OUT/upstream-build.txt" 2>&1 || { tail -20 "$OUT/upstream-build.txt"; echo "upstream $V build failed" >&2; exit 1; }
  done
  { gcc --version | head -1; cmake --version | head -1
    dpkg-query -W libgmp-dev libmpfr-dev 2>/dev/null || true
    echo "HEXL AVX-512 IFMA kernels in bench_up_v4: $(nm -C "$U/bin/bench_up_v4" | grep -c 'AVX512.*<52')"; } >> "$OUT/upstream-build.txt"
  step "build fork bench (shim bench.c against build/native/libpqz.a)"
  ./build.sh native > "$OUT/build.txt" 2>&1
  ${CC:-clang} -std=gnu11 -O2 -w -Isrc -o "$U/bin/bench_fork" xcheck/shim/bench.c build/native/libpqz.a
  cat "$OUT/upstream-build.txt"
  for V in v3 v4; do
    if [ $V = v4 ] && ! cpu_has avx512ifma; then
      step "KAT upstream v4: skipped, no avx512ifma in /proc/cpuinfo (built only; running needs an AVX-512 IFMA CPU or Intel SDE)"
      continue
    fi
    step "KAT upstream $V against kat/lazer-3330e48.json"
    "$U/bin/lazer_dump-$V" > "$OUT/kat-upstream-$V.json"
    python3 -I kat/check.py kat/lazer-3330e48.json "$OUT/kat-upstream-$V.json" | tee "$OUT/kat-upstream-$V.txt"
  done
  step "bench upstream vs fork, N=$N (xcheck/static/run.sh; skips bench_up_v4 without avx512ifma)"
  cp xcheck/static/run.sh "$U/bin/"
  (cd "$U/bin" && rm -rf raw-* results-*.json && ./run.sh "$N" bench_up_v3 bench_up_v4 bench_fork) | tee "$OUT/upstream-bench.txt"
  cp "$U"/bin/results-*.json "$OUT/" && cp -r "$U"/bin/raw-* "$OUT/"
  step "done: $OUT"
  exit 0
fi

# ---- quick / full
if [ $MODE = full ]; then
  NP=10 NV=100 NPW=5 NVW=30 NF=200 DIFF3="2 2 2 2 10 6 6 6"
else
  NP=3 NV=3 NPW=3 NVW=1 NF=50 DIFF3=
fi
DIFF="4 4 2 1 10 12 12 12" # the v2-sized sample (sv/rel3.sh): 2,710 cases
X86=1
cpu_has avx2 && cpu_has aes || { X86=0; echo "no avx2 / aes: the x86-64-v3 runs are skipped" | tee -a "$OUT/log.txt"; }

step "build (native, wasm, wasm without SV$( [ $X86 = 1 ] && echo ', native-x86v3'))"
{ ./build.sh all
  [ $X86 = 0 ] || ./build.sh native-x86v3
  SV=0 B=build/wasm-nosv ./build.sh wasm
  wc -c build/wasm/pqz.wasm build/wasm-nosv/wasm/pqz.wasm; } > "$OUT/build.txt" 2>&1
step "KAT"
build/native/kat_dump > "$OUT/kat-pqz.json"
python3 -I kat/check.py kat/lazer-3330e48.json "$OUT/kat-pqz.json" | tee "$OUT/kat.txt" || true
step "check_tbox_fixes.sh"
./check_tbox_fixes.sh > "$OUT/tbox-fixes.txt" 2>&1 || true
tail -1 "$OUT/tbox-fixes.txt"
step "sv/check_sv_fixes.sh"
sv/check_sv_fixes.sh > "$OUT/sv-fixes.txt" 2>&1 || true
tail -1 "$OUT/sv-fixes.txt"
step "differential test pqz_verify vs pqz_verify_fast, portable: pqz_sv_diff $DIFF"
build/native/pqz_sv_diff $DIFF > "$OUT/diff-portable.jsonl" || true
if [ -n "$DIFF3" ] && [ $X86 = 1 ]; then
  step "differential test, x86-64-v3: pqz_sv_diff $DIFF3"
  build/native-x86v3/pqz_sv_diff $DIFF3 > "$OUT/diff-x86v3.jsonl" || true
fi
step "five relations, generic verifier: native pqz_bench $NP $NV, wasm run_wasm.mjs $NPW $NVW"
build/native/pqz_bench $NP $NV 31 > "$OUT/native-generic.jsonl" || true
node test/run_wasm.mjs $NPW $NVW 31 > "$OUT/wasm-generic.jsonl" || true
if [ $MODE = full ]; then
  step "proofs_fnv: native pqz_bench 5 5, wasm run_wasm.mjs 3 1"
  build/native/pqz_bench 5 5 31 > "$OUT/fnv-native.jsonl" || true
  node test/run_wasm.mjs 3 1 31 > "$OUT/fnv-wasm.jsonl" || true
fi
step "five relations, specialised verifier: pqz_bench 2 $NF (portable$( [ $X86 = 1 ] && echo ', x86-64-v3')), wasm 2 $((NF / 2)), wasm both"
PQZ_VERIFY=fast build/native/pqz_bench 2 $NF > "$OUT/native-fast.jsonl" || true
[ $X86 = 0 ] || PQZ_VERIFY=fast build/native-x86v3/pqz_bench 2 $NF > "$OUT/x86v3-fast.jsonl" || true
PQZ_VERIFY=fast node test/run_wasm.mjs 2 $((NF / 2)) > "$OUT/wasm-fast.jsonl" || true
PQZ_VERIFY=both node test/run_wasm.mjs 2 $((NF / 20)) > "$OUT/wasm-both.jsonl" || true
step "wasm prove memory, one relation per process (the prover build without SV)"
: > "$OUT/alone-wasm-nosv.jsonl"
for m in 1 2 4 8 16; do
  PQZ_WASM_FILE=build/wasm-nosv/wasm/pqz.wasm node test/run_wasm.mjs 1 0 $m | sed 's/^{/{"backend": "wasm-nosv", /' \
    >> "$OUT/alone-wasm-nosv.jsonl" || true
done
step "tables and comparison"
python3 -I artifact/results.py check "$OUT" | tee "$OUT/summary.txt"
step "done: $OUT"
grep -q '^RESULT: PASS' "$OUT/summary.txt"
