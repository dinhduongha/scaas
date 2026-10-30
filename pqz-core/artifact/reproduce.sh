#!/bin/sh
# pqz-core reproducibility run, both proof systems (README.md): PQZL (the LaZer fork, C) and PQZH (Ligero, Rust), and
# pqz-ffi (the one precompile over both). Runs in the Docker image (Dockerfile) or on a local toolchain: clang 18,
# wasm-ld-18, node, python3, Rust 1.97.1 with wasm32-unknown-unknown and clippy (x86-64 Linux; --upstream also gcc / g++,
# cmake, unzip, git, libgmp-dev, libmpfr-dev).
#
#   artifact/reproduce.sh              quick: PQZL build, KAT, check_tbox_fixes.sh, pqzl/sv/check_sv_fixes.sh, the
#                                      differential test (pqzl/sv/rel3.sh sample), six relations generic + SV, native + wasm,
#                                      wasm prove memory per op; PQZH cargo tests (+ --no-default-features, clippy),
#                                      C <-> Rust cross-check, pqz-stmt xcheck, native + wasm32 bench of the six forms at
#                                      the proven preset (small N); pqz-ffi tests, C ABI, native = wasm32 digests, bench;
#                                      the vectors: pqz-vectors --check, pqz_kat.py --check, wasm32 replay (--full: +
#                                      tamper.py), op 7 R_TXM included (every built (id, M, auditorOn): native proof
#                                      -> ...01, its negatives -> ...00, wasm32 replay; PQZL M = 8 proved in wasm32
#                                      by the Rust backend, verify-only on the C one);
#                                      Rust = C (the Rust core pqzl/rust/: proofs_fnv of its prover native + wasm32,
#                                      the keys KAT; --full: + verify_fast); tables + comparison with
#                                      expected-results.json. pqz-ffi's PQZL backend is the Rust core (default feature
#                                      pqzl-rust, CTR-PQZ-09), so the pqz-ffi and vectors stages check the Rust core
#                                      against the values the C core fixed in expected-results.json
#   artifact/reproduce.sh --full       the same with the frozen run's sample sizes (PQZL: research/pqzl-measure/relfix.sh + pqzl/sv/rel3.sh;
#                                      PQZH: pqzh/ligero/runs/tx0.sh, the gate-B method, 1,000 verifies per form)
#   artifact/reproduce.sh --serve      build both wasm modules and serve a browser demo (PQZL R_TX, PQZH any form: prove
#                                      + verify) on http://$BIND:$PORT (default 127.0.0.1:8000); local only, never published
#   artifact/reproduce.sh --upstream [N]   build upstream LaZer 3330e48 from source (x86-64-v3 and AVX-512 IFMA
#                                      variants), golden KAT against params/sets/n2048-kmax1024/lazer-3330e48-kat.json, R_REG / R_TX bench
#                                      upstream vs the fork (N proves + N verifies, default 3); the AVX-512 binaries
#                                      run only if /proc/cpuinfo has avx512ifma
#   artifact/reproduce.sh --multi-bench    op 7 R_TXM measurement table (P6-ANON S6, D14): PQZL research/pqzl-measure/txm-bench.sh (the
#                                      L3 method) and PQZH ligero_bench / run_wasm.mjs txm (the H2 method of
#                                      pqzh/ligero/runs/txm.sh), every (id, M, auditorOn), oversize shapes in bench
#                                      builds only, and the Rust core's rows (pqzl/rust bench, wasm32 limit lifted);
#                                      results-multi.md (proof bytes, prove / verify times); ~1 h, ~2 GB
#
# Output: $OUT (default artifact/out/<mode>-<UTC stamp>): results.md, results.json, every raw run file, log.txt.
# Exit 0 = every check passed (quick / full / multi-bench). Memory: up to ~2 GB (the PQZL bench arena is 768 MiB;
# pqz-ffi's wasm32 run ~0.6 GB; op 7: pqz-ffi prove up to ~0.9 GB per test thread, pqz-vectors --check ~1 GB;
# --multi-bench: PQZL M = 16 ~1.6 GB).
set -eu
# the package is the default set (owner 2026-10-21: one parameter set per build, pqz-core/params/sets/)
export PQZ_SET=n2304-kmax4096
cd "$(dirname "$0")/.."
MODE=quick
case "${1:-}" in
  "") ;;
  --full) MODE=full ;;
  --serve) MODE=serve ;;
  --upstream) MODE=upstream ;;
  --multi-bench) MODE=multi ;;
  *) sed -n '2,38p' "$0"; exit 2 ;;
esac
OUT=${OUT:-artifact/out/$MODE-$(date -u +%Y%m%dT%H%M%SZ)}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
echo "$MODE" > "$OUT/mode.txt"
C="--release --locked --offline" # cargo: the committed Cargo.lock, no network (the image fetched the crates)
L=pqzh/ligero # the Ligero crate (PQZH)
LW=$L/wasm/target/wasm32-unknown-unknown/release/pqzh_ligero_wasm.wasm
TXMB=research/pqzl-measure/txm-bench.sh # L3's PQZL op 7 harness (--multi-bench); writes $(dirname $TXMB)/runs/<label>-*
cpu_has() { grep -m1 '^flags' /proc/cpuinfo | tr ' ' '\n' | grep -qx "$1"; }
step() { echo "== $(date -u +%T) $*" | tee -a "$OUT/log.txt"; }
run() { # run <file> <dir> <command...>: stdout + stderr to $OUT/<file>, then "rc=N" as its last line
  f=$OUT/$1 d=$2; shift 2
  (cd "$d" && "$@") > "$f" 2>&1 && r=0 || r=$?
  echo "rc=$r" >> "$f"
}

if [ $MODE = serve ]; then
  step "build wasm (PQZL pqzl/build/wasm/pqz.wasm, PQZH $LW)"
  { pqzl/build.sh wasm && (cd $L/wasm && cargo build $C --target wasm32-unknown-unknown); } > "$OUT/build.txt" 2>&1
  mkdir -p "$OUT/web"
  cp artifact/web/index.html pqzl/build/wasm/pqz.wasm "$LW" "$OUT/web/"
  step "serving $OUT/web on http://${BIND:-127.0.0.1}:${PORT:-8000}/ (Ctrl-C to stop)"
  exec python3 -m http.server "${PORT:-8000}" --bind "${BIND:-127.0.0.1}" -d "$OUT/web"
fi

if [ $MODE = upstream ]; then
  # Upstream LaZer 3330e48 + HEXL (its third_party zip) + the distro's GMP / MPFR, built from source here; flags as
  # research/upstream/static/build.sh (upstream Makefile defaults with -march=native -> the variant's flags, -fno-strict-aliasing
  # for aes256ctr-amd64.c, -DNDEBUG). HEXL's cpu_features (a GitHub fetch) is replaced by research/upstream/static/cpuf (real
  # CPUID through libgcc). v4: HEXL's AVX-512 kernels compiled in although the build host may lack AVX-512 (its
  # configure test relaxed from "compiles and runs" to "compiles"); building needs only the flags, running needs the CPU.
  N=${2:-3}
  PIN=3330e487228f633eceb322807b13a596b516770f
  U=$(pwd)/build/upstream
  SRC=${LAZER_SRC:-$U/lazer-src}
  [ -d "$SRC/.git" ] || git clone -q https://github.com/lazer-crypto/lazer "$SRC"
  [ "$(git -C "$SRC" rev-parse "$PIN^{commit}")" = $PIN ] || { echo "no LaZer $PIN in $SRC" >&2; exit 1; }
  P=$(pwd)
  # Same relation on both sides: the upstream bench compiles the fork's own src/pqz_rel.c (the R_REG / R_TX statement
  # builder and witness of libpqz), not a copy, with two upstream-API substitutions (no bounded decoder, no coder err
  # flag). The check: exactly those two lines differ; the diff goes to upstream-relation.txt.
  mkdir -p "$U"
  sed -e 's#coder_dec_begin_len (cstate, in, len);#coder_dec_begin (cstate, in); /* xcheck: upstream has no bounded decoder */#' \
      -e 's#if (cstate->err || coder_dec_end#if (0 /* xcheck: upstream coder has no err flag */ || coder_dec_end#' \
      pqzl/src/pqz_rel.c > "$U/up_rel.c"
  { echo "diff pqzl/src/pqz_rel.c build/upstream/up_rel.c (the upstream bench's relation source):"
    diff pqzl/src/pqz_rel.c "$U/up_rel.c" || true; } > "$OUT/upstream-relation.txt"
  [ "$(diff pqzl/src/pqz_rel.c "$U/up_rel.c" | grep -c '^[<>]')" = 4 ] \
    || { cat "$OUT/upstream-relation.txt"; echo "up_rel.c: expected exactly 2 substituted lines" >&2; exit 1; }
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
      cmake -S . -B build -DHEXL_BENCHMARK=OFF -DHEXL_TESTING=OFF -DCpuFeatures_DIR="$P/research/upstream/static/cpuf" > "$U/hexl-cmake-$V.log" 2>&1
      cmake --build build -j2 > "$U/hexl-build-$V.log" 2>&1
      mkdir -p build/hexl/lib64 && cp build/hexl/lib/libhexl.a build/hexl/lib64/ && touch .
      cd "$L"
      make lazer.h liblazer.a CFLAGS="-Wall -O3 -g $MARCH -fomit-frame-pointer -DFALCON_FPNATIVE -DFALCON_AVX2 -DFALCON_FMA -DNDEBUG -fno-strict-aliasing" > "$U/lazer-build-$V.log" 2>&1
      LIBS="$L/liblazer.a $L/third_party/hexl-development/build/hexl/lib/libhexl.a -lmpfr -lgmp -lstdc++ -lm -lpthread"
      CF="-std=gnu11 -O3 $MARCH -fomit-frame-pointer -fno-strict-aliasing -DNDEBUG -w"
      # R_REG / R_TX bench: the fork's relation source ($U/up_rel.c, above) and bench through the cross-check shim
      # (research/upstream/README.md: libc heap instead of the arena)
      gcc $CF -I"$P/research/upstream/shim" -I"$L" -I"$L/src" -I"$P/pqzl/src" -I"$P/params/sets/n2048-kmax1024" -c "$U/up_rel.c" -o "$U/up_rel-$V.o"
      gcc $CF -c "$P/research/upstream/shim/shim.c" -o "$U/up_shim-$V.o"
      gcc $CF -I"$P/pqzl/src" -I"$P/params/sets/n2048-kmax1024" -c "$P/research/upstream/shim/bench.c" -o "$U/up_bench-$V.o"
      mkdir -p "$U/bin"
      g++ -o "$U/bin/bench_up_$V" "$U/up_bench-$V.o" "$U/up_rel-$V.o" "$U/up_shim-$V.o" $LIBS
      # arithmetic-layer KAT dump (pqzl/kat/build-lazer-dump.sh, here dynamic)
      g++ -x c -std=gnu11 -O2 -fno-strict-aliasing $MARCH -DBUILD_FLAGS="\"lazer 3330e48 $V: $MARCH\"" -I. -I"$P/params/sets/n2048-kmax1024" \
        "$P/pqzl/kat/lazer_dump.c" -x none -o "$U/bin/lazer_dump-$V" $LIBS
      echo "$V: $MARCH; HEXL: $(grep -E 'Setting HEXL|not found: HEXL' "$U/hexl-cmake-$V.log" | sed 's/.*-- //' | tr '\n' ';')"
    ) >> "$OUT/upstream-build.txt" 2>&1 || { tail -20 "$OUT/upstream-build.txt"; echo "upstream $V build failed" >&2; exit 1; }
  done
  { gcc --version | head -1; cmake --version | head -1
    dpkg-query -W libgmp-dev libmpfr-dev 2>/dev/null || true
    echo "HEXL AVX-512 IFMA kernels in bench_up_v4: $(nm -C "$U/bin/bench_up_v4" | grep -c 'AVX512.*<52')"; } >> "$OUT/upstream-build.txt"
  step "build fork bench (shim bench.c against pqzl/build/native/libpqz.a)"
  pqzl/build.sh native > "$OUT/build.txt" 2>&1
  ${CC:-clang} -std=gnu11 -O2 -w -Ipqzl/src -Ipqzl/build/include -o "$U/bin/bench_fork" research/upstream/shim/bench.c pqzl/build/native/libpqz.a
  cat "$OUT/upstream-build.txt"
  for V in v3 v4; do
    if [ $V = v4 ] && ! cpu_has avx512ifma; then
      step "KAT upstream v4: skipped, no avx512ifma in /proc/cpuinfo (built only; running needs an AVX-512 IFMA CPU or Intel SDE)"
      continue
    fi
    step "KAT upstream $V against kat/lazer-3330e48.json"
    "$U/bin/lazer_dump-$V" > "$OUT/kat-upstream-$V.json"
    python3 -I pqzl/kat/check.py params/sets/n2048-kmax1024/lazer-3330e48-kat.json "$OUT/kat-upstream-$V.json" | tee "$OUT/kat-upstream-$V.txt"
  done
  step "bench upstream vs fork, N=$N (research/upstream/static/run.sh; skips bench_up_v4 without avx512ifma)"
  cp research/upstream/static/run.sh "$U/bin/"
  (cd "$U/bin" && rm -rf raw-* results-*.json && ./run.sh "$N" bench_up_v3 bench_up_v4 bench_fork) | tee "$OUT/upstream-bench.txt"
  cp "$U"/bin/results-*.json "$OUT/" && cp -r "$U"/bin/raw-* "$OUT/"
  step "done: $OUT"
  exit 0
fi

if [ $MODE = multi ]; then
  # P6-ANON S6 (D14): the op 7 measurement table. Reuses the L3 / H2 harnesses, not a copy: PQZL research/pqzl-measure/txm-bench.sh
  # (its own OVERSIZE=1 bench build under pqzl/build/ov; M = 16 there only), PQZH steps 5-8 of pqzh/ligero/runs/txm.sh
  # (feature oversize in target/oversize only). The precompile build (default stages) never has an oversize shape.
  step "PQZL R_TXM: $TXMB (M = 1, 2, 4, 8, 16 on / off: 10 proves, 30 verifies, SV 200, wasm 3 / 3)"
  run pqzl-txm.txt . $TXMB artifact-txm
  TR=$(dirname $TXMB)/runs
  for f in "$TR"/artifact-txm-*; do [ ! -e "$f" ] || mv "$f" "$OUT/pqzl-${f#"$TR"/artifact-}"; done
  step "PQZH R_TXM: native ligero_bench --rel txm (built M = 1, 2, 4): 10 proofs, 1,000 verifies, 12 x 80 mutations"
  run pqzh-txm-build.txt $L cargo build $C --bin ligero_bench
  run pqzh-txm-native.jsonl $L target/release/ligero_bench --rel txm --regime proven --r431 1 --np 10 --nv 1000 --nadv 80
  step "PQZH R_TXM oversize (M = 8, 16; feature oversize): 3 proofs, 100 verifies, 12 x 10 mutations"
  run pqzh-txm-oversize-build.txt $L cargo build $C --features oversize --bin ligero_bench --target-dir target/oversize
  run pqzh-txm-oversize.jsonl $L target/oversize/release/ligero_bench --rel txm --regime proven --r431 1 --np 3 --nv 100 --nadv 10
  step "PQZH R_TXM wasm32: 2 proofs, 1,000 verifies (oversize build: 100), 12 x 4 mutations"
  run pqzh-txm-wasm-build.txt $L/wasm cargo build $C --target wasm32-unknown-unknown
  run pqzh-txm-wasm.jsonl $L node wasm/run_wasm.mjs 2 1000 4 1 1 txm
  run pqzh-txm-oversize-wasm-build.txt $L/wasm cargo build $C --target wasm32-unknown-unknown --features oversize --target-dir target/oversize
  run pqzh-txm-oversize-wasm.jsonl $L env PQZH_WASM_FILE=wasm/target/oversize/wasm32-unknown-unknown/release/pqzh_ligero_wasm.wasm \
    node wasm/run_wasm.mjs 2 100 4 1 1 txm
  # port plan Task 12: the Rust core's rows (pqzl/rust bench + wasm/run_wasm.mjs, the PQZL counts above, one process per
  # shape; features oversize and, in wasm32, wasm-m8: the M <= 8 prove limit lifted to 16 for the measurement)
  step "Rust R_TXM (pqzl/rust): M = 1, 2, 4, 8, 16 on / off: 10 proves, 30 verifies, SV 200, wasm 3 / 3, wasm SV 100"
  RO=target/oversize RW=wasm/target/oversize/wasm32-unknown-unknown/release/pqzl_wasm.wasm
  run rust-txm-build.txt pqzl/rust sh -c "cargo build $C --features bench,oversize --bin bench --target-dir $RO \
    && cd wasm && cargo build $C --target wasm32-unknown-unknown --features pqzl/oversize,pqzl/wasm-m8 --target-dir $RO"
  run rust-txm.txt pqzl/rust sh -c "for t in 0 1 2 3 4 5 6 7 8 9; do m=\$((64 << t))
      $RO/release/bench 10 30 \$m >> '$OUT/rust-txm-native-generic.jsonl' || echo \"native generic \$t rc=\$?\"
      PQZ_VERIFY=fast $RO/release/bench 2 200 \$m >> '$OUT/rust-txm-native-fast.jsonl' || echo \"native fast \$t rc=\$?\"
      PQZL_WASM_FILE=$RW node wasm/run_wasm.mjs 3 3 \$m >> '$OUT/rust-txm-wasm-generic.jsonl' || echo \"wasm generic \$t rc=\$?\"
      PQZL_WASM_FILE=$RW PQZ_VERIFY=fast node wasm/run_wasm.mjs 1 100 \$m >> '$OUT/rust-txm-wasm-fast.jsonl' || echo \"wasm fast \$t rc=\$?\"
    done"
  step "op 7 table"
  python3 -I artifact/results.py multi "$OUT" | tee "$OUT/summary.txt"
  step "done: $OUT"
  grep -q '^RESULT: PASS' "$OUT/summary.txt"
  exit
fi

# ---- quick / full
if [ $MODE = full ]; then
  NP=10 NV=100 NPW=5 NVW=30 NF=200 DIFF3="2 2 2 2 10 6 6 6 6"
else
  NP=3 NV=3 NPW=3 NVW=1 NF=50 DIFF3=
fi
DIFF="4 4 2 1 10 12 12 12 12" # the sample of pqzl/sv/rel3.sh (n_tx0 = 12 last): 3,484 cases
X86=1
cpu_has avx2 && cpu_has aes || { X86=0; echo "no avx2 / aes: the x86-64-v3 runs are skipped" | tee -a "$OUT/log.txt"; }

step "build (native, wasm, wasm without SV$( [ $X86 = 1 ] && echo ', native-x86v3'))"
{ pqzl/build.sh all
  [ $X86 = 0 ] || pqzl/build.sh native-x86v3
  SV=0 B=build/wasm-nosv pqzl/build.sh wasm
  wc -c pqzl/build/wasm/pqz.wasm pqzl/build/wasm-nosv/wasm/pqz.wasm; } > "$OUT/build.txt" 2>&1
step "KAT"
pqzl/build/native/kat_dump > "$OUT/kat-pqz.json"
python3 -I pqzl/kat/check.py params/sets/$PQZ_SET/lazer-3330e48-kat.json "$OUT/kat-pqz.json" | tee "$OUT/kat.txt" || true
step "check_tbox_fixes.sh"
pqzl/check_tbox_fixes.sh > "$OUT/tbox-fixes.txt" 2>&1 || true
tail -1 "$OUT/tbox-fixes.txt"
step "pqzl/sv/check_sv_fixes.sh"
pqzl/sv/check_sv_fixes.sh > "$OUT/sv-fixes.txt" 2>&1 || true
tail -1 "$OUT/sv-fixes.txt"
step "differential test pqz_verify vs pqz_verify_fast, portable: pqz_sv_diff $DIFF"
pqzl/build/native/pqz_sv_diff $DIFF > "$OUT/diff-portable.jsonl" || true
if [ -n "$DIFF3" ] && [ $X86 = 1 ]; then
  step "differential test, x86-64-v3: pqz_sv_diff $DIFF3"
  pqzl/build/native-x86v3/pqz_sv_diff $DIFF3 > "$OUT/diff-x86v3.jsonl" || true
fi
step "six relations, generic verifier: native pqz_bench $NP $NV, wasm run_wasm.mjs $NPW $NVW"
pqzl/build/native/pqz_bench $NP $NV 63 > "$OUT/native-generic.jsonl" || true
node pqzl/test/run_wasm.mjs $NPW $NVW 63 > "$OUT/wasm-generic.jsonl" || true
if [ $MODE = full ]; then
  step "proofs_fnv: native pqz_bench 5 5, wasm run_wasm.mjs 3 1"
  pqzl/build/native/pqz_bench 5 5 63 > "$OUT/fnv-native.jsonl" || true
  node pqzl/test/run_wasm.mjs 3 1 63 > "$OUT/fnv-wasm.jsonl" || true
fi
step "six relations, specialised verifier: pqz_bench 2 $NF (portable$( [ $X86 = 1 ] && echo ', x86-64-v3')), wasm 2 $((NF / 2)), wasm both"
PQZ_VERIFY=fast pqzl/build/native/pqz_bench 2 $NF > "$OUT/native-fast.jsonl" || true
[ $X86 = 0 ] || PQZ_VERIFY=fast pqzl/build/native-x86v3/pqz_bench 2 $NF > "$OUT/x86v3-fast.jsonl" || true
PQZ_VERIFY=fast node pqzl/test/run_wasm.mjs 2 $((NF / 2)) > "$OUT/wasm-fast.jsonl" || true
PQZ_VERIFY=both node pqzl/test/run_wasm.mjs 2 $((NF / 20)) > "$OUT/wasm-both.jsonl" || true
step "wasm prove memory, one relation per process (the prover build without SV)"
: > "$OUT/alone-wasm-nosv.jsonl"
for m in 1 2 4 8 16 32; do
  PQZ_WASM_FILE=pqzl/build/wasm-nosv/wasm/pqz.wasm node pqzl/test/run_wasm.mjs 1 0 $m | sed 's/^{/{"backend": "wasm-nosv", /' \
    >> "$OUT/alone-wasm-nosv.jsonl" || true
done

# ---- PQZH (Ligero, Rust 1.97.1 = pqzh/rust-toolchain.toml), THE proven preset (Params::preset, --regime proven
# --r431 1), all six forms (R_TX0 = op 1 by length)
if [ $MODE = full ]; then
  LNP=5 LNV=1000 LNA=80 LWV=1000 LWA=4 FN=200 # = pqzh/ligero/runs/tx0.sh (gate-B method); pqz-ffi as ffi/run.sh
else
  LNP=2 LNV=20 LNA=2 LWV=20 LWA=1 FN=20
fi
step "PQZH: cargo test (default features: 6 x 960 mutations, negative witnesses, cross-form, EVM fixtures)"
run pqzh-test.txt $L cargo test $C -- --nocapture --test-threads 1
step "PQZH: the production build (--no-default-features): tests, examples / bins, clippy -D clippy::float_arithmetic"
run pqzh-nobench.txt $L sh -c "cargo test $C --no-default-features && cargo build $C --no-default-features --examples --bins \
  && cargo clippy $C --no-default-features -- -D clippy::float_arithmetic"
step "PQZH: C <-> Rust cross-check (pqzh/xcheck/ligero.sh: statement + witness bytes, then kat_stmt.py)"
run pqzh-xcheck.txt . pqzh/xcheck/ligero.sh
step "pqz-stmt: stmt/xcheck.sh (unit tests, C and pqz_kat.py cross-check, wasm32 build)"
run stmt-xcheck.txt . stmt/xcheck.sh artifact
for f in stmt/runs/artifact-*; do [ ! -e "$f" ] || mv "$f" "$OUT/stmt-${f#stmt/runs/artifact-}"; done
step "PQZH: native ligero_bench, six forms: $LNP proofs, $LNV verifies, 12 x $LNA mutations each"
run pqzh-native-build.txt $L cargo build $C --bin ligero_bench
run pqzh-native.jsonl $L target/release/ligero_bench --rel all --regime proven --r431 1 --np $LNP --nv $LNV --nadv $LNA
step "PQZH: wasm32 (node), six forms: 2 proofs, $LWV verifies, 12 x $LWA mutations each"
run pqzh-wasm-build.txt $L/wasm cargo build $C --target wasm32-unknown-unknown
run pqzh-wasm.jsonl $L node wasm/run_wasm.mjs 2 $LWV $LWA 1 1 0,1,2,3,4,5

# ---- pqz-ffi (P6e Task 7): the precompile over both systems; the subset of ffi/run.sh with this toolchain's clippy
step "pqz-ffi: cargo test --features prove,test-hooks (native digest lines, self-test, rejections, differential, faults)"
run ffi-test.txt ffi env PQZ_FFI_DIGESTS="$OUT/ffi-digests-native.jsonl" PQZ_FFI_FILL_OUT="$OUT/ffi-fill.txt" \
  cargo test $C --features prove,test-hooks -- --nocapture --test-threads 2
step "pqz-ffi: unit tests without prove, verify-only cdylib, symbol scan, C smoke test, clippy -D clippy::float_arithmetic"
run ffi-native.txt ffi sh -c "cargo test $C --lib && cargo build $C \
  && echo \"test hooks in the production cdylib (must be 0): \$(strings -a target/release/libpqz_ffi.so | grep -cE 'TEST_ARENA|TEST_FAIL_WORKER')\" \
  && F=\$(cargo tree --locked --offline -e features -i pqz-ffi --prefix none) \
  && case \$F in \
       *'pqz-ffi feature \"pqzl-c\"'*) ../pqzl/check_symbols.sh \"\$(pwd)/\$(ls -t target/release/build/pqz-ffi-*/out/libpqz.a | head -1)\" ;; \
       *'pqz-ffi feature \"pqzl-rust\"'*) echo 'symbols ok: no C core in this build (default backend pqzl-rust, CTR-PQZ-09: feature pqzl-c off)' ;; \
       *) echo 'C core in this build: unknown (no PQZL backend feature in cargo tree)'; false ;; \
     esac \
  && \${CC:-clang} -std=c11 -Wall -Wextra -DPQZ_SET_MAX_INPUT=\$(python3 -I -c \"import json; print(json.load(open('../params/sets/n2304-kmax4096/set.json'))['max_input'])\") -o target/c_abi tests/c_abi.c -Ltarget/release -lpqz_ffi -Wl,-rpath,\"\$(pwd)/target/release\" \
  && target/c_abi && cargo clippy $C --features prove,test-hooks --lib -- -D clippy::float_arithmetic"
step "pqz-ffi: wasm32 builds and digest lines (must equal native)"
run ffi-wasm-build.txt ffi sh -c "cargo build $C --lib --target wasm32-unknown-unknown && cd wasm && cargo build $C --target wasm32-unknown-unknown"
run ffi-digests-wasm.jsonl ffi node wasm/run_wasm.mjs wasm/target/wasm32-unknown-unknown/release/pqz_ffi_wasm.wasm 3
step "pqz-ffi: ffi_bench $FN"
run ffi-bench.jsonl ffi cargo run $C --features prove,test-hooks --example ffi_bench $FN

# ---- the vectors (P6e Task 11): smartcontracts/vectors/pqz/, generator pqz-ffi's pqz-vectors (as ffi/vectors/run.sh,
# check mode only: the image never rewrites them); tamper.py (179 single-leaf edits, each caught) with --full only
V=../smartcontracts/vectors/pqz
step "vectors: pqz-vectors --check (a second generation, byte for byte, every proof and negative input through pqz_precompile)"
run vectors-build.txt ffi cargo build $C --features prove --bin pqz-vectors
run vectors-check.txt ffi target/release/pqz-vectors --check
step "vectors: pqz_kat.py --check (independent Python)"
run vectors-pqz-kat.txt . python3 -I $V/pqz_kat.py --check
step "vectors: wasm32 replay (every proof proved again by pqz-ffi in wasm32: byte-equal, valid)"
run vectors-wasm.jsonl ffi node vectors/replay_wasm.mjs wasm/target/wasm32-unknown-unknown/release/pqz_ffi_wasm.wasm
if [ $MODE = full ]; then
  step "vectors: tamper.py (each checker catches changed leaves)"
  run vectors-tamper.txt ffi python3 -I vectors/tamper.py
fi

# ---- Rust = C (port plan Task 12): the Rust core pqzl/rust/ against values the C core fixed. The pqz-ffi and vectors
# stages above already run the Rust core (pqz-ffi's default backend pqzl-rust) against the C core's frozen digests,
# self-test and vectors; this stage adds only what they do not cover: the pqzl prover's own proofs_fnv (native, wasm32)
# and the keys KAT. Nothing above is repeated (owner 2026-10-16).
R=pqzl/rust
step "Rust = C: build (bench, keys_kat, the wasm32 bench module)"
run rust-build.txt $R sh -c "cargo build $C --features bench --bin bench && cargo build $C --features test-hooks --bin keys_kat \
  && cd wasm && cargo build $C --target wasm32-unknown-unknown"
step "Rust = C: proofs_fnv = the C core's (bench 5 5 63, bench 2 2 16320: the op 7 shapes, wasm32 3 1 63)"
run rust-fnv-native.jsonl $R target/release/bench 5 5 63
run rust-fnv-txm.jsonl $R target/release/bench 2 2 16320
run rust-fnv-wasm.jsonl $R node wasm/run_wasm.mjs 3 1 63
if [ $MODE = full ]; then
  step "Rust = C: the same proofs with verify_fast (bench 5 50 63, 2 50 16320, wasm32 3 10 63)"
  run rust-fast-native.jsonl $R env PQZ_VERIFY=fast target/release/bench 5 50 63
  run rust-fast-txm.jsonl $R env PQZ_VERIFY=fast target/release/bench 2 50 16320
  run rust-fast-wasm.jsonl $R env PQZ_VERIFY=fast node wasm/run_wasm.mjs 3 10 63
fi
step "Rust = C: keys KAT (keys_kat 100 = the C core's pqz_keys_kat 100 lines; pqz_kat.py --c-keys)"
(cd $R && target/release/keys_kat 100) > "$OUT/rust-keys-kat.jsonl" 2> "$OUT/rust-keys-kat-stderr.txt" || true
run rust-keys-pqz-kat.txt . python3 -I $V/pqz_kat.py --c-keys "$OUT/rust-keys-kat.jsonl"

step "tables and comparison"
python3 -I artifact/results.py check "$OUT" | tee "$OUT/summary.txt"
step "done: $OUT"
grep -q '^RESULT: PASS' "$OUT/summary.txt"
