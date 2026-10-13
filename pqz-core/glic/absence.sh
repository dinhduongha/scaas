#!/bin/sh
# G-LIC step 1 (docs/research/pqz-licence-inventory.md): GMP / MPFR / HEXL absence check for the pqz-core artifacts a
# release would ship (libpqz.a, libpqz.so, pqz.wasm with and without the specialised verifier) and the bench / test
# binaries. Builds from scratch into build/glic/, then prints every command and its output. Run under scripts/capped:
#   scripts/capped pqz-core/glic/absence.sh > pqz-core/glic/runs/absence-<date>.txt 2>&1
set -eu
cd "$(dirname "$0")/.."
B=build/glic   # git-ignored (build/)
NM=llvm-nm-18
PAT='gmp|mpfr|hexl'   # case-insensitive; the rewritten limb layer is pqz_mpn_* and does not match
run() { echo "\$ $*"; "$@"; echo "[rc=$?]"; echo; }
hits() { # $1 = label; stdin = names; prints the matching names and their count
  m=$(grep -iE "$PAT" || true); n=$(printf '%s' "$m" | grep -c . || true)
  echo "$1: $n names matching /$PAT/i"; [ -z "$m" ] || printf '%s\n' "$m"
}

echo "# pqz-core G-LIC absence check, $(date -u +%Y-%m-%dT%H:%MZ), commit $(git rev-parse --short HEAD)$(git diff --quiet HEAD -- . || echo ' (dirty)')"
run clang --version
run wasm-ld-18 --version
run $NM --version
rm -rf $B
run env B=$B ./build.sh all
run env SV=0 B=$B/wasm-nosv ./build.sh wasm
ART="$B/native/libpqz.a $B/native/libpqz.so $B/native/pqz_bench $B/native/kat_dump $B/native/pqz_sv_diff
     $B/wasm/pqz.wasm $B/wasm-nosv/wasm/pqz.wasm"
run sha256sum $ART

echo "## 1. symbol names (defined and undefined, every object / binary)"
for f in $ART; do
  echo "\$ $NM -A $f | grep -ciE '$PAT'"
  $NM -A "$f" 2>/dev/null | awk '{print $NF}' | hits "$f"
  echo
done
echo "\$ $NM -D --undefined-only $B/native/libpqz.so   (dynamic imports of the shared library)"
$NM -D --undefined-only $B/native/libpqz.so; echo

echo "## 2. linked libraries (ELF DT_NEEDED)"
for f in $B/native/libpqz.so $B/native/pqz_bench $B/native/kat_dump $B/native/pqz_sv_diff; do
  echo "\$ readelf -d $f | grep NEEDED"; readelf -d "$f" | grep NEEDED || echo "(none)"; echo
done
echo "\$ ar t $B/native/libpqz.a   (archive members)"; ar t $B/native/libpqz.a; echo

echo "## 3. wasm imports and exports (no import = nothing linked in at run time)"
for f in $B/wasm/pqz.wasm $B/wasm-nosv/wasm/pqz.wasm; do
  run llvm-objdump-18 --section-headers "$f"
  echo "\$ $NM --undefined-only $f"; $NM --undefined-only "$f" || true; echo
done

echo "## 4. embedded strings (library version banners, e.g. 'GNU MP', 'MPFR', 'HEXL')"
for f in $ART; do
  echo "\$ strings -a $f | grep -iE '$PAT'"; strings -a "$f" | hits "$f"; echo
done
echo "## 5. positive control: the same scans find GMP / MPFR where they are (system shared libraries, if installed)"
for f in /usr/lib/x86_64-linux-gnu/libgmp.so.10 /usr/lib/x86_64-linux-gnu/libmpfr.so.6; do
  [ -e "$f" ] || { echo "$f: not installed"; continue; }
  echo "\$ $NM -D --defined-only $f | grep -ciE '$PAT'"; $NM -D --defined-only "$f" | awk '{print $NF}' | hits "$f" | head -1
  echo "\$ strings -a $f | grep -ciE '$PAT'"; strings -a "$f" | hits "$f" | head -1; echo
done
echo "# end"
