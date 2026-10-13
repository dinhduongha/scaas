#!/bin/sh
# Forbidden-symbol scan: the library objects may reference only memcpy, memset, __stack_chk_fail (and the
# wasm linker's __stack_pointer) and each other (no malloc, stdio, libm, GMP/MPFR, getentropy). build.sh runs
# it on every build:   ./check_symbols.sh [objects...]          (default build/native/pqz_*.o)
set -eu
cd "$(dirname "$0")"
[ $# -gt 0 ] || set -- build/native/pqz_*.o
NM=${NM:-$(command -v llvm-nm-18 || command -v llvm-nm || echo nm)} # reads ELF and wasm objects
ALLOWED="memcpy memset __stack_chk_fail __stack_pointer"
undef=$($NM -u "$@" | awk 'NF == 2 {print $2}' | sort -u)
def=$($NM --defined-only "$@" | awk 'NF == 3 {print $3}' | sort -u)
bad=$(for s in $undef; do
  case " $ALLOWED " in *" $s "*) continue ;; esac
  echo "$def" | grep -qx "$s" || echo "$s"
done)
if [ -n "$bad" ]; then
  echo "forbidden symbols:" $bad >&2
  exit 1
fi
echo "symbols ok: only $ALLOWED outside the library objects"
