#!/bin/sh
# Forbidden-symbol scan: the library objects may reference only memcpy, memset, __stack_chk_fail (and the
# wasm linker's __stack_pointer) and each other (no malloc, stdio, libm, GMP/MPFR, getentropy). build.sh runs
# it on every build:   ./check_symbols.sh [objects...]          (default build/native/pqz_*.o)
# Paths are relative to the caller's directory; a missing file or an nm failure is an error (STATUS Open 9: the scan
# used to cd here first and print "symbols ok" over nm's errors). test/check_symbols_neg.sh checks both.
set -eu
if [ $# -eq 0 ]; then cd "$(dirname "$0")" && set -- build/native/pqz_*.o; fi
for f in "$@"; do [ -f "$f" ] || { echo "check_symbols: no such file: $f" >&2; exit 1; }; done
NM=${NM:-$(command -v llvm-nm-18 || command -v llvm-nm || echo nm)} # reads ELF and wasm objects
ALLOWED="memcpy memset __stack_chk_fail __stack_pointer"
u=$($NM -u "$@") || { echo "check_symbols: $NM -u failed" >&2; exit 1; }
d=$($NM --defined-only "$@") || { echo "check_symbols: $NM --defined-only failed" >&2; exit 1; }
undef=$(echo "$u" | awk 'NF == 2 {print $2}' | sort -u)
def=$(echo "$d" | awk 'NF == 3 {print $3}' | sort -u)
bad=$(for s in $undef; do
  case " $ALLOWED " in *" $s "*) continue ;; esac
  echo "$def" | grep -qx "$s" || echo "$s"
done)
if [ -n "$bad" ]; then
  echo "forbidden symbols:" $bad >&2
  exit 1
fi
echo "symbols ok: only $ALLOWED outside the library objects"
