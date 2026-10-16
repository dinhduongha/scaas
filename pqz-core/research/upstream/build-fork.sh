#!/bin/sh
# fork variants from the HEAD snapshot (fork/pqz-core, unchanged sources), each with the xcheck bench copy:
#   as       = ./build.sh native as shipped (clang -O2, generic x86-64, PQZ_ASSERT=1)
#   noassert = same + -DPQZ_ASSERT=0 (LaZer's ASSERT_DISABLED, as upstream's config.h)
#   native   = noassert + -O3 -march=native -mtune=native (upstream's Makefile flags)
set -eu
X=$(cd "$(dirname "$0")" && pwd)
for v in as noassert native; do
  rm -rf "$X/fork-$v"; cp -a "$X/fork/pqz-core" "$X/fork-$v"
  case $v in
    noassert) sed -i 's/^CFLAGS_LIB="-std=gnu11 -O2 /CFLAGS_LIB="-std=gnu11 -O2 -DPQZ_ASSERT=0 /' "$X/fork-$v/build.sh" ;;
    native) sed -i 's/^CFLAGS_LIB="-std=gnu11 -O2 /CFLAGS_LIB="-std=gnu11 -O3 -march=native -mtune=native -DPQZ_ASSERT=0 /' "$X/fork-$v/build.sh" ;;
  esac
  grep '^CFLAGS_LIB=' "$X/fork-$v/build.sh"
  (cd "$X/fork-$v" && ./build.sh native >/dev/null)
  clang -std=gnu11 -O2 -w -I"$X/fork-$v/src" -o "$X/bench_fork_$v" "$X/shim/bench.c" "$X/fork-$v/build/native/libpqz.a"
done
ls -la "$X"/bench_fork_*
