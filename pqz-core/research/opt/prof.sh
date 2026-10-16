#!/bin/sh
# P6d-2 gprof profile of the current tree (perf is blocked on the dev host): library and bench with -pg, no
# stack protector, one R_TX prove + verify under scripts/capped; flat profile to opt/runs/<label>-gprof.txt.
#   opt/prof.sh <label> [rel]        (rel as pqz_bench: 1 = R_REG, 2 = R_TX (default))
set -eu
cd "$(dirname "$0")/../../pqzl" # the PQZL core: build/, src/, test/, kat/
CAPPED=${CAPPED:-$(git rev-parse --show-toplevel)/scripts/capped}
P=build/prof
mkdir -p $P
./build.sh native >/dev/null # lazer.h
F="-std=gnu11 -O2 -pg -fno-builtin -fno-math-errno -ffp-contract=off -w -Ibuild/include -Isrc -Ilazer -Iparams"
for f in src/pqz_lazer.c src/pqz_ntt.c src/pqz_arena.c src/pqz_rel.c; do
  ${CC:-clang} $F -c "$f" -o $P/"$(basename "$f" .c)".o
done
${CC:-clang} -std=gnu11 -O2 -pg -w -Isrc -o $P/pqz_bench test/pqz_bench.c $P/pqz_*.o
(cd $P && $CAPPED ./pqz_bench 1 0 "${2:-2}" > bench.jsonl)
gprof -b -p $P/pqz_bench $P/gmon.out > "../research/opt/runs/$1-gprof.txt"
gprof -b -q $P/pqz_bench $P/gmon.out > "$P/$1-callgraph.txt"
head -30 "../research/opt/runs/$1-gprof.txt"
