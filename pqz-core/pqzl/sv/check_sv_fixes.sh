#!/bin/sh
# SV-side regression for the two tbox fixes behind proofSystemId v2 (the generic side is ../check_tbox_fixes.sh):
# the specialised verifier must follow both, and the differential test must see it when it does not. For each fix,
# src/pqz_sv.c is copied with that one line reverted to the pre-v2 transcript and pqz_sv_diff is linked against it:
#   SZ (P6-SZ, lazer-crypto/lazer#24): sz_eval_challenges back to one pair of rows (2 M values) for all pairs;
#   L2 (P6-L2, lazer-crypto/lazer#25): every exact-l2 equation back to one domain (M + 2 (d - 1) + 3 since A-2).
# Each reverted build must show mismatches (honest proofs the generic verifier accepts and it rejects); the tree's
# own build must show none. Needs build/native (./build.sh native). Heavy: run under scripts/capped.
#   sv/check_sv_fixes.sh [pqz_sv_diff args]     (default "1 1 0 1 0 1 1 1 1 1": one honest proof per relation, every
#                                               built R_TXM shape included; PQZ_ARENA_MB 2048 for its M = 8)
# Exit 0 = both fixes in place and both reversions detected.
set -eu
cd "$(dirname "$0")/.."
A=${1:-"1 1 0 1 0 1 1 1 1 1"}
export PQZ_ARENA_MB=${PQZ_ARENA_MB:-2048}
B=build/svfix
mkdir -p $B
CC=${CC:-clang}
F="-std=gnu11 -O2 -fno-builtin -fno-math-errno -ffp-contract=off -w -DPQZ_SV -DPQZ_TEST_HOOKS -Ibuild/include -Isrc -Ilazer -Iparams"
H=build/native
OLD_SZ='  { uint64_t V[2 * M]; if (!urandom_q (V, 2 * M, seed, dom)) return 0; for (unsigned i = 0; i < LAMBDA / 2; i++) for (unsigned j = 0; j < M; j++) g[(2 * i) * M + j] = V[j], g[(2 * i + 1) * M + j] = V[M + j]; return 1; }'
sed "s|^  return urandom_q (g, LAMBDA \* M, seed, dom);\$|$OLD_SZ|" src/pqz_sv.c > $B/sv_sz.c
sed 's|ONE (M + 2 \* (DEG - 1) + 3 + i);|ONE (M + 2 * (DEG - 1) + 3);|' src/pqz_sv.c > $B/sv_l2.c
rc=0
for v in tree sz l2; do
  src=src/pqz_sv.c
  [ $v = tree ] || src=$B/sv_$v.c
  n=$(diff src/pqz_sv.c $src | grep -c '^>' || true)
  if [ $v != tree ] && [ "$n" != 1 ]; then echo "check_sv_fixes $v: revert did not apply ($n lines)"; rc=1; continue; fi
  $CC $F -c $src -o $B/pqz_sv_$v.o
  $CC -std=gnu11 -O2 -w -Isrc -o $B/pqz_sv_diff_$v test/pqz_sv_diff.c $H/hooks/pqz_rel.o $B/pqz_sv_$v.o \
    $H/pqz_lazer.o $H/pqz_ntt.o $H/pqz_arena.o
  # shellcheck disable=SC2086
  $B/pqz_sv_diff_$v $A > $B/$v.jsonl || true
  m=$(sed -n 's/.*"seed": [0-9]*, "cases": \([0-9]*\), "mismatches": \([0-9]*\).*/\1 \2/p' $B/$v.jsonl)
  echo "check_sv_fixes $v: cases mismatches = $m"
  set -- $m
  if [ $v = tree ]; then [ "${2:-x}" = 0 ] || rc=1; else [ "${2:-0}" -gt 0 ] || rc=1; fi
done
[ $rc = 0 ] && echo "check_sv_fixes: ok" || echo "check_sv_fixes: FAIL"
exit $rc
