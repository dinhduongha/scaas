#!/bin/sh
# Independent review of pqz_sv.c (docs/reviews/specs/2026-10-13-pqz-sv-review.md): the reproducers. Heavy: run under
# scripts/capped. Nothing here is linked into libpqz; production sources are only copied and patched under build/.
#   sv/review/review.sh dom          finding 3: beta4 (i = d - 1) and upsilon share one (seed, dom) (sz trace hook)
#   sv/review/review.sh domctl       the same on a copy of lnp-tbox.c with A-2 undone (upsilon back at M + 2 (d - 1)):
#                                    the control must report the shared dom (8a review m2)
#   sv/review/review.sh norm         cheating provers past the final hash: z1 / w / z21 norms (both verifiers must
#                                    reject, and accept once that one check is removed). z21 was finding 1 (no bound,
#                                    both accepted; lazer#26), fixed as P6-Z21: check_tbox_fixes.sh runs this mode
#   sv/review/review.sh zdiff [N J M] P6-Z21 differential: z21-inflated proofs of all six relations and the eight
#                                    built R_TXM shapes (mask M, default 16383; k = 1.25^0..J,
#                                    N seeds), generic and fast must agree and accept iff ||(z21, z22)||^2 <= Bsq
#   sv/review/review.sh fuzz SECS    libFuzzer, fast verifier alone, six relations, ASan + UBSan
set -eu
cd "$(dirname "$0")/../.."
PB=build${PQZ_BUILD_TAG:+/$PQZ_BUILD_TAG} # the C build root; gate.sh sets PQZ_BUILD_TAG = the set (concurrent gates: build/<set>/)
B=$PB/review
mkdir -p $B
CC=${CC:-clang}
FL="-std=gnu11 -O2 -fno-builtin -fno-math-errno -ffp-contract=off -w -I$PB/include -Isrc -Ilazer -Iparams"
[ -f $PB/native/libpqz.a ] || ./build.sh native >/dev/null

lib () { # lib OUT INCDIR SVSRC EXTRA_CFLAGS: libpqz variant with lnp-quad.c / pqz_sv.c from INCDIR / SVSRC
  o=$B/$1
  mkdir -p "$o"
  $CC -I"$2" $FL $4 -c src/pqz_lazer.c -o "$o/pqz_lazer.o"
  for f in pqz_ntt pqz_arena pqz_rel; do $CC $FL $4 -c src/$f.c -o "$o/$f.o"; done
  [ -z "$3" ] || $CC $FL $4 -c "$3" -o "$o/pqz_sv.o"
  ar rcs "$o/libpqz.a" "$o"/*.o
}

poc () { # the cheating prover: lnp_quad_prove (lines 1..335 of lnp-quad.c) with the hooks of normpoc_hooks.h
  mkdir -p $B/poc
  { echo '#include "lazer.h"'; cat sv/review/normpoc_hooks.h; sed -e '1d' -e '1,335{
s|^      polyvec_grandom (y1, params->log2stdev1, yseed, dom);$|&\n      if (pqz_poc_mode == 1) polyvec_lshift (y1, y1, 3);|
s|^      polyvec_grandom (y2, params->log2stdev2, yseed, dom);$|&\n      if (pqz_poc_mode == 2) polyvec_lshift (y21, y21, pqz_poc_shift);\n      if (pqz_poc_mode == 4) poc_mul0 (y21, pqz_poc_k);|
s|if (params->rej1)$|if (params->rej1 \&\& pqz_poc_mode != 1)|
s|if (params->rej2)$|if (params->rej2 \&\& !POC_Z21)|
s|rej = int_gt (norm, params->Bsqr);|rej = !POC_Z21 \&\& int_gt (norm, params->Bsqr);|
s|^      coder_enc_urandom3 (cstate, w1, m_, log2m);$|      if (pqz_poc_mode == 3) poc_shift (w1, m_, 2);\n&|
s|^  polyvec_scale (w1, gamma, w1);$|  if (POC_Z21) { polyvec_l2sqr (norm, y21); pqz_poc_z21sq = int_get_i64 (norm); polyvec_l2sqr (norm, y2); pqz_poc_z2sq = int_get_i64 (norm); }\n  if (pqz_poc_mode == 3) poc_shift (w1, m_, -2);\n&|
s|^  polyvec_dcompress_make_ghint (h, y22, w1, dcomp_param);$|&\n  if (pqz_poc_mode == 3) poc_add (h, 2);|
}' lazer/lnp-quad.c; } > $B/poc/lnp-quad.c
  n=$(diff lazer/lnp-quad.c $B/poc/lnp-quad.c | grep -c '^>' || true)
  echo "prover patch: $n lines added or changed"
  lib poc $B/poc src/pqz_sv.c "-DPQZ_NORM_POC -DPQZ_SV -DPQZ_TEST_HOOKS"
}

case "${1:-}" in
dom)
  for f in pqz_lazer pqz_ntt pqz_arena pqz_rel; do $CC $FL -DPQZ_SZ_TRACE -c src/$f.c -o $B/dom-$f.o; done
  $CC -std=gnu11 -O2 -w -I$PB/include -Isrc -o $B/dom_trace sv/review/dom_trace.c $B/dom-*.o
  $B/dom_trace | grep -v '^dom=' || true
  ;;
domctl)
  U=$B/a2ctl
  mkdir -p $U
  sed 's|hash, M + 2 \* (d - 1) + 1, params);|hash, M + 2 * (d - 1), params);|' lazer/lnp-tbox.c > $U/lnp-tbox.c
  echo "control: A-2 undone on $(diff lazer/lnp-tbox.c $U/lnp-tbox.c | grep -c '^>') line(s) of lnp-tbox.c"
  $CC -I$U $FL -DPQZ_SZ_TRACE -c src/pqz_lazer.c -o $U/dom-pqz_lazer.o
  for f in pqz_ntt pqz_arena pqz_rel; do $CC $FL -DPQZ_SZ_TRACE -c src/$f.c -o $U/dom-$f.o; done
  $CC -std=gnu11 -O2 -w -I$PB/include -Isrc -o $U/dom_trace sv/review/dom_trace.c $U/dom-*.o
  $U/dom_trace | grep -v '^dom=' || true
  ;;
norm)
  rm -rf $B/norm-out # a previous run's proofs (another parameter set's) must never be verified or exported
mkdir -p $B/noz1 $B/now $B/noz21 $B/norm-out
  poc
  $CC -std=gnu11 -O2 -w -DPQZ_NORM_POC -I$PB/include -Isrc -o $B/normpoc_prove sv/review/normpoc.c $B/poc/libpqz.a
  # controls: one check removed in both verifiers (lnp_quad_verify, pqz_sv.c verify_body)
  sed '336,$ s|b = int_le (l2sqr, bnd);|b = 1; /* review control */|' lazer/lnp-quad.c > $B/noz1/lnp-quad.c
  sed 's|if (!l2_le (W.zc, DEG \* mq, S->z1bnd))|if (0) /* review control */|' src/pqz_sv.c > $B/noz1/pqz_sv.c
  sed '336,$ s|b = int_le (l2sqr, params->Bsqr);|b = 1; /* review control */|' lazer/lnp-quad.c > $B/now/lnp-quad.c
  sed 's#if (s21 > S->Bsq || !l2_le (wl, DEG \* km, S->Bsq - s21))#if (0) /* review control */#' src/pqz_sv.c > $B/now/pqz_sv.c
  # P6-Z21 control: the z21 term removed from the ||(z21, w - gamma w1)|| check (the pre-fix verifiers)
  sed '336,$ s|^  int_add (l2sqr, l2sqr, l2z21);$|  /* review control */|' lazer/lnp-quad.c > $B/noz21/lnp-quad.c
  sed 's|l2_sum (z21, DEG \* m2r, S->Bsq);|0; /* review control */|' src/pqz_sv.c > $B/noz21/pqz_sv.c
  for v in noz1 now noz21; do
    for f in lnp-quad.c pqz_sv.c; do
      src=lazer/$f; [ $f = pqz_sv.c ] && src=src/$f
      [ "$(diff $src $B/$v/$f | grep -c '^>' || true)" = 1 ] || echo "control $v: patch of $f did not apply"
    done
    lib $v $B/$v $B/$v/pqz_sv.c "-DPQZ_SV"
    $CC -std=gnu11 -O2 -w -I$PB/include -Isrc -o $B/normpoc_verify_$v sv/review/normpoc.c $B/$v/libpqz.a
  done
  $CC -std=gnu11 -O2 -w -I$PB/include -Isrc -o $B/normpoc_verify sv/review/normpoc.c $PB/native/libpqz.a
  echo "== cheating prover"
  $B/normpoc_prove prove $B/norm-out
  echo "== production verifiers ($PB/native/libpqz.a)"
  $B/normpoc_verify verify $B/norm-out
  echo "== control: z1 norm check removed from both verifiers"
  $B/normpoc_verify_noz1 verify $B/norm-out
  echo "== control: ||(z21, w - gamma w1)|| check removed from both verifiers"
  $B/normpoc_verify_now verify $B/norm-out
  echo "== control: z21 term removed from the ||(z21, w - gamma w1)|| check in both verifiers (pre-P6-Z21)"
  $B/normpoc_verify_noz21 verify $B/norm-out
  ;;
zdiff)
  # P6-Z21 differential: z21-inflated proofs of every relation, both verifiers in-process (sv/review/z21diff.c)
  poc
  $CC -std=gnu11 -O2 -w -I$PB/include -Isrc -o $B/z21diff sv/review/z21diff.c $B/poc/libpqz.a -lm
  PQZ_ARENA_MB=${PQZ_ARENA_MB:-2048} $B/z21diff "${2:-1}" "${3:-31}" "${4:-16383}" # mask: six P6e forms + eight R_TXM
  ;;
fuzz)
  T=${2:-600}
  SAN="-fsanitize=address,undefined -fno-sanitize=vla-bound,pointer-overflow -fno-sanitize-recover=all"
  SRC="src/pqz_lazer.c src/pqz_ntt.c src/pqz_arena.c src/pqz_rel.c src/pqz_sv.c"
  ${CC} -O1 -g -fno-omit-frame-pointer -std=gnu11 -w -DPQZ_SV -DPQZ_TEST_HOOKS -I$PB/include -Isrc -Ilazer -Iparams \
    $SAN -fsanitize=fuzzer -o $B/sv_fuzz5 $SRC sv/review/sv_fuzz5.c
  mkdir -p $B/fuzz5-corpus
  ASAN_OPTIONS=detect_leaks=0 $B/sv_fuzz5 -max_total_time="$T" -max_len=128 -seed=7 -rss_limit_mb=3500 \
    -print_final_stats=1 $B/fuzz5-corpus > $B/fuzz5.log 2>&1 || echo "fuzz rc=$?"
  grep -E "^#[0-9]+ +(DONE|pulse|INITED)|ERROR|SUMMARY|stat::|Done|abort" $B/fuzz5.log | tail -12
  ;;
*)
  echo "usage: $0 dom | norm | zdiff [N J] | fuzz SECS" >&2
  exit 2
  ;;
esac
