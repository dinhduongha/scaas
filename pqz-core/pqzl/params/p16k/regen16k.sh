#!/bin/sh
# Plan 5h Task 7: LaZer's codegen (../codegen, pinned Sage image, no network) on the 16k specs here, after
# e_s1_16k.sage's pqz_delta / kmlwe_min were written into them: pqz_<rel>_params.h next to each spec (the production
# names, so plan Task 8 copies them over ../pqz_<rel>_params.h), then ../to_rust.py's converter into p16k/rust/ (its
# strict parser checks every value fits its Rust type). As ../regen.sh, with --memory.
#   scripts/capped pqz-core/pqzl/params/p16k/regen16k.sh <LaZer 3330e48> [specs] > pqz-core/pqzl/params/p16k/codegen-16k.txt
set -u
IMG=sagemath/sagemath@sha256:4f5589eb6c565949a006f8665de2876b8414410daf5ac554f4434a15d4f3d528   # tag 10.7
LZ=$(cd "$1" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
shift
[ $# -gt 0 ] || set -- reg tx tx0 burn ds dr txm2 txm20 txm4 txm40 txm8 txm80 txm8g1 txm80g1
[ "$(git -C "$LZ" rev-parse HEAD)" = 3330e487228f633eceb322807b13a596b516770f ] || { echo "LaZer must be at 3330e48" >&2; exit 1; }
echo "LaZer $(git -C "$LZ" rev-parse HEAD); image $IMG"
rc=0
for r in "$@"; do
  t0=$(date +%s)
  docker run --rm --network none --memory 2g --cpus 1 -v "$LZ/third_party":/lz/third_party:ro -v "$HERE/../codegen":/lz/codegen:ro \
    -v "$HERE/${r}_params.sage":/lz/params.sage:ro --entrypoint /bin/sh "$IMG" -c \
    'mkdir -p /tmp/w && cp -r /lz/codegen /tmp/w/ && ln -s /lz/third_party /tmp/w/third_party && cd /tmp/w/codegen && sage lnp-tbox-codegen.sage /lz/params.sage' \
    > "$HERE/pqz_${r}_params.h" 2> "$HERE/$r.err" || rc=1
  echo "== $r: $(( $(date +%s) - t0 )) s, $(wc -c < "$HERE/pqz_${r}_params.h") B, sha256 $(sha256sum < "$HERE/pqz_${r}_params.h" | cut -c1-16)"
  sed -n -e '3,5p' -e '/^\/\/ total = /p' -e '/^\/\/ Proof size/{n;p}' "$HERE/pqz_${r}_params.h" | sed 's/^/   /'
  grep -v 'rop: ' "$HERE/$r.err" | sed 's/^/   stderr: /' | head -20   # the old lwe-estimator's attack lines dropped
  rm -f "$HERE/$r.err"
done
python3 -I -c "
import sys; sys.path.insert(0, '$HERE/..'); import to_rust as t
t.HERE, t.OUT, t.OVERSIZE = '$HERE', '$HERE/rust', set(); sys.argv = ['to_rust.py']; sys.exit(t.main())" || rc=1
echo "regen16k rc=$rc"
exit $rc
