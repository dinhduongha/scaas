#!/bin/sh
# Plan 5h Task 8b: LaZer's codegen (pqz-core/pqzl/params/codegen, pinned Sage image, no network) on the set n2304-kmax4096 (set (a))
# specs here (after e-s1.txt confirmed their pqz_delta / kmlwe_min): pqz_<rel>_params.h next to each spec (the set's
# headers: pqzl/build.sh PQZ_SET=n2304-kmax4096 includes this directory), then pqzl/params/to_rust.py converts them
# into rust/. As pqzl/params/p16k/regen16k.sh, with --memory.
#   scripts/capped pqz-core/params/sets/n2304-kmax4096/regen.sh <LaZer 3330e48> [specs] > pqz-core/params/sets/n2304-kmax4096/codegen.txt
set -u
IMG=sagemath/sagemath@sha256:4f5589eb6c565949a006f8665de2876b8414410daf5ac554f4434a15d4f3d528   # tag 10.7
LZ=$(cd "$1" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
shift
[ $# -gt 0 ] || set -- reg tx tx0 burn ds dr txm2 txm20 txm4 txm40 txm8 txm80 txm16 txm160
[ "$(git -C "$LZ" rev-parse HEAD)" = 3330e487228f633eceb322807b13a596b516770f ] || { echo "LaZer must be at 3330e48" >&2; exit 1; }
echo "LaZer $(git -C "$LZ" rev-parse HEAD); image $IMG"
rc=0
for r in "$@"; do
  t0=$(date +%s)
  docker run --rm --network none --memory 2g --cpus 1 -v "$LZ/third_party":/lz/third_party:ro -v "$HERE/../../../pqzl/params/codegen":/lz/codegen:ro \
    -v "$HERE/${r}_params.sage":/lz/params.sage:ro --entrypoint /bin/sh "$IMG" -c \
    'mkdir -p /tmp/w && cp -r /lz/codegen /tmp/w/ && ln -s /lz/third_party /tmp/w/third_party && cd /tmp/w/codegen && sage lnp-tbox-codegen.sage /lz/params.sage' \
    > "$HERE/pqz_${r}_params.h" 2> "$HERE/$r.err" || rc=1
  echo "== $r: $(( $(date +%s) - t0 )) s, $(wc -c < "$HERE/pqz_${r}_params.h") B, sha256 $(sha256sum < "$HERE/pqz_${r}_params.h" | cut -c1-16)"
  sed -n -e '3,5p' -e '/^\/\/ total = /p' -e '/^\/\/ Proof size/{n;p}' "$HERE/pqz_${r}_params.h" | sed 's/^/   /'
  grep -v 'rop: ' "$HERE/$r.err" | sed 's/^/   stderr: /' | head -20   # the old lwe-estimator's attack lines dropped
  rm -f "$HERE/$r.err"
done
python3 -I "$HERE/../../../pqzl/params/to_rust.py" n2304-kmax4096 || rc=1
echo "regen rc=$rc"
exit $rc
