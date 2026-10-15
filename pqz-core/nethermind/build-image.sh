#!/bin/sh
# P6f Task 5 (D13, R1): build scaas/nethermind-pqz:1.39.0-<label> locally (never pushed) and check it.
#   scripts/capped pqz-core/nethermind/build-image.sh pqz1        -> runs/<date>-image-<label>.txt
#   CALIB=1 ...                                                   also the calib target (Task 6): ...-<label>-calib
set -eu
L=${1:?label, e.g. pqz1}
cd "$(dirname "$0")"
ROOT=$(cd ../.. && pwd)
TAG=scaas/nethermind-pqz:1.39.0-$L
OUT=runs/$(date +%F)-image-$L.txt
mkdir -p runs bin
exec > "$OUT" 2>&1
run() { echo "\$ $*"; "$@"; echo "[rc=$?]"; echo; }
echo "# P6f image $TAG, $(date -u +%Y-%m-%dT%H:%MZ), commit $(git rev-parse --short HEAD)$(git diff --quiet HEAD -- "$ROOT/pqz-core" ":!$ROOT/pqz-core/nethermind/runs" || echo ' (dirty)')"
COMMIT=$(git rev-parse HEAD)$(git diff --quiet HEAD -- "$ROOT/pqz-core" ":!$ROOT/pqz-core/nethermind/runs" || echo -dirty)
run ./ref.sh
run python3 -I corpus.py bin/corpus.jsonl
export DOCKER_BUILDKIT=1
B="docker build -f Dockerfile --progress plain"
rm -rf bin/ffi-out
run $B --target ffi-export -o bin/ffi-out "$ROOT"
FFI=$(sha256sum bin/ffi-out/libpqz_ffi.so | cut -d' ' -f1)
echo "libpqz_ffi.so sha256 $FFI"
run $B --target node --build-arg COMMIT="$COMMIT" --build-arg FFI_SHA256="$FFI" -t "$TAG" "$ROOT"
if [ "${CALIB:-0}" = 1 ]; then
  run $B --target calib --build-arg COMMIT="$COMMIT" --build-arg FFI_SHA256="$FFI" -t "$TAG-calib" "$ROOT"
fi

echo "## checks"
run docker image inspect "$TAG" --format 'id {{.Id}} created {{.Created}} size {{.Size}}'
run docker image inspect "$TAG" --format '{{range $k, $v := .Config.Labels}}{{if or (eq (slice $k 0 5) "scaas") (eq $k "org.opencontainers.image.title")}}{{$k}}={{$v}}{{"\n"}}{{end}}{{end}}'
echo "RepoDigests (empty = never pushed): $(docker image inspect "$TAG" --format '{{json .RepoDigests}}')"
X=bin/image-check
rm -rf $X && mkdir -p $X
C=$(docker create "$TAG")
docker cp -q "$C":/nethermind/plugins/. $X/
docker rm "$C" > /dev/null
run ls -la $X
SO=$X/libpqz_ffi.so
LABEL=$(docker image inspect "$TAG" --format '{{index .Config.Labels "scaas.pqz.ffi.sha256"}}')
GOT=$(sha256sum $SO | cut -d' ' -f1)
[ "$GOT" = "$LABEL" ] && echo "ffi sha256 in the image = label: $GOT" || { echo "FAIL ffi sha256 $GOT != label $LABEL"; exit 1; }
echo "test-hook names in the image's library (must be 0): $(nm -D $SO | grep -ciE 'test_|pqz_test|TEST_ARENA|TEST_FAIL') / strings $(strings -a $SO | grep -cE 'TEST_ARENA|TEST_FAIL_WORKER|pqz_test_fail_worker')"
echo "GMP / MPFR / HEXL (glic/absence.sh's pattern /gmp|mpfr|hexl/i): symbols $(nm -A $SO 2>/dev/null | grep -ciE 'gmp|mpfr|hexl'), dynamic $(nm -D $SO | grep -ciE 'gmp|mpfr|hexl'), strings $(strings -a $SO | grep -ciE 'gmp|mpfr|hexl')"
echo "\$ readelf -d $SO | grep NEEDED"; readelf -d $SO | grep NEEDED
echo "\$ nm -D --defined-only $SO | grep ' T '"; nm -D --defined-only $SO | grep ' T '
run docker run --rm "$TAG" --version
echo "build-image: ok"
