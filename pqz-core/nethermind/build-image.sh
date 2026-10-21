#!/bin/sh
# P6f Task 5 (D13, R1): build scaas/nethermind-pqz:2.2.0-<label> locally (never pushed) and check it.
#   scripts/capped pqz-core/nethermind/build-image.sh pqz1        -> runs/<date>-image-<label>.txt
#   CALIB=1 ...                                                   also the calib target (Task 6): ...-<label>-calib
#   FFI_REV=<commit> ...                                          the library from that commit (the reviewed one)
set -eu
L=${1:?label, e.g. pqz1}
cd "$(dirname "$0")"
ROOT=$(cd ../.. && pwd)
TAG=scaas/nethermind-pqz:2.2.0-$L
OUT=runs/$(date +%F)-image-$L.txt
mkdir -p runs bin
exec > "$OUT" 2>&1
run() { echo "\$ $*"; "$@"; echo "[rc=$?]"; echo; }
echo "# P6f image $TAG, $(date -u +%Y-%m-%dT%H:%MZ), commit $(git rev-parse --short HEAD)$(git diff --quiet HEAD -- "$ROOT/pqz-core" ':(top,exclude)pqz-core/nethermind/runs' || echo ' (dirty)')"
COMMIT=$(git rev-parse HEAD)$(git diff --quiet HEAD -- "$ROOT/pqz-core" ':(top,exclude)pqz-core/nethermind/runs' || echo -dirty)
# the reviewed library hash (review W-G, 2026-10-19), compiled into the plugin as well
EXP=$(sed -n 's/.*ExpectedLibrarySha256 = "\([0-9a-f]\{64\}\)";.*/\1/p' Nethermind.Pqz/SelfTest.cs)
[ ${#EXP} = 64 ] || { echo "FAIL no ExpectedLibrarySha256 in Nethermind.Pqz/SelfTest.cs"; exit 1; }
# FFI_REV=<commit>: libpqz_ffi.so from that commit's tree (the reviewed library), the plugin from the work tree
CTX=
if [ -n "${FFI_REV:-}" ]; then
  rm -rf bin/ffi-src && mkdir -p bin/ffi-src
  git -C "$ROOT" archive "$FFI_REV" LICENSE pqz-core smartcontracts/vectors/pqz | tar -x -C bin/ffi-src
  CTX="--build-context ffisrc=bin/ffi-src"
  COMMIT="$COMMIT+ffi@$(git -C "$ROOT" rev-parse "$FFI_REV")"
  echo "library sources: $FFI_REV = $(git -C "$ROOT" rev-parse "$FFI_REV")"
fi
run ./ref.sh
run python3 -I corpus.py bin/corpus.jsonl
export DOCKER_BUILDKIT=1
B="docker build -f Dockerfile --progress plain --resource memory=4g"   # BuildKit runs outside scripts/capped: cap it (oomd)
rm -rf bin/ffi-out
run $B $CTX --target ffi-export -o bin/ffi-out "$ROOT"
FFI=$(sha256sum bin/ffi-out/libpqz_ffi.so | cut -d' ' -f1)
echo "libpqz_ffi.so sha256 $FFI, reviewed $EXP"
# review W-G: the image carries only the reviewed library (the Dockerfile checks FFI_SHA256 again, the plugin at start-up)
[ "$FFI" = "$EXP" ] || { echo "FAIL the built library is not the reviewed one: review the build, set ExpectedLibrarySha256 = \"$FFI\" in Nethermind.Pqz/SelfTest.cs, commit, rebuild"; exit 1; }
run $B $CTX --target node --build-arg COMMIT="$COMMIT" --build-arg FFI_SHA256="$EXP" -t "$TAG" "$ROOT"
if [ "${CALIB:-0}" = 1 ]; then
  run $B $CTX --target calib --build-arg COMMIT="$COMMIT" --build-arg FFI_SHA256="$EXP" -t "$TAG-calib" "$ROOT"
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
