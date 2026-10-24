#!/bin/sh
# P6f R1: extract /nethermind of the pinned base image into ref/ (git-ignored) — the plugin compiles against exactly
# these assemblies. The container is created, copied from and removed; it is never started.
set -eu
cd "$(dirname "$0")"
IMG=${NM_BASE:-nethermind/nethermind:2.2.0@sha256:5cc0061e6a317e9249e1e1f537a0a40a2036525c62f1cb250943432f4c000a38}
docker image inspect "$IMG" > /dev/null 2>&1 || docker pull "$IMG"
rm -rf ref && mkdir ref
C=$(docker create "$IMG")
trap 'docker rm "$C" > /dev/null' EXIT
docker cp -q "$C":/nethermind/. ref/
echo "ref/ from $IMG ($(docker image inspect "$IMG" --format '{{.Id}}')): $(ls ref/*.dll | wc -l) dlls"
