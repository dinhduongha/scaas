#!/bin/sh
# P6f R1: extract /nethermind of the pinned base image into ref/ (git-ignored) — the plugin compiles against exactly
# these assemblies. The container is created, copied from and removed; it is never started.
set -eu
cd "$(dirname "$0")"
IMG=${NM_BASE:-nethermind/nethermind:1.39.0@sha256:8af90a30989c16cb15e087bd250c623c98585e490a25950a75642460d497eae6}
docker image inspect "$IMG" > /dev/null 2>&1 || docker pull "$IMG"
rm -rf ref && mkdir ref
C=$(docker create "$IMG")
trap 'docker rm "$C" > /dev/null' EXIT
docker cp -q "$C":/nethermind/. ref/
echo "ref/ from $IMG ($(docker image inspect "$IMG" --format '{{.Id}}')): $(ls ref/*.dll | wc -l) dlls"
