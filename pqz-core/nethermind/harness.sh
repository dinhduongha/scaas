#!/bin/sh
# P6f Task 4: the P/Invoke boundary harness inside the pinned base image (its .NET 10.0.9 runtime and OpenSSL 3.5),
# against the production cdylib (pqz-core/ffi/target/release). Run under scripts/capped:
#   scripts/capped pqz-core/nethermind/harness.sh <minutes> <label>     -> runs/<date>-harness-<label>.txt
# Needs Harness/bin/Release/net10.0 (run-tests.sh builds it) and bin/corpus.jsonl.
set -eu
cd "$(dirname "$0")"
HERE=$(pwd)
ROOT=$(cd ../.. && pwd)
BASE=nethermind/nethermind:1.39.0@sha256:8af90a30989c16cb15e087bd250c623c98585e490a25950a75642460d497eae6
SDK=mcr.microsoft.com/dotnet/sdk:10.0.301-resolute@sha256:196f61c6262aa890f41dd654ff52d3b995187124a37778fb990ed0c31c26da44
OUT=runs/$(date +%F)-harness-$2.txt
docker run --rm --memory 4g --cpus 4 -u "$(id -u):$(id -g)" -e HOME=/tmp -e DOTNET_CLI_HOME=/tmp -e DOTNET_NOLOGO=1 \
  -e NUGET_PACKAGES="$HOME/.nuget/packages" -v "$HOME/.nuget/packages:$HOME/.nuget/packages" -v "$ROOT:$ROOT" -w "$HERE" "$SDK" \
  dotnet build Harness/Harness.csproj -c Release -m:2 -p:UseSharedCompilation=false -v q > /dev/null
{
  echo "# P6f harness ($2), $(date -u +%FT%TZ), image $BASE, commit $(git rev-parse --short HEAD)"
  docker run --rm --memory 4g --cpus 4 -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$ROOT:$ROOT" -w "$HERE" --entrypoint dotnet "$BASE" \
    Harness/bin/Release/net10.0/Harness.dll run "$ROOT/pqz-core/ffi/target/release" bin/corpus.jsonl "$ROOT" --minutes "$1" --threads 8
  echo "rc=$?"
} > "$OUT" 2>&1
tail -40 "$OUT"
