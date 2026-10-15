#!/bin/sh
# P6f Tasks 1-3: the test suite inside the pinned SDK image (Ubuntu 26.04, OpenSSL 3.5 like the node's base image:
# the host's OpenSSL 3.0 has no ML-DSA, so MLDsa.IsSupported is false there). Run under scripts/capped:
#   scripts/capped pqz-core/nethermind/run-tests.sh      -> runs/<date>-test.txt
# Needs ref/ (ref.sh), bin/corpus.jsonl (corpus.py), pqz-core/ffi/target/release/libpqz_ffi.so and
# bin/test-hooks/libpqz_ffi.so (README §Build).
set -eu
cd "$(dirname "$0")"
HERE=$(pwd)
ROOT=$(cd ../.. && pwd)
SDK=mcr.microsoft.com/dotnet/sdk:10.0.301-resolute@sha256:196f61c6262aa890f41dd654ff52d3b995187124a37778fb990ed0c31c26da44
OUT=runs/$(date +%F)-test.txt
docker run --rm --memory 4g --cpus 4 -u "$(id -u):$(id -g)" -e HOME=/tmp -e DOTNET_CLI_HOME=/tmp -e DOTNET_CLI_TELEMETRY_OPTOUT=1 -e DOTNET_NOLOGO=1 \
  -e NUGET_PACKAGES="$HOME/.nuget/packages" -v "$HOME/.nuget/packages:$HOME/.nuget/packages" \
  -v "$ROOT:$ROOT" -w "$HERE" "$SDK" sh -c '
    echo "# P6f tests in $(. /etc/os-release; echo $PRETTY_NAME), $(openssl version), SDK $(dotnet --version), $(date -u +%FT%TZ)"
    dotnet test Nethermind.Pqz.Test/Nethermind.Pqz.Test.csproj -c Release -m:2 -p:UseSharedCompilation=false --logger "console;verbosity=normal"
    echo "rc=$?"' > "$OUT" 2>&1
grep -E "^# P6f|Passed!|Failed!|Total tests|Passed:|Failed:|rc=" "$OUT"
