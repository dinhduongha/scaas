#!/bin/sh
# run.sh <corpus> <minutes> <threads> <label>: start container pqz-leak detached + a detached sampler
set -eu
S=/tmp/claude-1000/-home-ha-work-ainative-scaas/8c42b1a5-f1f3-4226-bb0f-b8276053c550/scratchpad/leak
ROOT=/home/ha/work/ainative/scaas
BASE=nethermind/nethermind:2.2.0@sha256:5cc0061e6a317e9249e1e1f537a0a40a2036525c62f1cb250943432f4c000a38
docker run -d --name pqz-leak --memory 2g --cpus 4 -u "$(id -u):$(id -g)" -e HOME=/tmp -v "$ROOT:$ROOT:ro" -v "$S:$S:ro" \
  -w "$ROOT/pqz-core/nethermind" --entrypoint dotnet "$BASE" \
  Harness/bin/Release/net10.0/Harness.dll run "$S/lib" "$1" "$ROOT" --minutes "$2" --threads "$3"
rm -f "$S/$4.samples"
nohup "$S/sample.sh" pqz-leak 100000 "$S/$4.samples" > /dev/null 2>&1 &
echo "started $4"
