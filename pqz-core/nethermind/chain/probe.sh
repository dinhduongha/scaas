#!/bin/sh
# P6f §10 step 2 probe (also "before" for step 1): e2e.py probe / before against one RPC.
#   probe.sh <engine-pqz.json> [rpc] [genesis-hash]          after T
#   BEFORE=1 probe.sh <engine-pqz.json> [rpc]                before T: the addresses are empty
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
E=${1:?engine-pqz.json}; RPC=${2:-http://127.0.0.1:18545}; G=${3:-}
if [ "${BEFORE:-0}" = 1 ]; then exec python3 -I "$HERE/e2e.py" before --engine "$E" --rpc "$RPC"; fi
exec python3 -I "$HERE/e2e.py" probe --engine "$E" --rpc "$RPC" ${G:+--genesis-hash "$G"}
