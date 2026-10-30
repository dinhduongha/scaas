#!/usr/bin/env bash
# The UaRegistry Wasm exposes exactly the T3 functions: no admin, no upgrade, no setter (plan SOR-D18; spec S16, C13).
# usage: check-registry-interface.sh <scaas_ua_registry.wasm>
set -euo pipefail
want="__constructor key_owner receivable record_of register registration_of relayers require_authorized ua_at ua_count ua_of ua_page"
got=$(stellar contract info interface --wasm "$1" --output json 2>/dev/null \
  | python3 -c 'import json, sys; print(" ".join(sorted(e["function_v0"]["name"] for e in json.load(sys.stdin) if "function_v0" in e)))')
if [ "$got" != "$want" ]; then
  echo "registry interface: MISMATCH" >&2
  echo "  want: $want" >&2
  echo "  got:  $got" >&2
  exit 1
fi
echo "registry interface: ok"
