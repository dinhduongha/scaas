#!/usr/bin/env bash
# The UaRegistry Wasm exposes exactly these functions: no admin, no upgrade, no setter (plan SOR-D18; spec S16, C13).
# usage: check-registry-interface.sh <scaas_ua_registry.wasm>
set -euo pipefail
want="__constructor accept_membership checked_of kem_key_at kem_key_of key_owner kind_name member_accepted member_checked membership_sig_of pop_of pqz_key_of pqz_key_sig_of pqz_pop_of receivable record_of register register_frost register_msig register_musig2 register_webauthn registration_of relayers require_authorized set_kem_key set_pqz_key store_pqz_pop ua_at ua_count ua_of ua_of_frost ua_of_msig ua_of_musig2 ua_of_webauthn ua_page"
iface=$(stellar contract info interface --wasm "$1" --output json) || { echo "registry interface: could not read $1" >&2; exit 1; }
got=$(python3 -c 'import json, sys; print(" ".join(sorted(e["function_v0"]["name"] for e in json.load(sys.stdin) if "function_v0" in e)))' <<<"$iface")
if [ "$got" != "$want" ]; then
  echo "registry interface: MISMATCH" >&2
  echo "  want: $want" >&2
  echo "  got:  $got" >&2
  exit 1
fi
echo "registry interface: ok"
