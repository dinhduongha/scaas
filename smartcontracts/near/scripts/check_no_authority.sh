#!/usr/bin/env bash
# Spec §3.9: no SCaaS NEAR contract can change its own code, keys or existence. Fails on any account-authority API
# (Promise methods and their env::promise_batch_action_* forms: deploy / global contracts, access and gas keys, key
# and account deletion) and on near-contract-standards' upgrade module, in the `src/` of every crate except the
# test-only ones (`integration`, `test-receiver`). With arguments, scans those paths instead.
# Not caught here (review item): a whole-balance transfer action.
set -euo pipefail
NEAR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PAT='deploy_|use_global_contract|add_full_access_key|add_access_key|add_gas_key|add_key_with|add_key_allowance|transfer_to_gas_key|delete_key|delete_account|near_contract_standards::upgrade|Upgradable'
if [ $# -eq 0 ]; then
  for m in "$NEAR"/*/Cargo.toml; do
    c="$(dirname "$m")"
    case "$(basename "$c")" in integration|test-receiver) continue ;; esac
    set -- "$@" "$c/src"
  done
fi
if grep -rnE --include='*.rs' "$PAT" "$@"; then
  echo "check_no_authority: forbidden account-authority API above (spec §3.9)" >&2
  exit 1
fi
echo "check_no_authority: clean ($# paths)"
