#!/usr/bin/env bash
# Spec §3.9: no SCaaS NEAR contract can change its own code, keys or existence. Fails on any account-authority host
# API in a contract crate (a crate whose Cargo.toml builds a cdylib). With arguments, scans those paths instead.
# `promise_batch_action_add_key` covers the low-level env form of AddKey that the Promise names above do not match.
set -euo pipefail
NEAR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PAT='deploy_contract|add_full_access_key|add_access_key|delete_key|delete_account|deploy_global_contract|use_global_contract|promise_batch_action_add_key'
if [ $# -eq 0 ]; then
  for m in "$NEAR"/*/Cargo.toml; do grep -q cdylib "$m" && set -- "$@" "$(dirname "$m")/src"; done
fi
if grep -rnE --include='*.rs' "$PAT" "$@"; then
  echo "check_no_authority: forbidden account-authority API above (spec §3.9)" >&2
  exit 1
fi
echo "check_no_authority: clean ($# paths)"
