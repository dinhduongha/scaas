#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# PqVault plan V10e: pqvault-core's real-crypto e2e on a local anvil (tests/e2e.rs), capped, foreground; each anvil is the
# test's own (a port the OS gave) and stops with it. Short progress lines and a heartbeat every 30 s here; the full output in
# the git-ignored runs/2026-11-22-pqvault-e2e.log. Usage: runs/2026-11-22-pqvault-e2e.sh [test name …]
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.foundry/bin:$PATH" CARGO_INCREMENTAL=0
log=runs/2026-11-22-pqvault-e2e.log
: >"$log"
tests=("$@")
[ ${#tests[@]} -gt 0 ] || tests=(personal_vault_recovery_conflict_passphrase shared_vault_both_modes a_second_app_core_is_kept_apart)
for t in "${tests[@]}"; do
    echo "[pqvault-e2e] start $t"
    start=$SECONDS
    (while sleep 30; do echo "[pqvault-e2e] $t running $((SECONDS - start)) s"; done) &
    beat=$!
    CAPPED_SLOTS=${CAPPED_SLOTS:-4} ../../scripts/capped cargo test --locked --offline -j 2 --test e2e -- --ignored --exact "$t" \
        --nocapture >>"$log" 2>&1
    rc=$?
    kill "$beat" 2>/dev/null
    wait "$beat" 2>/dev/null
    grep -a '\[pqvault-e2e\]' "$log" | tail -n 3
    if [ "$rc" -eq 0 ]; then echo "[pqvault-e2e] ok $t ($((SECONDS - start)) s)"; else echo "[pqvault-e2e] FAIL $t rc $rc (see $log)"; fi
done
