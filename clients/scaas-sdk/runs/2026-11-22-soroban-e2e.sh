#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# The SDK's Soroban local-network e2e (plan T39, open from T41.soroban), from the worktree root:
#   clients/scaas-sdk/runs/2026-11-22-soroban-e2e.sh
# Builds the Wasm (`build.sh soroban`, capped), starts the pinned Protocol 30 quickstart (quickstart.sh: one container,
# --memory 3g; removed on every exit), then the ignored test `tests/soroban_e2e.rs` (capped, -j2): A hands a pay off to B, B lands
# it, the same blob is ImportConsumed, A's own self-relay lands (paid by key 2, then by A's own key), a native XLM send lands.
# Gate step `sdk-soroban-e2e`.
set -euo pipefail
W=$(git rev-parse --show-toplevel)
QS=$W/smartcontracts/soroban/scripts/quickstart.sh
STELLAR_BIN=${STELLAR_BIN:-$("$QS" cli)}
export STELLAR_BIN PATH="$(dirname "$STELLAR_BIN"):$PATH"
echo "[sor-e2e] build Wasm"
CARGO_BUILD_JOBS=2 "$W/scripts/capped" "$W/smartcontracts/scripts/build.sh" soroban
echo "[sor-e2e] quickstart"
"$QS" up # exit 3 when a scaas-stellar container already exists: never ours to remove
trap '"$QS" down' EXIT
trap 'exit 130' INT TERM
"$QS" wait
cd "$W/clients/scaas-sdk"
echo "[sor-e2e] cargo test --test soroban_e2e"
"$W/scripts/capped" cargo test --locked --offline -j2 --no-default-features --features vault,wallet,soroban \
    --test soroban_e2e -- --ignored --nocapture
echo "[sor-e2e] PASS"
