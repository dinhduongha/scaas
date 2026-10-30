#!/usr/bin/env bash
# UA-Soroban local e2e on the pinned Protocol 30 quickstart (spec §10, S17; plan T10; gate step `e2e-soroban-local`):
# build the Wasm (capped), check the registry interface, start the quickstart (removed on every exit), then the node's
# e2e tests `e2e_soroban` and `e2e_soroban_ua` against it (capped, one slot, -j2).
# env: STELLAR_URL, STELLAR_PASSPHRASE, STELLAR_FRIENDBOT, STELLAR_BIN (defaults: the local quickstart, `stellar`);
# QS_PORT (quickstart.sh). usage: e2e-local.sh
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$here/../../.." && pwd)"
SOR="$ROOT/smartcontracts/soroban"
QS="$here/quickstart.sh"
port="${QS_PORT:-31980}"
export STELLAR_BIN="${STELLAR_BIN:-stellar}"
export STELLAR_URL="${STELLAR_URL:-http://127.0.0.1:$port/rpc}"
export STELLAR_PASSPHRASE="${STELLAR_PASSPHRASE:-Standalone Network ; February 2017}"
export STELLAR_FRIENDBOT="${STELLAR_FRIENDBOT:-http://127.0.0.1:$port/friendbot}"

echo "== e2e-local: $(git -C "$ROOT" rev-parse --short HEAD) $(date -u +%FT%TZ); $("$STELLAR_BIN" --version | head -1)"
echo "== build Wasm"
CARGO_BUILD_JOBS=2 "$ROOT/scripts/capped" "$ROOT/smartcontracts/scripts/build.sh" soroban
echo "== registry interface"
"$here/check-registry-interface.sh" "$SOR/target/wasm32v1-none/release/scaas_ua_registry.wasm"
if [ ! -d "$ROOT/clients/clientkeys/node_modules" ]; then
  echo "== clientkeys npm ci (the e2e signer, SOR-D13)"
  (cd "$ROOT/clients/clientkeys" && "$ROOT/scripts/capped" npm ci --no-audit --no-fund)
fi

echo "== quickstart"
"$QS" up   # exit 3 when a scaas-stellar container already exists: never ours to remove
trap '"$QS" down' EXIT
trap 'exit 130' INT TERM
"$QS" wait

cd "$ROOT/scaas-node"
echo "== cargo test --test e2e_soroban"
CAPPED_SLOTS=1 "$ROOT/scripts/capped" cargo test -j2 --test e2e_soroban -- --ignored --test-threads=1
echo "== cargo test --test e2e_soroban_ua"
CAPPED_SLOTS=1 "$ROOT/scripts/capped" cargo test -j2 --test e2e_soroban_ua -- --ignored --test-threads=1 --nocapture
echo "== e2e-local: PASS"
