#!/usr/bin/env bash
# T0 spike (plan UA-Soroban T0): the unit tests, the Wasm, then the network figures on the pinned Protocol 30 quickstart.
# Run with CAPPED_SLOTS=1 (a docker container runs). Writes runs/<date>-ua-soroban-t0-settings.json; the caller tees the log.
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
QS="$HERE/../scripts/quickstart.sh"
RUNS="$HERE/../runs"
DATE=${SPIKE_DATE:-$(date +%F)}
export STELLAR_BIN=${STELLAR_BIN:-$("$QS" cli)}
export SPIKE_RPC=http://127.0.0.1:${QS_PORT:-31980}/rpc
export SPIKE_PASSPHRASE="Standalone Network ; February 2017"
export SPIKE_CFG=$(mktemp -d)
trap '"$QS" down; rm -rf "$SPIKE_CFG"' EXIT   # down on every exit (no-op when the container is absent)
trap 'exit 130' INT TERM
NET=(--rpc-url "$SPIKE_RPC" --network-passphrase "$SPIKE_PASSPHRASE")

echo "# T0 spike at commit $(git -C "$ROOT" rev-parse --short HEAD) $(date -Is)"
echo "# stellar-cli: $("$STELLAR_BIN" --version | tr '\n' ' ')"
cd "$HERE"
SDK=$(cargo metadata --format-version 1 --manifest-path "$HERE/Cargo.toml" 2>/dev/null \
  | python3 -I -c 'import json,sys; print(next(p["manifest_path"] for p in json.load(sys.stdin)["packages"] if p["name"]=="soroban-sdk"))')
SDK=$(dirname "$SDK")/src
echo "# soroban-sdk $(basename "$(dirname "$SDK")") host functions used (exact Rust signatures):"
for f in ml_dsa_44_verify ml_dsa_65_verify secp256r1_verify; do
  awk -v f="$f" '$0 ~ "pub fn "f"\\(" {p=1} p {printf "%s", $0} p && /\)/ {print ""; exit}' "$SDK/crypto.rs" | tr -s ' ' | sed 's/^/#   /'
done
grep -hE 'pub fn (g1_add|g1_mul|g1_msm|g2_add|g2_mul|g2_msm|pairing_check)\(' "$SDK/crypto/bls12_381.rs" | sed 's/ {$//; s/^ */#   /'
echo "## unit tests (SDK testutils, protocol 30)"
"$ROOT/scripts/capped" cargo test -j2 -- --nocapture --test-threads=1 2>&1 | grep -E 'BUDGET|^test |test result|panicked'
# soroban-sdk 30 refuses a plain cargo build for Wasm: the CLI (>= 30) shakes the contract spec
CARGO_BUILD_JOBS=2 "$ROOT/scripts/capped" "$STELLAR_BIN" contract build --manifest-path "$HERE/ua-spike/Cargo.toml" --quiet
WASM="$HERE/target/wasm32v1-none/release/scaas_ua_spike.wasm"
echo "## wasm $(stat -c %s "$WASM") bytes"

"$QS" up
"$QS" wait
echo "# image: $(grep -o 'stellar/quickstart@sha256:[0-9a-f]*' "$QS")"
docker exec scaas-stellar sh -c 'stellar-core version | head -2; stellar-rpc version | head -1' | sed 's/^/# /'
"$STELLAR_BIN" network settings "${NET[@]}" --output json > "$RUNS/$DATE-ua-soroban-t0-settings.json"
for i in $(seq 1 30); do   # friendbot comes up after the RPC
  "$STELLAR_BIN" keys generate spike --config-dir "$SPIKE_CFG" "${NET[@]}" --fund --overwrite >/dev/null 2>&1 && break
  sleep 5
done
export SPIKE_ID=$("$STELLAR_BIN" contract deploy --wasm "$WASM" --source-account spike --config-dir "$SPIKE_CFG" "${NET[@]}" 2>"$SPIKE_CFG/deploy.err") \
  || { cat "$SPIKE_CFG/deploy.err" >&2; exit 1; }
echo "## spike contract $SPIKE_ID"
python3 -I "$HERE/measure.py" "$RUNS/$DATE-ua-soroban-t0-settings.json"
