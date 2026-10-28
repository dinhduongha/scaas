#!/usr/bin/env bash
# Build one on-chain family (or all) with its native tool. Heavy: the caller wraps it in scripts/capped.
# usage: build.sh <evm|aptos|sui|soroban|cosmos|ton|solana|near|algorand|all>
set -euo pipefail
SC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAMILIES="evm aptos sui soroban cosmos ton solana near algorand"
build() {
  echo "== build $1"
  case "$1" in
    evm)     (cd "$SC/evm" && forge build) ;;
    aptos)   aptos move compile --package-dir "$SC/move/aptos" --dev --skip-fetch-latest-git-deps ;;
    sui)     sui move build --path "$SC/move/sui" ;;
    soroban) (cd "$SC/soroban" && cargo build --target wasm32v1-none --release) ;;
    cosmos)  "$SC/cosmos/build-wasm.sh" ;;
    ton)     (cd "$SC/ton" && { [ -d node_modules ] || npm ci; } && npm run build) ;;
    solana)  (export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"; cd "$SC/solana" && cargo build-sbf) ;;
    near)    for m in "$SC"/near/*/Cargo.toml "$SC"/near/integration/*/Cargo.toml; do grep -q 'cdylib' "$m" || continue  # contract crates (+ test fixtures)
               (cd "$(dirname "$m")" && CARGO_BUILD_JOBS=2 cargo near build non-reproducible-wasm --no-abi); done ;;
    # puyapy (pinned in requirements.txt, venv .venv) → out/*.{approval,clear}.bin + ARC-56; artifacts.json rewritten.
    # Two passes (T15, spec §4.8): the executor LogicSig with a sentinel router id (+ its source map, for the tests'
    # failure messages), split around it into EXEC_PREFIX / EXEC_SUFFIX, then every app with both baked into the router.
    algorand) X=ROUTER_APP_ID=0x5ca5ec0de0e1ec01; "$SC/algorand/scripts/venv.sh" && (cd "$SC/algorand" \
               && . .venv/bin/activate && rm -rf out \
               && puyapy contracts/executor.py --out-dir "$PWD/out" --output-bytecode --no-output-teal -T "$X" \
               && T=$(python -I scripts/exec_split.py "${X#*=}") \
               && puyapy contracts --out-dir "$PWD/out" --output-bytecode --no-output-teal --no-output-source-map \
                    -T "$X" $T \
               && python -I scripts/artifacts.py ${ALGORAND_ARTIFACTS_CHECK:+--check}) ;;
    *) echo "unknown family '$1' (one of: $FAMILIES all)" >&2; exit 2 ;;
  esac
}
[ "${1:-}" = all ] && set -- $FAMILIES
[ $# -gt 0 ] || { echo "usage: $0 <$FAMILIES|all>" >&2; exit 2; }
for f in "$@"; do build "$f"; done
