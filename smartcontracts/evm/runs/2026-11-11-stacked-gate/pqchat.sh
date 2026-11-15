#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# The stacked gate's PqChat on-chain group (3c T95's local run; 3r renamed the topic's owner to its admin and never ran it):
# PqChat is not a group of matrix.sh (its hook is one line there, not yet added), so as 3c ran it: a fresh anvil (Amsterdam,
# 200 M, 128 KiB code), deploy.sh evm with DEPLOY_PQCHAT=1, then script/onchain/run.sh local PqChat --tc PqChatOnchain
# --ffi (its records-local-pqchat.jsonl and negatives as every group's), anvil's dev keys 0-3. Under scripts/capped
# (gates.sh pqchat); anvil stops on exit. Local only.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE/../.."
PORT=${PORT:-18642}
RPC=http://127.0.0.1:$PORT
T=$(mktemp -d)
A=
trap '[ -z "$A" ] || kill "$A" 2> /dev/null; rm -rf "$T"' EXIT
trap 'exit 1' INT TERM
anvil --chain-id 31337 --hardfork amsterdam --gas-limit 200000000 --code-size-limit 131072 --port "$PORT" > "$T/anvil.log" 2>&1 &
A=$!
for i in $(seq 60); do
  cast chain-id --rpc-url "$RPC" > /dev/null 2>&1 && break
  [ "$i" -lt 60 ] || { cat "$T/anvil.log"; echo "anvil did not start"; exit 1; }
  sleep 1
done
echo "[local/pqchat] anvil up (chain 31337, port $PORT)"
D0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
export DEPLOY_NAME=local-pqchat-testnet
export DEPLOY_JSON=deployments/$DEPLOY_NAME.json RELEASES_JSON=deployments/$DEPLOY_NAME-releases.json
rm -f "$RELEASES_JSON"
env PRIVATE_KEY=$D0 FOUNDRY_OUT=out/onchain-deploy FOUNDRY_CACHE_PATH=cache/onchain-deploy CHAIN_CODE_LIMIT=131072 \
  RELEASES_WRITE=true DEPLOY_PQCHAT=1 NOTICE_PERIOD=0 DEMO_SUPPLY=1000000000000 VERIFY_TARGET=local \
  DEPLOY_SALT="$(cast keccak scaas.deploy.stacked-gate.pqchat)" ../scripts/deploy.sh evm "$RPC" > "$T/deploy.out" 2>&1 ||
  { tail -30 "$T/deploy.out"; echo "[local/pqchat] FAIL deploy.sh"; exit 1; }
echo "[local/pqchat] deploy ok: $DEPLOY_JSON"
env ONCHAIN_RPC="$RPC" PRIVATE_KEY=$D0 ONCHAIN_K1=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d \
  ONCHAIN_K2=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a \
  ONCHAIN_K3=0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6 \
  sh script/onchain/run.sh local PqChat --tc PqChatOnchain --ffi
