#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# A local deploy set `mldsa-on` on an own single-node Nethermind copy (both precompiles), for mldsa_on.py before the live set
# (owner 2026-11-16). Its own container, data dir and port: never the live stack, never copy.sh's pqzcopy-* project. From
# smartcontracts/evm:
#   MO_COPY=<dir> sh script/onchain/mldsa_on_copy.sh init     copy.sh init + genesis0 + copygen.py into <dir> (Clique period 2 s)
#   MO_COPY=<dir> sh script/onchain/mldsa_on_copy.sh up       docker run (--memory 1700m) the signer, its RPC on 127.0.0.1:$MO_PORT
#   MO_COPY=<dir> ../../scripts/capped sh script/onchain/mldsa_on_copy.sh deploy   deploy.sh evm, MLDSA_PRECOMPILE=on, DEPLOY_PQZ=1
#   MO_COPY=<dir> ../../scripts/capped sh script/onchain/mldsa_on_copy.sh run [groups]   mldsa_on.py --set mldsa-on
#   sh script/onchain/mldsa_on_copy.sh down                   stop and remove the container (no leftover)
# The copy's genesis funds test keys 0x…01-0x…03 (copygen.py); its signer key is a throwaway in <dir>. Test only.
set -eu
CS=../../pqz-core/nethermind/chain
NAME=${MO_NAME:-mldsaon-signer}
PORT=${MO_PORT:-18575}
RPC=http://127.0.0.1:$PORT
IMAGE=${MO_IMAGE:-scaas/nethermind-pqz:2.2.0-pqz9}
K() { printf '0x%064x' "$1"; }
cmd=${1:?init, up, deploy, run or down}
case $cmd in
init)
  C=${MO_COPY:?MO_COPY: the copy's directory (git-ignored, e.g. scratchpad/)}
  COPY=$C sh $CS/copy.sh init
  COPY=$C sh $CS/copy.sh genesis0 "${MO_ENGINE:-$CS/engine-pqz.json}"
  python3 -I script/onchain/copygen.py "$C"
  python3 -I -c 'import json,sys; p=sys.argv[1]; g=json.load(open(p)); g["engine"]["Clique"]["params"]["period"]=2; json.dump(g,open(p,"w"),indent=1)' \
    "$C/genesis.pqz0.json" ;;
up)
  C=$(cd "${MO_COPY:?MO_COPY}" && pwd)
  docker run -d --name "$NAME" --memory 1700m --memory-swap 1700m --cpus 2 -p "127.0.0.1:$PORT:8545" \
    -v "$C/data-signer:/nethermind/nethermind_datadir" -v "$C/genesis.pqz0.json:/nethermind/genesis.json:ro" \
    -v "$C/config.signer.json:/nethermind/config.json:ro" -v "$C/password.txt:/nethermind/password.txt:ro" \
    -v "$C/keystore:/nethermind/keystore" "$IMAGE" --config /nethermind/config.json --datadir /nethermind/nethermind_datadir > /dev/null
  for i in $(seq 120); do
    [ "$(cast block-number --rpc-url "$RPC" 2> /dev/null || echo 0)" -ge 2 ] && break
    [ "$i" -lt 120 ] || { echo "[copy] FAIL no block in 120 s"; exit 1; }
    sleep 1
  done
  echo "[copy] up: $NAME, chain $(cast chain-id --rpc-url "$RPC"), $RPC" ;;
deploy)
  OUTD=${MATRIX_OUT:-runs/$(date +%Y-%m-%d)-mldsa-on-copy}
  mkdir -p "$OUTD"
  echo "[copy] deploy set mldsa-on (MLDSA_PRECOMPILE=on, DEPLOY_PQZ=1, DEPLOY_PQCHAT=1) …"
  t0=$(date +%s)
  env PRIVATE_KEY="$(K 1)" DEPLOY_NAME=local-mldsaon-testnet FOUNDRY_OUT=out/onchain-deploy FOUNDRY_CACHE_PATH=cache/onchain-deploy \
    RELEASE_GAS_GATE=public CHAIN_CODE_LIMIT=131072 RELEASES_WRITE=true RELEASES_JSON=deployments/local-mldsaon-testnet-releases.json DEPLOY_WRAPPED=1 DEPLOY_REGULATED=1 DEPLOY_ZETHER=1 \
    DEPLOY_PQZ=1 DEPLOY_PQCHAT=1 NOTICE_PERIOD=0 DEMO_SUPPLY=1000000000000 MLDSA_PRECOMPILE=on \
    DEPLOY_SALT="$(cast keccak scaas.deploy.mldsa-on.copy)" \
    COMPLIANCE_ADMIN=0x0000000000000000000000004e59b44847b379578588920ca78fbf26c0b4956c \
    ../scripts/deploy.sh evm "$RPC" > "$OUTD/deploy-copy.log" 2>&1 \
    || { echo "[copy] FAIL deploy: $(grep -E 'Error|FAIL|refus' "$OUTD/deploy-copy.log" | tail -1 | cut -c1-160)"; exit 1; }
  echo "[copy] deploy ok ($(($(date +%s) - t0))s)" ;;
run)
  OUTD=${MATRIX_OUT:-runs/$(date +%Y-%m-%d)-mldsa-on-copy}
  ONCHAIN_K1=$(K 1) ONCHAIN_K2=$(K 2) ONCHAIN_K3=$(K 3) DEPLOY_NAME=local-mldsaon-testnet MATRIX_OUT=$OUTD \
    EVM_OUT=${EVM_OUT:-out/t66b-e2e} python3 -I script/onchain/mldsa_on.py --set mldsa-on --net local-copy --rpc "$RPC" \
    ${2:+--groups "$2"} ;;
down)
  docker rm -f "$NAME" > /dev/null 2>&1 || true
  echo "[copy] down: $NAME removed" ;;
*) echo "unknown command $cmd"; exit 2 ;;
esac
