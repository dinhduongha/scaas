#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# T66b Step 5b: the whole on-chain matrix on ONE target, self-contained (nothing read from another target's run). From
# smartcontracts/evm, through scripts/capped, in the foreground (README.md has the per-target commands):
#   matrix.sh local           a fresh anvil (chain 31337, Amsterdam, 200 M gas, 128 KiB code) on $PORT, deploy.sh on it,
#                             every group, stopped after; the PQ groups on a fresh local Nethermind copy with the PQZ and
#                             ML-DSA precompiles: COPY=<git-ignored dir> (copy.sh init, genesis0, copygen.py, up; down
#                             after), or one already up at LOCAL_PQ_RPC; neither: listed as not run. Needs no other chain.
#   matrix.sh scaas-testnet   the SCaaS testnet RPC (RPC_7622), its Step 5 deploy deployments/7622.json
#   matrix.sh <name>          another testnet: ONCHAIN_RPC; PRIVATE_KEY (its deployer) and ONCHAIN_K1..K3, or else
#                             indices 0-3 of SCAAS_TESTNET_MNEMONIC_FILE; deploy.sh first if deployments/<chainid>.json is
#                             missing and MATRIX_DEPLOY=1
# ONCHAIN_PQZ: precompile (the node answers OP_SELFTEST), offchain (only the OFFCHAIN group), off (no PQ group).
# MATRIX_GROUPS: the groups to run (default all). Outputs are named by target: records-<target>-<group>.jsonl,
# deployments/onchain-<target>-<group>.json. Keys are never printed.
set -eu
command -v anvil > /dev/null || PATH=$HOME/.foundry/bin:$PATH
tgt=${1:?target: local | scaas-testnet | <name>}
OUTD=runs/2026-11-10-ua-mtx-merge-t66b-step5b
GROUPS=${MATRIX_GROUPS:-tokens gov dex misc zether pq pqoff verifiers views}
T=$(mktemp -d)
A= CP=
CS=$(cd ../../pqz-core/nethermind/chain && pwd)
trap '[ -n "$A" ] && kill "$A" 2>/dev/null; [ -z "$CP" ] || sh "$CS/copy.sh" down > /dev/null 2>&1; rm -rf "$T"' EXIT INT TERM
# anvil's well-known dev keys (local only): 0 deploys, 1-3 sign
D0=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
D1=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
D2=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
D3=0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6
case $tgt in
local)
  PORT=${PORT:-18620}
  anvil --chain-id 31337 --hardfork amsterdam --gas-limit 200000000 --code-size-limit 131072 --port "$PORT" \
    > "$T/anvil.log" 2>&1 &
  A=$!
  for i in $(seq 90); do
    cast chain-id --rpc-url "http://127.0.0.1:$PORT" > /dev/null 2>&1 && break
    [ "$i" -lt 90 ] || { echo "anvil did not start"; cat "$T/anvil.log"; exit 1; }
    sleep 1
  done
  RPC=http://127.0.0.1:$PORT
  export ONCHAIN_K1=$D1 ONCHAIN_K2=$D2 ONCHAIN_K3=$D3 PRIVATE_KEY=$D0
  PQZ=${ONCHAIN_PQZ:-precompile}
  PQ_RPC=${LOCAL_PQ_RPC:-}
  if [ -z "$PQ_RPC" ] && [ -n "${COPY:-}" ] && [ "$PQZ" != off ]; then
    export COPY
    echo "## local copy (Nethermind, PQZ and ML-DSA precompiles) at $(basename "$COPY")"
    { sh "$CS/copy.sh" init && sh "$CS/copy.sh" genesis0 "$CS/engine-pqz.json" && python3 -I script/onchain/copygen.py "$COPY" &&
      CP=1 && sh "$CS/copy.sh" up "${COPY_IMAGE:-scaas/nethermind-pqz:2.2.0-pqz7}" genesis.pqz0.json; } \
      > "$OUTD/copy-local.log" 2>&1 || { tail -20 "$OUTD/copy-local.log"; exit 1; }
    PQ_RPC=http://10.76.22.10:8545  # the signer (docker-compose.copy.yml): no rate limit
    for i in $(seq 120); do
      [ "$(cast block-number --rpc-url "$PQ_RPC" 2> /dev/null || echo 0)" -ge 2 ] && break
      [ "$i" -lt 120 ] || { echo "the copy did not start"; exit 1; }
      sleep 1
    done
  fi
  MATRIX_DEPLOY=1 ;;
scaas-testnet)
  RPC=${RPC_7622:-http://127.0.0.1:8545}
  # the genesis-funded test keys 0x…01-0x…03 (the PQ group's e2e takes them by number)
  ONCHAIN_K1=$(printf '0x%064x' 1) ONCHAIN_K2=$(printf '0x%064x' 2) ONCHAIN_K3=$(printf '0x%064x' 3)
  export ONCHAIN_K1 ONCHAIN_K2 ONCHAIN_K3 PRIVATE_KEY=$ONCHAIN_K1
  PQZ=${ONCHAIN_PQZ:-precompile}
  PQ_RPC=$RPC ;;
*)
  RPC=${ONCHAIN_RPC:?ONCHAIN_RPC for target $tgt}
  # keys not given: indices 0 (deployer) and 1-3 of the testnet-only mnemonic file (its `mnemonic:` line, or the whole
  # file), copied into the run's private temp dir for cast (the phrase never on a command line, never printed), each key
  # only in this process's environment
  if [ -z "${PRIVATE_KEY:-}" ] && [ -n "${SCAAS_TESTNET_MNEMONIC_FILE:-}" ]; then
    (umask 077; sed -n 's/^mnemonic:[[:space:]]*//p' "$SCAAS_TESTNET_MNEMONIC_FILE" > "$T/m")
    [ -s "$T/m" ] || (umask 077; grep -v '^#' "$SCAAS_TESTNET_MNEMONIC_FILE" > "$T/m")
    mk() { cast wallet private-key --mnemonic "$T/m" --mnemonic-index "$1"; }
    PRIVATE_KEY=$(mk 0) ONCHAIN_K1=$(mk 1) ONCHAIN_K2=$(mk 2) ONCHAIN_K3=$(mk 3)
    export PRIVATE_KEY ONCHAIN_K1 ONCHAIN_K2 ONCHAIN_K3
    rm -f "$T/m"
  fi
  : "${PRIVATE_KEY:?PRIVATE_KEY (the deployer) or SCAAS_TESTNET_MNEMONIC_FILE}" "${ONCHAIN_K1:?}" "${ONCHAIN_K2:?}" "${ONCHAIN_K3:?}"
  PQZ=${ONCHAIN_PQZ:-off}
  PQ_RPC=$RPC ;;
esac
CHAIN=$(cast chain-id --rpc-url "$RPC")
export ONCHAIN_RPC=$RPC DEPLOY_JSON=deployments/$CHAIN.json RELEASES_JSON=deployments/$CHAIN-releases.json
[ "$tgt" != scaas-testnet ] || export RELEASES_JSON=deployments/7622-t66b-releases.json
if [ "${MATRIX_DEPLOY:-0}" = 1 ] && { [ "$tgt" = local ] || [ ! -f "$DEPLOY_JSON" ]; }; then
  echo "## deploy on $tgt (chain $CHAIN)"
  rm -f "$RELEASES_JSON"
  FOUNDRY_OUT=out/onchain-deploy FOUNDRY_CACHE_PATH=cache/onchain-deploy RELEASE_GAS_GATE=public CHAIN_CODE_LIMIT=${CHAIN_CODE_LIMIT:-131072} \
    RELEASES_WRITE=true \
    DEPLOY_WRAPPED=1 DEPLOY_REGULATED=1 DEPLOY_ZETHER=1 NOTICE_PERIOD=0 DEMO_SUPPLY=1000000000000 \
    DEPLOY_SALT=$(cast keccak "scaas.deploy.onchain.$tgt") COMPLIANCE_ADMIN=0x4e59b44847b379578588920cA78FbF26c0B4956C \
    ../scripts/deploy.sh evm "$RPC" > "$OUTD/deploy-$tgt.log" 2>&1 || { tail -20 "$OUTD/deploy-$tgt.log"; exit 1; }
  echo "ok deploy: $DEPLOY_JSON"
fi
if [ "$tgt" = scaas-testnet ]; then NOTE=runs/2026-11-10-ua-mtx-merge-t66b-step5-7622.txt; export NOTE; fi
python3 -I script/onchain/basebook.py "$tgt"
rc=0
for g in $GROUPS; do
  echo "## $g on $tgt"
  case $g in
  tokens|gov|dex|misc)
    G=$(echo "$g" | sed 's/^./\U&/')
    # forge's limit = its simulated gasUsed x m / 100 (README); tokens: x 2.00 (anvil undershot a CREATE by 19 % and a
    # kind-2 relay at x 1.30); misc: its SCaaSDex release and refund-heavy calls carry their own gas
    m=130 f=
    [ "$g" != tokens ] || { m=200; f=--ffi; }  # tokens: the ML-DSA-65 keys and signatures by node (vm.ffi)
    ONCHAIN_GAS_MULTIPLIER=${ONCHAIN_GAS_MULTIPLIER:-$m} script/onchain/run.sh "$tgt" "$G" --tc "$G" $f || rc=1 ;;
  zether)
    NET=$tgt RPC=$RPC PRIVATE_KEY=$ONCHAIN_K1 sh script/onchain/zether.sh || rc=1 ;;
  pq|pqoff)
    o=; [ $g = pq ] || o=--offchain
    if [ "$PQZ" = off ] || { [ "$PQZ" = offchain ] && [ $g = pq ]; } || [ -z "$PQ_RPC" ]; then
      echo "not run: $g (ONCHAIN_PQZ=$PQZ${PQ_RPC:+, }${PQ_RPC:-, no PQZ node for this target})"
    else
      EVM_OUT=${EVM_OUT:-out/t66b-e2e} python3 -I script/onchain/pq.py --net "$tgt" --rpc "$PQ_RPC" $o || rc=1
    fi ;;
  verifiers) python3 -I script/onchain/verifiers.py "$tgt" "$RPC" || rc=1 ;;
  views) python3 -I script/onchain/coverage.py views "$tgt" "$RPC" || rc=1 ;;
  esac
done
python3 -I script/onchain/coverage.py table --net "$tgt" > "$OUTD/table-$tgt.txt"
echo "matrix $tgt: rc $rc (table $OUTD/table-$tgt.txt)"
exit $rc
