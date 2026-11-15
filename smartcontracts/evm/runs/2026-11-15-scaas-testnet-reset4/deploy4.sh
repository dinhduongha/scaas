#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# SCaaS testnet reset 4, step deploy (TODO 3zd; owner standing go 2026-11-14): reset 3's deploy3.sh on the reset 4 tree
# (pre-reset4 a5cfe748a + RescueVault alloc + mldsa87-calib bd11da664): deploy.sh evm (NET-EVM-11: Deploy.s.sol
# simulated, DeploySend.s.sol sends, the deploy order in force), every kind deploy.sh carries, DEPLOY_ZETHER=1,
# DEPLOY_PQCHAT=1, DEPLOY_PQZ=1 (reset 4b: the PQZ releases 4, 5, 12, 13). Books by the chain's key (NET-EVM-13): deployments/scaas-testnet.json and
# scaas-testnet-t66b-releases.json. The RescueVault is not deployed here: it is in the genesis alloc (NET-EVM-14).
# Memory and keys as reset 3: the run under scripts/capped (outside it DeploySend.s.sol was OOM-killed in reset 2 and 3);
# deployer = index 0 of SCAAS_TESTNET_MNEMONIC_FILE, funded first by the genesis test key 0x…04; the key only in this
# process's environment, never printed. Verification is its own step (verify.sh).
#   RPC_7622=<url> SCAAS_TESTNET_MNEMONIC_FILE=<file> sh runs/2026-11-15-scaas-testnet-reset4/deploy4.sh > runs/2026-11-15-scaas-testnet-reset4/deploy.log 2>&1
set -eu
cd "$(dirname "$0")/../.."
command -v forge > /dev/null || PATH=$HOME/.foundry/bin:$PATH
RPC=${RPC_7622:?set RPC_7622 to the SCaaS testnet RPC (no default)}
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
(umask 077; sed -n 's/^mnemonic:[[:space:]]*//p' "${SCAAS_TESTNET_MNEMONIC_FILE:?}" > "$T/m")
[ -s "$T/m" ] || (umask 077; grep -v '^#' "$SCAAS_TESTNET_MNEMONIC_FILE" > "$T/m")
PRIVATE_KEY=$(cast wallet private-key --mnemonic "$T/m" --mnemonic-index 0)
rm -f "$T/m"
export PRIVATE_KEY
DEP=$(cast wallet address --private-key "$PRIVATE_KEY")
echo "deployer $DEP, chain $(cast chain-id --rpc-url "$RPC"), start $(date -u +%FT%TZ)"
if [ "$(cast balance --rpc-url "$RPC" "$DEP")" = 0 ]; then
  # the genesis test key 0x…04 (public test key of the SCaaS testnet genesis); explicit gas (EIP-8037: a new account's state gas)
  cast send --rpc-url "$RPC" --private-key "$(printf '0x%064x' 4)" --gas-limit 300000 --value 100ether "$DEP" \
    | grep -E '^(transactionHash|blockNumber|status|gasUsed) '
fi
echo "deployer balance $(cast balance --rpc-url "$RPC" --ether "$DEP")"
CAPPED_SLOTS=3 ../../scripts/capped env \
  FOUNDRY_OUT=out/onchain-deploy FOUNDRY_CACHE_PATH=cache/onchain-deploy RELEASE_GAS_GATE=public CHAIN_CODE_LIMIT=131072 \
  RELEASES_JSON=deployments/scaas-testnet-t66b-releases.json RELEASES_WRITE=true \
  DEPLOY_WRAPPED=1 DEPLOY_REGULATED=1 DEPLOY_ZETHER=1 DEPLOY_PQCHAT=1 DEPLOY_PQZ=1 NOTICE_PERIOD=0 DEMO_SUPPLY=1000000000000 \
  DEMO_HOLDER=0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69 \
  COMPLIANCE_ADMIN=0x0000000000000000000000004e59b44847b379578588920ca78fbf26c0b4956c \
  DEPLOY_SALT="$(cast keccak "scaas.deploy.reset4.1")" VERIFY_TARGET=scaas-testnet \
  VERIFY=none VERIFY_REASON="reset 4: verify.sh runs as its own step after the deploy" \
  ../scripts/deploy.sh evm "$RPC"
echo "deploy.sh rc 0, end $(date -u +%FT%TZ)"
