#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# SCaaS testnet reset 2, step 2 (owner 2026-11-10): deploy.sh evm (NET-EVM-11: Deploy.s.sol simulated, DeploySend.s.sol
# sends) at 26586d2e with every kind deploy.sh carries, DEPLOY_ZETHER=1 and DEPLOY_PQCHAT=1; the Step 5 env otherwise
# (runs/2026-11-10-ua-mtx-merge-t66b-step5-7622.txt) and matrix.sh's remote deploy (compiled first under scripts/capped into
# out/onchain-deploy). The send runs under scripts/capped as in reset 1 (RUNBOOK: scripts/capped deploy.sh evm): in a 1 GiB scope
# outside capped, DeploySend.s.sol was OOM-killed (1,044 MB anon) at 10:54:45Z before its first transaction (nonce 0). Deployer = index 0 of SCAAS_TESTNET_MNEMONIC_FILE (Step 5's,
# funded by test key 0x…04); the key only in this process's environment, never printed. Verification deferred (owner).
#   sh runs/2026-11-10-scaas-testnet-reset2/deploy2.sh > runs/2026-11-10-scaas-testnet-reset2/deploy.log 2>&1
set -eu
cd "$(dirname "$0")/../.."
RPC=${RPC_7622:-http://127.0.0.1:8545}
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
(umask 077; sed -n 's/^mnemonic:[[:space:]]*//p' "${SCAAS_TESTNET_MNEMONIC_FILE:?}" > "$T/m")
[ -s "$T/m" ] || (umask 077; grep -v '^#' "$SCAAS_TESTNET_MNEMONIC_FILE" > "$T/m")
PRIVATE_KEY=$(cast wallet private-key --mnemonic "$T/m" --mnemonic-index 0)
rm -f "$T/m"
export PRIVATE_KEY
echo "deployer $(cast wallet address --private-key "$PRIVATE_KEY"), chain $(cast chain-id --rpc-url "$RPC"), start $(date -u +%FT%TZ)"
CAPPED_SLOTS=3 ../../scripts/capped env \
  FOUNDRY_OUT=out/onchain-deploy FOUNDRY_CACHE_PATH=cache/onchain-deploy RELEASE_GAS_GATE=public CHAIN_CODE_LIMIT=131072 \
  RELEASES_JSON=deployments/7622-t66b-releases.json RELEASES_WRITE=true \
  DEPLOY_WRAPPED=1 DEPLOY_REGULATED=1 DEPLOY_ZETHER=1 DEPLOY_PQCHAT=1 NOTICE_PERIOD=0 DEMO_SUPPLY=1000000000000 \
  DEMO_HOLDER=0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69 COMPLIANCE_ADMIN=0x4e59b44847b379578588920cA78FbF26c0B4956C \
  DEPLOY_SALT="$(cast keccak "scaas.deploy.t66b.1")" VERIFY_TARGET=scaas-testnet \
  VERIFY=none VERIFY_REASON="owner 2026-11-10: verification after reset 2, later" \
  ../scripts/deploy.sh evm "$RPC"
echo "deploy.sh rc 0, end $(date -u +%FT%TZ)"
