#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# SCaaS testnet reset 3, step 2 (owner 2026-11-10 "tự động làm, không cần hỏi nữa"): reset 2's deploy2.sh on the merged
# build: deploy.sh evm (NET-EVM-11: Deploy.s.sol simulated, DeploySend.s.sol sends; the 3r order SmartKeyAccount factory,
# ComplianceRegistry, router, factory, configureChain, releases, setChainEntries) with every kind deploy.sh carries,
# DEPLOY_ZETHER=1 and DEPLOY_PQCHAT=1. FACTORY_ADMIN_NEXT is not set (optional; no next admin named): the factory admin
# stays the deployer, no transferAdmin. Books by the chain's key (NET-EVM-13): deployments/scaas-testnet.json and
# scaas-testnet-t66b-releases.json (the release list matrix.sh reads for scaas-testnet). COMPLIANCE_ADMIN is a UA id
# (bytes32, round 3r), the CREATE2 deployer's native UA as matrix.sh's.
# Memory: the deploy scripts compile under scripts/capped first (out/onchain-deploy). The run then goes under scripts/capped
# as reset 2's did (reset 1's RUNBOOK line): outside capped, DeploySend.s.sol was OOM-killed while it measured the plan on
# the fork, at 1 GiB in reset 2 (1,044 MB anon) and at 2 GiB in reset 3's first try (deploy-2gib-oom.log, nothing sent).
# Deployer = index 0 of SCAAS_TESTNET_MNEMONIC_FILE, funded first by the genesis test key 0x…04 (as reset 2); the key only
# in this process's environment, never printed. Verification is step 3 (verify.sh), not inside deploy.sh.
#   RPC_7622=<url> sh runs/2026-11-12-scaas-testnet-reset3/deploy3.sh > runs/2026-11-12-scaas-testnet-reset3/deploy.log 2>&1
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
  DEPLOY_WRAPPED=1 DEPLOY_REGULATED=1 DEPLOY_ZETHER=1 DEPLOY_PQCHAT=1 NOTICE_PERIOD=0 DEMO_SUPPLY=1000000000000 \
  DEMO_HOLDER=0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69 \
  COMPLIANCE_ADMIN=0x0000000000000000000000004e59b44847b379578588920ca78fbf26c0b4956c \
  DEPLOY_SALT="$(cast keccak "scaas.deploy.reset3.1")" VERIFY_TARGET=scaas-testnet \
  VERIFY=none VERIFY_REASON="reset 3: verify.sh runs as its own step after the deploy" \
  ../scripts/deploy.sh evm "$RPC"
echo "deploy.sh rc 0, end $(date -u +%FT%TZ)"
