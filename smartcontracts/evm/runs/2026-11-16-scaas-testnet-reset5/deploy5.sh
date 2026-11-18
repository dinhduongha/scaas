#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# SCaaS testnet reset 5, step deploy (owner 2026-11-16 "Ok, reset 5 before PR #18"; two deploy sets, owner 2026-11-16 "ok,
# option 2, one chain, two deploy sets"): reset 4's deploy4.sh once per set, mldsa-on (MLDSA_PRECOMPILE=on, the shipped
# default: MldsaVerifier 0x0130 / 0x0131 / 0x0134 on the chain's precompiles) and mldsa-off (MLDSA_PRECOMPILE=off: the
# ML-DSA kinds on the registry's expanded-key cache, the forge matrix's set), each its own DEPLOY_SALT and releases book;
# deploy.sh evm (NET-EVM-11: Deploy.s.sol simulated, DeploySend.s.sol sends in batches of 16), every kind deploy.sh carries,
# DEPLOY_ZETHER=1, DEPLOY_PQCHAT=1, DEPLOY_PQZ=1. The book deployments/scaas-testnet.json holds both sets (NET-EVM-13
# Change), mldsa-off at its top level. The RescueVault is in the genesis alloc (NET-EVM-14). Memory and keys as reset 4:
# the run under scripts/capped; deployer = index 0 of SCAAS_TESTNET_MNEMONIC_FILE, funded first by the genesis test key
# 0x…04; the key only in this process's environment, never printed. Verification is its own step (verify.sh).
#   RPC_7622=<url> SCAAS_TESTNET_MNEMONIC_FILE=<file> sh runs/2026-11-16-scaas-testnet-reset5/deploy5.sh <mldsa-on|mldsa-off> > runs/2026-11-16-scaas-testnet-reset5/deploy-<set>.log 2>&1
set -eu
cd "$(dirname "$0")/../.."
command -v forge >/dev/null || PATH=$HOME/.foundry/bin:$PATH
RPC=${RPC_7622:?set RPC_7622 to the SCaaS testnet RPC (no default)}
SET=${1:?mldsa-on | mldsa-off}
case $SET in
    mldsa-on) MODE=on REL=deployments/scaas-testnet-mldsa-on-t66b-releases.json ;;
    mldsa-off) MODE=off REL=deployments/scaas-testnet-t66b-releases.json ;;
    *)
        echo "deploy5: DEPLOY_SET_UNKNOWN $SET"
        exit 1
        ;;
esac
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
(
    umask 077
    sed -n 's/^mnemonic:[[:space:]]*//p' "${SCAAS_TESTNET_MNEMONIC_FILE:?}" >"$T/m"
)
[ -s "$T/m" ] || (
    umask 077
    grep -v '^#' "$SCAAS_TESTNET_MNEMONIC_FILE" >"$T/m"
)
PRIVATE_KEY=$(cast wallet private-key --mnemonic "$T/m" --mnemonic-index 0)
rm -f "$T/m"
export PRIVATE_KEY
DEP=$(cast wallet address --private-key "$PRIVATE_KEY")
echo "deployer $DEP, chain $(cast chain-id --rpc-url "$RPC"), set $SET, start $(date -u +%FT%TZ)"
if [ "$(cast balance --rpc-url "$RPC" "$DEP")" = 0 ]; then
    # the genesis test key 0x…04 (public test key of the SCaaS testnet genesis); explicit gas (EIP-8037: a new account's state gas)
    cast send --rpc-url "$RPC" --private-key "$(printf '0x%064x' 4)" --gas-limit 300000 --value 100ether "$DEP" |
        grep -E '^(transactionHash|blockNumber|status|gasUsed) '
fi
echo "deployer balance $(cast balance --rpc-url "$RPC" --ether "$DEP")"
CAPPED_SLOTS=3 ../../scripts/capped env \
    FOUNDRY_OUT=out/onchain-deploy FOUNDRY_CACHE_PATH=cache/onchain-deploy RELEASE_GAS_GATE=public CHAIN_CODE_LIMIT=131072 \
    RELEASES_JSON="$REL" RELEASES_WRITE=true DEPLOY_SET="$SET" MLDSA_PRECOMPILE="$MODE" \
    DEPLOY_WRAPPED=1 DEPLOY_REGULATED=1 DEPLOY_ZETHER=1 DEPLOY_PQCHAT=1 DEPLOY_PQZ=1 NOTICE_PERIOD=0 DEMO_SUPPLY=1000000000000 \
    DEMO_HOLDER=0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69 \
    COMPLIANCE_ADMIN=0x0000000000000000000000004e59b44847b379578588920ca78fbf26c0b4956c \
    DEPLOY_SALT="$(cast keccak "scaas.deploy.reset5.$SET")" VERIFY_TARGET=scaas-testnet \
    VERIFY=none VERIFY_REASON="reset 5: one whole-chain verify.sh after the matrix (owner 2026-11-15)" \
    DEPLOY_LOG="runs/2026-11-16-scaas-testnet-reset5/deploy-$SET-forge.log" \
    ../scripts/deploy.sh evm "$RPC"
echo "deploy.sh rc 0, set $SET, end $(date -u +%FT%TZ)"
