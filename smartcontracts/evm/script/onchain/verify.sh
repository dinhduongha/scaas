#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# T66b Step 5b, NET-EVM-09 (owner 2026-11-10): the verification step on its own. Every contract deployed on the target's
# chain (vcheck.py's discovery: the deployment books, every broadcast, the getters that name a child) verified on its
# explorer, then the completeness check: each address verified, a linked EIP-1167 clone, or SSTORE2 data, else a fail
# row and exit 1. From smartcontracts/evm, outside scripts/capped (each forge verify-contract goes through it):
#   sh script/onchain/verify.sh scaas-testnet      RPC_7622, BLOCKSCOUT_API (defaults: loopback)
# matrix.sh runs it as the group `verify` and after each scaas-testnet group. Rows: runs/…-step5b/verify-<target>.txt.
set -eu
command -v cast > /dev/null || PATH=$HOME/.foundry/bin:$PATH
tgt=${1:?target}
case $tgt in
scaas-testnet) RPC=${RPC_7622:-http://127.0.0.1:8545} API=${BLOCKSCOUT_API:-http://127.0.0.1:4000/api} ;;
*) echo "[$tgt/verify] FAIL VERIFY_NOT_CONFIGURED: no explorer wired for this target"; exit 1 ;;
esac
exec python3 -I script/onchain/vcheck.py "$tgt" "$RPC" "$API" --fix
