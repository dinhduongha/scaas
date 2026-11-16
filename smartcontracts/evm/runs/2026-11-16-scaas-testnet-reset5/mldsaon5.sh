#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Reset 5: the real-transaction rows of deploy set mldsa-on (script/onchain/mldsa_on.py, branch mldsa-on-e2e) on the SCaaS
# testnet, with their own key set: indexes 60, 61, 62 of SCAAS_TESTNET_MNEMONIC_FILE (no matrix group's: sched.py's sets are
# 10-60 exclusive), topped up to sched.py's mldsa-on budget from index 0 (sched.py fund), the keys only in this process's environment, never
# printed. From smartcontracts/evm, outside capped (a remote target, as matrix.sh):
#   RPC_7622=<rpc> SCAAS_TESTNET_MNEMONIC_FILE=<file> MATRIX_OUT=runs/2026-11-16-matrix sh runs/2026-11-16-scaas-testnet-reset5/mldsaon5.sh
set -eu
command -v cast > /dev/null || PATH=$HOME/.foundry/bin:$PATH
RPC=${RPC_7622:?} T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
(umask 077; sed -n 's/^mnemonic:[[:space:]]*//p' "${SCAAS_TESTNET_MNEMONIC_FILE:?}" > "$T/m")
[ -s "$T/m" ] || (umask 077; grep -v '^#' "$SCAAS_TESTNET_MNEMONIC_FILE" > "$T/m")
mk() { cast wallet private-key --mnemonic "$T/m" --mnemonic-index "$1"; }
ONCHAIN_K1=$(mk 60) ONCHAIN_K2=$(mk 61) ONCHAIN_K3=$(mk 62) FUND_KEY=$(mk 0)
rm -f "$T/m"
export ONCHAIN_K1 ONCHAIN_K2 ONCHAIN_K3
A=$(for k in "$ONCHAIN_K1" "$ONCHAIN_K2" "$ONCHAIN_K3"; do cast wallet address --private-key "$k"; done | tr '\n' ' ')
echo "[mldsa-on] keys $A, start $(date -u +%FT%TZ)"
FUND_KEY=$FUND_KEY python3 -I script/onchain/sched.py fund "$RPC" $(for a in $A; do printf "mldsa-on=%s " "$a"; done)
FUND_KEY=
python3 -I script/onchain/mldsa_on.py --set mldsa-on --net scaas-testnet --rpc "$RPC"
echo "[mldsa-on] rc 0, end $(date -u +%FT%TZ)"
