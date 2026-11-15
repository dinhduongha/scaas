#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# SCaaS testnet reset 3, step 5: the PQZ kinds 4, 5, 12, 13 by script/pqz/e2e.py (its own deploy: registry trio with the PQ
# kinds, factory, releases 0, 4, 5, 12, 13; ML-DSA / PQZ / msig holders with real proofs), the full run (sections 1-7),
# --split as the matrix's pq group, through e2e3.py (each transaction's gas limit given explicitly as pq.py asks it), test keys 0x…01-0x…03 (genesis-funded), PQZ_SET n2304-kmax4096 (the default; the
# contracts from EVM_OUT=out/t66b-e2e built at it). The RPC is named (no default). Outside scripts/capped in a 1G scope with
# no slot (owner 2026-11-10, remote broadcast). Log: e2e-pqz-scaas-testnet.txt beside this file; book
# deployments/scaas-testnet-pqz.json (copied beside this file as deployments-scaas-testnet-pqz.json).
#   RPC_7622=<url> sh runs/2026-11-12-scaas-testnet-reset3/e2e3.sh > runs/2026-11-12-scaas-testnet-reset3/e2e3.log 2>&1
set -eu
cd "$(dirname "$0")/../.."
RPC=${RPC_7622:?set RPC_7622 to the SCaaS testnet RPC (no default)}
H=runs/2026-11-12-scaas-testnet-reset3
e=0
systemd-run --user --scope --quiet -p MemoryMax=1G -p MemorySwapMax=0 -- env EVM_OUT=out/t66b-e2e \
  python3 -I "$H/e2e3.py" --rpc "$RPC" --split --keys 1,2,3 --log "$H/e2e-pqz-scaas-testnet.txt" || e=$?
[ ! -f deployments/scaas-testnet-pqz.json ] || cp deployments/scaas-testnet-pqz.json "$H/deployments-scaas-testnet-pqz.json"
echo "e2e.py rc $e"
exit $e
