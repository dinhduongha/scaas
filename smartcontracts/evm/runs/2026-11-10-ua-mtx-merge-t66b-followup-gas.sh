#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# T66b follow-up, fix 2 (NET-EVM-11): the full deploy (smartcontracts/scripts/deploy.sh evm, Step 5's flags) on a local
# anvil with a 60 M block gas limit, then the gas limits forge sent. One scripts/capped job; anvil is stopped on exit.
#   PRIVATE_KEY=<anvil's dev account 0> scripts/capped smartcontracts/evm/runs/2026-11-10-ua-mtx-merge-t66b-followup-gas.sh
# DEPLOY_SH (default ../scripts/deploy.sh) names another deploy.sh, e.g. the one before the fix
# (`git show cd48e32b:smartcontracts/scripts/deploy.sh` written beside it), for the red run.
set -u
export PATH="$HOME/.foundry/bin:$PATH"
cd "$(dirname "$0")/.." || exit 2
: "${PRIVATE_KEY:?the anvil dev account 0}"
PORT=31993 RPC=http://127.0.0.1:31993 LIMIT=${LIMIT:-60000000} DEPLOY_SH=${DEPLOY_SH:-../scripts/deploy.sh}
anvil --chain-id $PORT --hardfork amsterdam --gas-limit "$LIMIT" --code-size-limit 131072 --port $PORT --silent & A=$!
trap 'kill $A 2>/dev/null; wait $A 2>/dev/null' EXIT
for _ in $(seq 50); do cast chain-id --rpc-url $RPC >/dev/null 2>&1 && break; sleep 0.2; done
echo "anvil: chain $(cast chain-id --rpc-url $RPC), block gas limit $(cast block latest --field gasLimit --rpc-url $RPC)"
export PRIVATE_KEY FOUNDRY_PROFILE=scaas-testnet DEPLOY_WRAPPED=1 DEPLOY_REGULATED=1 DEPLOY_ZETHER=1 NOTICE_PERIOD=0
export COMPLIANCE_ADMIN=0x4e59b44847b379578588920ca78fbf26c0b4956c DEMO_SUPPLY=1000000000000
export DEMO_HOLDER=0x6813Eb9362372EEF6200f3b1dbC3f819671cBA69 RELEASE_GAS_GATE=public
export RELEASES_JSON=deployments/$PORT-releases.json RELEASES_WRITE=true
rm -rf broadcast/Deploy.s.sol/$PORT broadcast/DeploySend.s.sol/$PORT deployments/$PORT.json "$RELEASES_JSON"
bash "$DEPLOY_SH" evm $RPC; rc=$?
echo "deploy.sh rc=$rc; blocks mined $(cast block-number --rpc-url $RPC)"
for f in broadcast/Deploy.s.sol/$PORT/run-latest.json broadcast/DeploySend.s.sol/$PORT/run-latest.json; do
  [ -f "$f" ] || continue
  python3 -I - "$f" <<'P'
import json, sys
j = json.load(open(sys.argv[1]))
t, r = j["transactions"], j.get("receipts", [])
print(f"{sys.argv[1]}: {len(t)} transactions, {len(r)} receipts, isFixedGasLimit {sorted(set(x['isFixedGasLimit'] for x in t))}")
g = [int(x["transaction"]["gas"], 16) for x in t]
print(f"  largest gas limit {max(g):,} (tx {g.index(max(g))}), sum {sum(g):,}")
if r:
    u = [int(x["gasUsed"], 16) for x in r]
    print(f"  status {sorted(set(x['status'] for x in r))}, gasUsed largest {max(u):,}, sum {sum(u):,}")
P
done
exit $rc
