#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# SCaaS testnet reset 1 (2026-11-04, CTR-UA-39): `mldsa87` (0x0134) on the deploy JSON's UA registry line, per the RUNBOOK's
# `MLDSA87` section: the gen-1 registry of `deploy.sh` has no 0x0134 because `DeployBase._mldsa87Precompile` probes in
# forge's own EVM, which has no MLDSA87 (the RUNBOOK and DeployBase's note: outside `forge script`, P6g D15). So:
#   1. UAMldsaVerifier(0x0134, 0x…5caa0014, probe valid, probe invalid) by `forge create` (the node runs the constructor's probe;
#      the inputs are pq_kat.json's mldsa87 EIP-8355 probe pair, as DeployBase reads them)
#   2. a gen-2 UARegistry: predecessor = the JSON's `ua_registry`, its chainUid, Hedera false, verify budget 12,000,000, the
#      JSON's SmartKeyAccount implementation, no msig, kinds [(0x0134, verifier, 250,000)] (DeployBase.CAP_MLDSA87, the
#      PROVISIONAL precompile-path cap until T-GAS), linked to the JSON's `ua_registry_lib`
#   3. checks: generation, predecessor, kindEnabled(0x0134) / verifyCap on gen 2, the verifier's PRECOMPILE; the gas of
#      UAMldsaVerifier.verify on the KAT signature (eth_estimateGas, for T-GAS's record); gen 1 enables 0x0135 (fndsa1024)
#   4. registrations from smartcontracts/vectors/ua/portable.json (portable PoPs, any chain): `mldsa87` on gen 2,
#      `fndsa1024` on gen 1; then registrationOf / checkedOf
# Writes deployments/7622-mldsa87.json (git-ignored; the run log keeps the addresses).
#   PRIVATE_KEY=<the registrar, test key 0x…04> [RPC=…] [J=deployments/7622.json] runs/2026-11-04-mldsa87-gen2-7622.sh
set -euo pipefail
cd "$(dirname "$0")/.."
RPC=${RPC:-http://127.0.0.1:8545}
J=${J:-deployments/7622.json}
: "${PRIVATE_KEY:?}"
export FOUNDRY_PROFILE=${FOUNDRY_PROFILE:-scaas-testnet}
ML87=0x000000000000000000000000000000005caA0014
KAT=../vectors/ua/pq_kat.json; PORT=../vectors/ua/portable.json
REG1=$(jq -r .ua_registry "$J"); LIB=$(jq -r .ua_registry_lib "$J"); SKA=$(jq -r .smart_key_account_implementation "$J")
UID_=$(jq -r .chain_uid "$J")
echo "gen-1 registry $REG1 (lib $LIB), chainUid $UID_, SmartKeyAccount implementation $SKA"
for k in 0x0134 0x0135; do echo "gen 1 kindEnabled($k) = $(cast call "$REG1" 'kindEnabled(uint16)(bool)' $k --rpc-url "$RPC"), cap $(cast call "$REG1" 'verifyCap(uint16)(uint64)' $k --rpc-url "$RPC")"; done
V=$(jq -r .kinds.mldsa87.eip8355_probe_valid "$KAT"); I=$(jq -r .kinds.mldsa87.eip8355_probe_invalid "$KAT")
echo "## 1. UAMldsaVerifier(0x0134, $ML87, probe valid ${#V} hex chars, probe invalid ${#I})"
VER=$(forge create src/ua/MlDsa.sol:UAMldsaVerifier --rpc-url "$RPC" --private-key "$PRIVATE_KEY" --broadcast --json \
  --constructor-args 308 "$ML87" "$V" "$I" | tee -a /dev/stderr | jq -r .deployedTo)
echo "UAMldsaVerifier at $VER: KIND $(cast call "$VER" 'KIND()(uint16)' --rpc-url "$RPC") PRECOMPILE $(cast call "$VER" 'PRECOMPILE()(address)' --rpc-url "$RPC")"
echo "## 2. UARegistry gen 2"
REG2=$(forge create src/ua/UARegistry.sol:UARegistry --rpc-url "$RPC" --private-key "$PRIVATE_KEY" --broadcast --json \
  --libraries "src/ua/UARegistryLib.sol:UARegistryLib:$LIB" \
  --constructor-args "$UID_" "$REG1" false 12000000 "$SKA" false "[(308,$VER,250000)]" | tee -a /dev/stderr | jq -r .deployedTo)
echo "## 3. checks"
echo "gen 2 $REG2: generation $(cast call "$REG2" 'generation()(uint8)' --rpc-url "$RPC") predecessor $(cast call "$REG2" 'predecessor()(address)' --rpc-url "$RPC") chainUid $(cast call "$REG2" 'chainUid()(bytes32)' --rpc-url "$RPC")"
echo "gen 2 kindEnabled(0x0134) = $(cast call "$REG2" 'kindEnabled(uint16)(bool)' 0x0134 --rpc-url "$RPC"), verifyCap $(cast call "$REG2" 'verifyCap(uint16)(uint64)' 0x0134 --rpc-url "$RPC")"
python3 -I - "$PORT" > /tmp/ml87-pop-$$.txt <<'PY2'
import json, sys
r = next(x for x in json.load(open(sys.argv[1]))["registrations"] if x["name"] == "mldsa87")
print(r["keyData"]); print(r["popMessage"]); print(r["pop"])
PY2
PK=$(sed -n 1p /tmp/ml87-pop-$$.txt); MS=$(sed -n 2p /tmp/ml87-pop-$$.txt); SG=$(sed -n 3p /tmp/ml87-pop-$$.txt); rm -f /tmp/ml87-pop-$$.txt
echo "UAMldsaVerifier.verify on portable.json's mldsa87 PoP (keyData, popMessage, pop): $(cast call "$VER" 'verify(bytes,bytes32,bytes)(bool)' "$PK" "$MS" "$SG" --rpc-url "$RPC"), eth_estimateGas $(cast estimate "$VER" 'verify(bytes,bytes32,bytes)' "$PK" "$MS" "$SG" --rpc-url "$RPC") (a whole transaction: intrinsic + calldata + the call)"
echo "## 4. registrations (portable.json)"
reg() {  # <registry> <vector name>
  python3 -I - "$PORT" "$2" > /tmp/reg-$$.txt <<'PY'
import json, sys
r = next(x for x in json.load(open(sys.argv[1]))["registrations"] if x["name"] == sys.argv[2])
a = r["args"]; t = a["attrs"]; k = t["kem"]
print(a["kind"]); print(a["keyData"]); print(f"({t['pqzKey']},{t['pqzPopHash']},({k['scheme']},{k['mlkemEk']},{k['x25519']}),{t['kemPkHash']})")
print(a["pop"]); print(a["pqzPop"]); print(r["ua"])
PY
  local K KD AT PO PP UA; { read -r K; read -r KD; read -r AT; read -r PO; read -r PP; read -r UA; } < /tmp/reg-$$.txt; rm -f /tmp/reg-$$.txt
  echo "$2 (kind $K) ua $UA on $1: uaOf = $(cast call "$1" 'uaOf(uint16,bytes)(bytes32)' "$K" "$KD" --rpc-url "$RPC")"
  cast send "$1" 'register(uint16,bytes,(bytes,bytes32,(uint8,bytes,bytes32),bytes32),bytes,bytes)' "$K" "$KD" "$AT" "$PO" "$PP" \
    --private-key "$PRIVATE_KEY" --rpc-url "$RPC" --json | jq -r '"  register: tx \(.transactionHash) status \(.status) block \(.blockNumber) gasUsed \(.gasUsed)"'
  echo "  checkedOf (pop, pqzPop, kem) = $(cast call "$1" 'checkedOf(bytes32)(uint8,uint8,uint8)' "$UA" --rpc-url "$RPC" | tr '\n' ' ')"
  echo "  registrationOf kind = $(cast call "$1" 'registrationOf(bytes32)' "$UA" --rpc-url "$RPC" | cut -c1-66)"
}
reg "$REG2" mldsa87
reg "$REG1" fndsa1024
jq -n --arg v "$VER" --arg r "$REG2" --arg p "$REG1" --arg u "$UID_" \
  '{chain_uid: $u, ua_registry_gen1: $p, ua_registry_mldsa87: $r, mldsa87_verifier: $v, mldsa87_cap: 250000}' > deployments/7622-mldsa87.json
cat deployments/7622-mldsa87.json
