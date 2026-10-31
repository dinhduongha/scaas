#!/usr/bin/env bash
# Verify every contract of forge broadcasts (Deploy.s.sol, the Zether e2e) and of the PQZ e2e runs on Blockscout (owner
# 2026-10-31, SCaaS testnet 7622).
# usage: verify-blockscout.sh [broadcast.json ...] [e2e-run-log ...]  (paths relative to smartcontracts/evm; an argument
#   ending in .json is a broadcast; default broadcast/Deploy.s.sol/7622/run-latest.json and, when present,
#   broadcast/ZetherE2E.s.sol/7622/run-latest.json)
#   env BLOCKSCOUT_API (default http://192.168.1.72:4000/api), RPC (default http://192.168.1.72:8545),
#   FOUNDRY_PROFILE (default scaas-testnet)
# Run after every 7622 reset or deploy. Broadcast: the CREATE / CREATE2 rows and the contracts they create
# (additionalContracts: MtxRelayExecutor, the SmartKeyAccount implementation, the token / DEX implementations); the
# constructor arguments are the tail of each init code after the artifact's creation bytecode. A child forge cannot
# name: an EIP-1167 clone (a factory token, `createToken`) is checked as below, an SSTORE2 data contract (code starting
# 0x00: the inner-product verifier's generators, registry records, memos) is listed as skip (data, nothing to verify).
# PQZ e2e (script/pqz/e2e.py, which writes only the last run's addresses to deployments/7622-pqz.json): its run logs,
# default every runs/*.txt whose "# P6g e2e on chain" header names this chain's genesis hash (older logs name a reset
# chain, whose addresses now hold other code). Per log line "      <Name> at 0x…": a direct CREATE from the deployer,
# constructor arguments = the input of the log's last "tx …: 0x…" line before it (the creation) after the artifact's
# bytecode; "<Name> release at 0x…": an
# OpenFactory release, arguments abi.encode(envVersion, env, implArgs) as OpenFactory._deploy appends them (implArgs
# empty, as e2e.py passes); "<sym> at 0x…" with no artifact (pqUSD, pqW): an EIP-1167 clone of a release: not verified
# itself, the row checks that Blockscout links it to its (verified) implementation (proxy_type eip1167).
# No --libraries: forge links the deployed bytecode after compiling, so its metadata has no libraries; the verifier
# matches the unlinked placeholders as library transformations (full match), while --libraries changes the metadata
# hash (partial match only).
# --skip-is-verified-check: forge's own check takes a contract Blockscout shows through a verified twin (same code,
# `verified_twin_address_hash`, e.g. a second e2e run's verifiers) for verified and skips it; the script checks
# `is_verified` itself.
# Skips verified addresses; prints one ok/fail row per contract; exit 1 on any fail. Blockscout learns the code of a
# CREATE2 / factory child only on demand (internal transactions are off), so each address is looked up first.
set -uo pipefail
case "${1:-}" in -h|--help) sed -n '2,8p' "${BASH_SOURCE[0]}"; exit 0;; esac
cd "$(dirname "${BASH_SOURCE[0]}")/.."
bs=()
while [ $# -gt 0 ] && [[ "$1" == *.json ]]; do bs+=("$1"); shift; done
if [ ${#bs[@]} -eq 0 ]; then
  bs=(broadcast/Deploy.s.sol/7622/run-latest.json)
  [ -f broadcast/ZetherE2E.s.sol/7622/run-latest.json ] && bs+=(broadcast/ZetherE2E.s.sol/7622/run-latest.json)
fi
for B in "${bs[@]}"; do [ -f "$B" ] || { echo "no broadcast $B" >&2; exit 2; }; done
B="${bs[0]}"
API="${BLOCKSCOUT_API:-http://192.168.1.72:4000/api}"
RPC="${RPC:-http://192.168.1.72:8545}"
export FOUNDRY_PROFILE="${FOUNDRY_PROFILE:-scaas-testnet}"
CAPPED="$(git rev-parse --show-toplevel)/scripts/capped"
CHAIN="$(jq -r .chain "$B")"
ENV_T='(address,bytes32,address,address,bool,address[],address[],bytes32[])'
fails=0; skips=0; table=(); seen=" "

# Gentle on the API (Blockscout's per-IP limit, 500 calls / 15 min by default, answers 429): curl retries a 429 with a
# back-off, one address call per check, a pause between contracts.
api() { curl -s -m 20 --retry 6 --retry-delay 15 "$API/v2/$1"; }
addr_field() { api "addresses/$1" | jq -r ".$2 // false"; }
known() { for _ in 1 2 3 4 5; do [ "$(addr_field "$1" is_contract)" = true ] && return; sleep 3; done; }

# verify <name> <address> <constructor args hex without 0x> [label]
verify() {
  local name=$1 addr=$2 args=$3 label=${4:-$1} arts art src out opt=()
  arts=(out/*/"$name".json)
  if [ ${#arts[@]} -ne 1 ] || [ ! -f "${arts[0]}" ]; then table+=("fail  $label  $addr  artifact: ${arts[*]}"); fails=$((fails + 1)); return; fi
  art="${arts[0]}"
  known "$addr"
  if [ "$(addr_field "$addr" is_verified)" = true ]; then table+=("ok    $label  $addr  (already verified)"); return; fi
  sleep 2
  src="$(jq -r '.metadata.settings.compilationTarget | keys[0]' "$art")"
  [ -n "$args" ] && opt=(--constructor-args "0x$args")
  out="$("$CAPPED" forge verify-contract "$addr" "$src:$name" --verifier blockscout --verifier-url "$API/" \
         --chain-id "$CHAIN" "${opt[@]}" --watch --delay 10 --skip-is-verified-check 2>&1)"
  if [ "$(addr_field "$addr" is_verified)" = true ]; then table+=("ok    $label  $addr")
  else
    table+=("fail  $label  $addr  $(grep -E 'Details:|Error:' <<< "$out" | tail -1)"); fails=$((fails + 1))
  fi
}

# clone <label> <address>: an EIP-1167 clone of a release is not verified itself; Blockscout must link it (proxy_type
# eip1167) to its implementation, which must be verified. A data contract (SSTORE2, code 0x00…) is a skip.
clone() {
  local name=$1 addr=$2 code impl j pt li iv
  code="$(cast code -r "$RPC" "$addr")"
  if [[ "$code" == 0x00* ]]; then table+=("skip  $name  $addr  SSTORE2 data contract ($(( (${#code} - 2) / 2 )) B), nothing to verify"); skips=$((skips + 1)); return; fi
  if [[ "$code" != 0x363d3d373d3d3d363d73* ]]; then table+=("fail  $name  $addr  no artifact, not an EIP-1167 clone"); fails=$((fails + 1)); return; fi
  impl="0x${code:22:40}"
  known "$addr"
  if [ "$(addr_field "$addr" is_contract)" != true ]; then
    # Blockscout 9.0.2 may never fetch a factory clone's code (internal transactions off; its on-demand ContractCode
    # fetch returned nothing for the Zether e2e clones, 2026-10-31): a verification request for the clone, against its
    # implementation's source, makes it fetch the code; the request itself fails (a 45-byte proxy), as expected
    local in art
    in="$(api "smart-contracts/$impl" | jq -r '.name // empty')"
    art="$(ls out/*/"$in".json 2>/dev/null | head -1)"
    if [ -n "$in" ] && [ -n "$art" ]; then
      "$CAPPED" forge verify-contract "$addr" "$(jq -r '.metadata.settings.compilationTarget | keys[0]' "$art"):$in" \
        --verifier blockscout --verifier-url "$API/" --chain-id "$CHAIN" --skip-is-verified-check >/dev/null 2>&1
      known "$addr"
    fi
  fi
  j="$(api "smart-contracts/$addr")"   # also makes Blockscout (re)fetch the proxy's implementation
  pt="$(jq -r '.proxy_type // "none"' <<< "$j")"
  li="$(jq -r '[.implementations[]?.address_hash | ascii_downcase] | join(",")' <<< "$j")"
  iv="$(addr_field "$impl" is_verified)"
  if [ "$pt" = eip1167 ] && [ "$li" = "$impl" ] && [ "$iv" = true ]; then
    table+=("ok    $name  $addr  eip1167 clone of $impl (verified)")
  else
    table+=("fail  $name  $addr  clone of $impl: proxy_type $pt, implementations [$li], implementation verified $iv"); fails=$((fails + 1))
  fi
}

# init code minus the artifact's creation bytecode (linked library addresses have the placeholders' length)
ctor_tail() { local code; code="$(jq -r .bytecode.object out/*/"$1".json)"; echo "${2:${#code}}"; }

for B in "${bs[@]}"; do
  while IFS=$'\t' read -r name addr init; do
    [[ "$seen" == *" ${addr,,} "* ]] && continue; seen+="${addr,,} "
    if [ "$name" = - ]; then clone "child of $(jq -r --arg a "${addr,,}" '.transactions[] | select([.additionalContracts[]?.address | ascii_downcase] | index($a)) | .function // .contractName' "$B" | head -1)" "$addr"
    else verify "$name" "$addr" "$(ctor_tail "$name" "$init")"; fi
  done < <(jq -r '.transactions[]
    | (select(.transactionType | test("^CREATE")) | [.contractName, .contractAddress,
         (if .transaction.to then "0x" + .transaction.input[66:] else .transaction.input end)]),
      (.additionalContracts[]? | [.contractName // "-", .address, .initCode])
    | @tsv' "$B")
done

# ---- PQZ e2e runs
logs=("$@")
if [ ${#logs[@]} -eq 0 ]; then
  g="$(cast block 0 -r "$RPC" -f hash)"
  mapfile -t logs < <(grep -l "^# P6g e2e on chain $CHAIN, .*genesis $g" runs/*.txt)
fi
for log in "${logs[@]}"; do
  fac=""
  while read -r name rel addr tx; do
    addr="${addr,,}"
    [ "$name" = OpenFactory ] && fac="$addr"
    [[ "$seen" == *" $addr "* ]] && continue; seen+="$addr "
    if [ "$rel" = release ]; then    # an OpenFactory release: find its (kind, version), rebuild the appended arguments
      kind="$(cast call -r "$RPC" "$addr" 'kind()(uint8)')"; v=0; ev=""
      for ((i = $(cast call -r "$RPC" "$fac" 'latestVersion(uint8)(uint64)' "$kind"); i > 0; i--)); do
        [ "$(cast call -r "$RPC" "$fac" 'implementationOf(uint8,uint64)(address)' "$kind" "$i" | tr A-F a-f)" = "$addr" ] && v=$i && break
      done
      [ "$v" -gt 0 ] && ev="$(cast call -r "$RPC" "$fac" 'releaseOf(uint8,uint64)((address,uint16,bytes32,uint64,bool))' "$kind" "$v" \
                              | sed -E 's/^\([^,]+, ([0-9]+),.*/\1/')"
      if [ -z "$ev" ]; then table+=("fail  $name  $addr  not a release of factory $fac"); fails=$((fails + 1)); continue; fi
      env="$(cast call -r "$RPC" "$fac" "envOf(uint8,uint16)($ENV_T)" "$kind" "$ev")"
      args="$(cast abi-encode "f(uint16,$ENV_T,bytes)" "$ev" "$env" 0x)"
      verify "$name" "$addr" "${args#0x}" "$name (release kind $kind v$v)"
    elif ls out/*/"$name".json >/dev/null 2>&1; then    # a direct CREATE from the e2e deployer
      verify "$name" "$addr" "$(ctor_tail "$name" "$(cast tx -r "$RPC" "$tx" input)")"
    else                                                 # a token: EIP-1167 clone of a release
      clone "$name" "$addr"
    fi
  done < <(awk '/^(ok|FAIL) +tx .*: 0x[0-9a-f]{64}/ { match($0, /: 0x[0-9a-f]{64}/); tx = substr($0, RSTART + 2, 66) }
                $0 ~ /^      [A-Za-z0-9_]+ (release )?at 0x[0-9a-fA-F]{40}/ { print $1, ($2 == "release" ? "release" : "-"), ($2 == "release" ? $4 : $3), tx }' "$log")
done

[ ${#table[@]} -gt 0 ] || { echo "nothing to verify: empty result table (chain $CHAIN)" >&2; exit 1; }
printf '%s\n' "${table[@]}"
echo "$(( ${#table[@]} - fails - skips )) ok, $skips skip, $fails fail (chain $CHAIN, $API)"
[ "$fails" -eq 0 ]
