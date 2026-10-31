#!/usr/bin/env bash
# Verify every contract of one Deploy.s.sol broadcast on Blockscout (owner 2026-10-31, SCaaS testnet 7622).
# usage: verify-blockscout.sh [broadcast/Deploy.s.sol/<chainid>/run-latest.json]
#   env BLOCKSCOUT_API (default http://192.168.1.72:4000/api), FOUNDRY_PROFILE (default private7622)
# Run after every 7622 reset or deploy. Covers the CREATE / CREATE2 rows of the broadcast and the contracts they create
# (additionalContracts: MtxRelayExecutor, the SmartKeyAccount implementation, the token / DEX implementations); the
# constructor arguments are the tail of each init code after the artifact's creation bytecode. No --libraries: forge
# links the deployed bytecode after compiling, so its metadata has no libraries; the verifier matches the unlinked
# placeholders as library transformations (full match), while --libraries changes the metadata hash (partial match only).
# Skips verified addresses; prints one ok/fail row per contract;
# exit 1 on any fail. Blockscout learns the code of a CREATE2 / factory child only on demand (internal transactions are
# off), so each address is looked up first.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
B="${1:-broadcast/Deploy.s.sol/7622/run-latest.json}"
API="${BLOCKSCOUT_API:-http://192.168.1.72:4000/api}"
export FOUNDRY_PROFILE="${FOUNDRY_PROFILE:-private7622}"
CAPPED="$(git rev-parse --show-toplevel)/scripts/capped"
CHAIN="$(jq -r .chain "$B")"
fails=0; table=()

addr_field() { curl -s -m 10 "$API/v2/addresses/$1" | jq -r ".$2 // false"; }

while IFS=$'\t' read -r name addr init; do
  arts=(out/*/"$name".json)
  if [ ${#arts[@]} -ne 1 ] || [ ! -f "${arts[0]}" ]; then table+=("fail  $name  $addr  artifact: ${arts[*]}"); fails=$((fails + 1)); continue; fi
  art="${arts[0]}"
  for _ in 1 2 3 4 5; do [ "$(addr_field "$addr" is_contract)" = true ] && break; sleep 2; done
  if [ "$(addr_field "$addr" is_verified)" = true ]; then table+=("ok    $name  $addr  (already verified)"); continue; fi
  src="$(jq -r '.metadata.settings.compilationTarget | keys[0]' "$art")"
  code="$(jq -r .bytecode.object "$art")"
  args="0x${init:${#code}}"
  opt=(); [ "$args" != 0x ] && opt=(--constructor-args "$args")
  out="$("$CAPPED" forge verify-contract "$addr" "$src:$name" --verifier blockscout --verifier-url "$API/" \
         --chain-id "$CHAIN" "${opt[@]}" --watch 2>&1)"
  if [ "$(addr_field "$addr" is_verified)" = true ]; then table+=("ok    $name  $addr")
  else
    table+=("fail  $name  $addr  $(grep -E 'Details:|Error:' <<< "$out" | tail -1)"); fails=$((fails + 1))
  fi
done < <(jq -r '.transactions[]
  | (select(.transactionType | test("^CREATE")) | [.contractName, .contractAddress,
       (if .transaction.to then "0x" + .transaction.input[66:] else .transaction.input end)]),
    (.additionalContracts[]? | [.contractName, .address, .initCode])
  | @tsv' "$B")

printf '%s\n' "${table[@]}"
echo "$(( ${#table[@]} - fails )) ok, $fails fail (chain $CHAIN, $API)"
[ "$fails" -eq 0 ]
