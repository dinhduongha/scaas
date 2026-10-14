#!/bin/sh
# forge test of the Solidity Ligero verifier only (fixtures from runs/evm.sh); run alone:
#   scripts/capped pqz-core/pqzh/ligero/runs/forge.sh <tag> [extra forge args]
cd "$(dirname "$0")/../../../../smartcontracts/evm"
tag=$1
shift
FOUNDRY_CODE_SIZE_LIMIT=65536 /usr/bin/time -v forge test --match-path 'test/pqzh/ligero/*' -vv --gas-limit 9000000000000000000 "$@" \
  > ../../pqz-core/pqzh/ligero/runs/$tag-forge.txt 2>&1
echo forge rc=$?
