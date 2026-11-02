#!/bin/bash
# usage (from <variant>/smartcontracts/evm): sizes.sh  - runtime / init of the registry and its libraries, from the artifacts
for c in UARegistry UAViewLib UARegisterLib; do
  f=out/$c.sol/$c.json; [ -f "$f" ] || continue
  jq -r --arg c "$c" '[$c, (.deployedBytecode.object|length/2-1), (.bytecode.object|length/2-1), (.deployedBytecode.linkReferences|[.[]|keys[]]|join(","))]|@tsv' "$f"
done
