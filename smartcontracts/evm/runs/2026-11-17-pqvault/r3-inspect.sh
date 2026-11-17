#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# PqVault plan R3 step 1 / step 3 (3): PqChat's ABI evidence on the current tree, into runs/2026-11-17-pqvault/<dir>/ (git-ignored
# where large): `forge inspect` abi, methodIdentifiers and storageLayout of PqChat and PqChatTopics, and
# type(IPqChat).interfaceId as the XOR of IPqChat's selectors (what solc computes). From smartcontracts/evm:
#   sh runs/2026-11-17-pqvault/r3-inspect.sh r3-before | r3-after
# Compare: diff -r runs/2026-11-17-pqvault/r3-before/inspect runs/2026-11-17-pqvault/r3-after/inspect
set -eu
D=runs/2026-11-17-pqvault/$1/inspect
mkdir -p "$D"
C=../../scripts/capped
export FOUNDRY_OUT=out/t66a-test-pqchat FOUNDRY_CACHE_PATH=cache/t66a-test-pqchat FOUNDRY_TEST=test/pqchat FOUNDRY_SCRIPT=test/pqchat
for c in PqChat PqChatTopics; do
  for f in abi methodIdentifiers storageLayout; do
    "$C" ~/.foundry/bin/forge inspect "$c" "$f" --json > "$D/$c.$f.json"
  done
done
"$C" ~/.foundry/bin/forge inspect IPqChat methodIdentifiers --json > "$D/IPqChat.methodIdentifiers.json"
python3 -c "
import json, functools, sys
m = json.load(open(sys.argv[1]))
print('0x%08x' % functools.reduce(lambda a, b: a ^ b, (int(v, 16) for v in m.values()), 0))" "$D/IPqChat.methodIdentifiers.json" > "$D/IPqChat.interfaceId.txt"
cat "$D/IPqChat.interfaceId.txt"
