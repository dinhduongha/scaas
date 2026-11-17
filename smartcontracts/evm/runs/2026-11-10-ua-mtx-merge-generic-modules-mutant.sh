#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# CTR-TOK-30 (owner 2026-11-10, every class's release module-checked): the mutant removes the generic path's
# `_checkModules` call in OpenFactory._newRelease; the two negative tests must fail on it. The source is put back on exit.
# Run inside one capped slot, so the mutant exists only while this job holds it:
#   scripts/capped smartcontracts/evm/runs/2026-11-10-ua-mtx-merge-generic-modules-mutant.sh
set -u
export PATH="$HOME/.foundry/bin:$PATH"
cd "$(dirname "$0")/.." || exit 2
F=src/factory/OpenFactory.sol
B=$(mktemp)
cp "$F" "$B"
trap 'cp "$B" "$F"; rm -f "$B"' EXIT
python3 -I - "$F" <<'P'
import sys
p = sys.argv[1]
s = open(p).read()
old = "        _checkModules(r.implementation, d, envVersion);\n"
assert s.count(old) == 1, "the call is not there once"
open(p, "w").write(s.replace(old, ""))
P
forge test --match-path '{test/v2/FactoryGenericKind.t.sol,test/pqchat/PqChat.t.sol}' \
  --match-test 'test_generic_modulesChecked|test_deployImplementation_moduleNotPinnedRefused'
rc=$?
echo "mutant: forge rc=$rc (1 = the negative tests failed: killed)"
[ "$rc" -eq 1 ]
