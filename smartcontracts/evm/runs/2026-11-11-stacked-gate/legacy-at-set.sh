#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# The modules differential at another PQZ set needs its pre-split side at that set too: test/modules reads the
# pre-split releases of d142b57c from out/t66b-legacy/, which script/modules/legacy_artifacts.py builds at the default
# set; a set-sized answer (pqzAcc: the account's ciphertext) then differs by the set alone. This exports d142b57c's
# src once per set into the git-ignored scratchpad/t66b-pre-<set>, puts in that commit's own PqzSet.sol of the set,
# builds it (scripts/capped), and writes out/t66b-legacy/ from it (legacy_artifacts.py json). `default` writes it back
# from legacy_artifacts.py's own default-set build (scratchpad/t66b-pre). From the repository root:
#   sh smartcontracts/evm/runs/2026-11-11-stacked-gate/legacy-at-set.sh <set> | default
set -eu
S=${1:?set or default}
ROOT=$(cd "$(dirname "$0")/../../../.." && pwd)
EVM=$ROOT/smartcontracts/evm
PRE=d142b57c
if [ "$S" = default ]; then
  P=$ROOT/scratchpad/t66b-pre
else
  P=$ROOT/scratchpad/t66b-pre-$S
  if [ ! -d "$P/smartcontracts/evm/out" ]; then
    rm -rf "$P" && mkdir -p "$P"
    git -C "$ROOT" archive --format=tar "$PRE" smartcontracts/evm/src smartcontracts/evm/foundry.toml | tar -x -C "$P"
    git -C "$ROOT" show "$PRE:pqz-core/params/sets/$S/PqzSet.sol" > "$P/smartcontracts/evm/src/pqz/PqzSet.sol"
    cp -al "$EVM/lib" "$P/smartcontracts/evm/lib"
    (cd "$P/smartcontracts/evm" && "$ROOT/scripts/capped" "$HOME/.foundry/bin/forge" build src > /dev/null)
  fi
fi
grep -q "NAME = \"$([ "$S" = default ] && echo n2304-kmax4096 || echo "$S")\"" "$P/smartcontracts/evm/src/pqz/PqzSet.sol" ||
  { echo "legacy-at-set.sh: $P is not at set $S"; exit 1; }
(cd "$EVM" && python3 script/modules/legacy_artifacts.py json "$P/smartcontracts/evm/out")
echo "out/t66b-legacy: d142b57c at $S"
