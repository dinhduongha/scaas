#!/bin/bash
# Feed S3's vectors to S2's Solidity verifier without touching any worktree:
# snapshot smartcontracts/ from branch r3-zether-contracts into a temp dir, borrow forge libs
# from a checkout that has them (S2_LIB), add tools/S3Vectors.t.sol, run forge.
#   S2_LIB=/path/to/smartcontracts/evm/lib tools/s2_forge_check.sh
# Works on branches from before and after the family re-layout (smartcontracts/ vs smartcontracts/evm/).
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(/usr/bin/git -C "$HERE" rev-parse --show-toplevel)"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
/usr/bin/git -C "$REPO" archive "${S2_BRANCH:-r3-zether-contracts}" smartcontracts | tar -x -C "$OUT"
SC="$OUT/smartcontracts"; [ -f "$SC/evm/foundry.toml" ] && SC="$SC/evm"
cp -r "${S2_LIB:?set S2_LIB to a smartcontracts/evm/lib with forge-std}" "$SC/lib"
mkdir -p "$SC/test/vectors/zether/s3"
cp "$HERE"/vectors/*.json "$SC/test/vectors/zether/s3/"
cp "$HERE/tools/S3Vectors.t.sol" "$SC/test/zether/"
cd "$SC"
forge test --match-contract S3VectorsTest --evm-version prague -vv
