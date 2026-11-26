#!/bin/bash
# Feed S3's vectors to S2's Solidity verifier without touching any worktree:
# snapshot smartcontracts/ from branch r3-zether-contracts into a temp dir, copy the forge libs
# (S2_LIB, default this checkout's smartcontracts/evm/lib: links into vendor/ after scripts/vendor.sh install), add
# tools/S3Vectors.t.sol, run forge.
#   [S2_LIB=<a smartcontracts/evm/lib>] tools/s2_forge_check.sh
# Works on branches from before and after the family re-layout (smartcontracts/ vs smartcontracts/evm/).
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(/usr/bin/git -C "$HERE" rev-parse --show-toplevel)"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
/usr/bin/git -C "$REPO" archive "${S2_BRANCH:-r3-zether-contracts}" smartcontracts | tar -x -C "$OUT"
SC="$OUT/smartcontracts"
[ -f "$SC/evm/foundry.toml" ] && SC="$SC/evm"
cp -rL "${S2_LIB:-$REPO/smartcontracts/evm/lib}" "$SC/lib" # -L: the files the links name
mkdir -p "$SC/test/vectors/zether/s3"
cp "$HERE"/vectors/*.json "$SC/test/vectors/zether/s3/"
cp "$HERE/tools/S3Vectors.t.sol" "$SC/test/zether/"
cd "$SC"
forge test --match-contract S3VectorsTest --evm-version prague -vv
