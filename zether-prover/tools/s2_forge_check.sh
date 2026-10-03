#!/bin/bash
# Feed S3's vectors to S2's Solidity verifier without touching any worktree:
# snapshot smartcontracts/ from branch r3-zether-contracts into a temp dir, borrow forge libs
# from a checkout that has them (S2_LIB), add tools/S3Vectors.t.sol, run forge.
#   S2_LIB=/path/to/smartcontracts/lib tools/s2_forge_check.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$(/usr/bin/git -C "$HERE" rev-parse --show-toplevel)"
OUT="$(mktemp -d)"
trap 'rm -rf "$OUT"' EXIT
/usr/bin/git -C "$REPO" archive "${S2_BRANCH:-r3-zether-contracts}" smartcontracts | tar -x -C "$OUT"
cp -r "${S2_LIB:?set S2_LIB to a smartcontracts/lib with forge-std}" "$OUT/smartcontracts/lib"
mkdir -p "$OUT/smartcontracts/test/vectors/zether/s3"
cp "$HERE"/vectors/*.json "$OUT/smartcontracts/test/vectors/zether/s3/"
cp "$HERE/tools/S3Vectors.t.sol" "$OUT/smartcontracts/test/zether/"
cd "$OUT/smartcontracts"
forge test --match-contract S3VectorsTest --evm-version prague -vv
