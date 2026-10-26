#!/bin/sh
# ROLL_MAX scan, 8d2b fix round (review I1): both relay paths (mtxExecute, uaExecute with the ML-DSA-65 fee UA). Each set
# built with ROLL_MAX = 192 (its PqzSet.sol, uncommitted, restored). Sets as arguments (default: all four).
W=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$W"
[ $# -gt 0 ] || set -- n2048-kmax1024 n2304-kmax4096 n2560-kmax16384 n2816-kmax65536
for s in "$@"; do
  f=pqz-core/params/sets/$s/PqzSet.sol
  sed -i 's/uint256 internal constant ROLL_MAX = [0-9_]*;/uint256 internal constant ROLL_MAX = 192;/' $f
  L=smartcontracts/evm/runs/2026-10-26-t8d2b-fix-rollscan-$s.txt
  { echo "# t8d2b fix ROLL_MAX scan at $s, commit $(/usr/bin/git rev-parse --short HEAD)$(/usr/bin/git diff --quiet HEAD -- smartcontracts/evm/src smartcontracts/evm/test || echo ' + uncommitted test/src') + PqzSet.ROLL_MAX = 192 (uncommitted, restored), test/research/PqzPackGas.t.sol"
    scripts/capped smartcontracts/evm/script/pqz/at-set.sh $s test --match-path test/research/PqzPackGas.t.sol --match-test test_pack_scanRoll -vv; echo "rc $?"; } > $L 2>&1
  /usr/bin/git checkout -q HEAD -- $f
done
echo done
