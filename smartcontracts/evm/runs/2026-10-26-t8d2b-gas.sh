#!/bin/sh
# t8d2b gas logs (plan 5h Task 8d part 2b): PqzStateGas.t.sol (ROLL_MAX / prepare pins, the per-op tests, the gas table)
# at the four sets, one at a time (at-set.sh edits src/pqz/PqzSet.sol). Run from the work tree root.
W=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$W"
for s in n2048-kmax1024 n2304-kmax4096 n2560-kmax16384 n2816-kmax65536; do
  L=smartcontracts/evm/runs/2026-10-26-t8d2b-gas-$s.txt
  { echo "# t8d2b gas at $s, commit $(/usr/bin/git rev-parse --short HEAD)$(/usr/bin/git diff --quiet HEAD -- smartcontracts/evm/src smartcontracts/evm/test pqz-core/params/sets || echo ' + uncommitted')"
    CAPPED_SLOTS=4 CAPPED_MEM=3G scripts/capped smartcontracts/evm/script/pqz/at-set.sh $s test --match-path test/pqz/PqzStateGas.t.sol -vv; echo "rc $?"; } > $L 2>&1
done
echo done
