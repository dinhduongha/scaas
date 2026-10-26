#!/bin/sh
# ROLL_MAX scan (plan 5h Task 8d part 2b): each set built with ROLL_MAX = 192 (its PqzSet.sol, uncommitted, restored).
W=/home/ha/work/ainative/scaas/.claude/worktrees/pqz-8d2b
cd $W
for s in n2048-kmax1024 n2304-kmax4096 n2560-kmax16384 n2816-kmax65536; do
  f=pqz-core/params/sets/$s/PqzSet.sol
  sed -i 's/uint256 internal constant ROLL_MAX = [0-9_]*;/uint256 internal constant ROLL_MAX = 192;/' $f
  L=smartcontracts/evm/runs/2026-10-26-t8d2b-rollscan-$s.txt
  { echo "# t8d2b ROLL_MAX scan at $s, commit $(/usr/bin/git rev-parse --short HEAD) + PqzSet.ROLL_MAX = 192 (uncommitted, restored), test/research/PqzPackGas.t.sol"; 
    CAPPED_SLOTS=4 CAPPED_MEM=3G scripts/capped smartcontracts/evm/script/pqz/at-set.sh $s test --match-path test/research/PqzPackGas.t.sol --match-test test_pack_scanRoll -vv; echo "rc $?"; } > $L 2>&1
  /usr/bin/git checkout -q HEAD -- $f
done
echo done
