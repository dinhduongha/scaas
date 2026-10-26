#!/bin/sh
# t8d2b: the full forge suite at the four sets (at-set.sh, one at a time), then the size gate at the committed set.
W=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$W"
for s in n2048-kmax1024 n2304-kmax4096 n2560-kmax16384 n2816-kmax65536; do
  L=smartcontracts/evm/runs/2026-10-26-t8d2b-forge-$s.txt
  { echo "# t8d2b forge test at $s, commit $(/usr/bin/git rev-parse --short HEAD)"
    CAPPED_SLOTS=4 CAPPED_MEM=3G scripts/capped smartcontracts/evm/script/pqz/at-set.sh $s test; echo "rc=$?"; } > $L 2>&1
done
L=smartcontracts/evm/runs/2026-10-26-t8d2b-sizes.txt
{ echo "# t8d2b size gate at the committed set (n2304-kmax4096), commit $(/usr/bin/git rev-parse --short HEAD)"
  cd smartcontracts/evm
  CAPPED_SLOTS=4 CAPPED_MEM=3G ../../scripts/capped forge build src --sizes --json > "${TMPDIR:-/tmp}/t8d2b-sizes.json" 2>/dev/null
  python3 -I ../../scripts/size_gate.py "${TMPDIR:-/tmp}/t8d2b-sizes.json" size-baseline.json; echo "rc=$?"; } > $L 2>&1
echo done
