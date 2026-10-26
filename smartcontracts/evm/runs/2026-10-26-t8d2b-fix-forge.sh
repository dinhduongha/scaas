#!/bin/sh
# t8d2b fix round: the full forge suite at the four sets (at-set.sh, one at a time), then the size gate at the committed
# set. The v2 artefact tests read FOUNDRY_OUT since the fix round (review m10c), so no plain `forge build` is needed first.
W=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$W"
for s in n2048-kmax1024 n2304-kmax4096 n2560-kmax16384 n2816-kmax65536; do
  L=smartcontracts/evm/runs/2026-10-26-t8d2b-fix-forge-$s.txt
  { echo "# t8d2b fix forge test at $s, commit $(/usr/bin/git rev-parse --short HEAD)$(/usr/bin/git diff --quiet HEAD -- smartcontracts/evm/src smartcontracts/evm/test pqz-core/params/sets || echo ' + uncommitted')"
    scripts/capped smartcontracts/evm/script/pqz/at-set.sh $s test; echo "rc=$?"; } > $L 2>&1
done
L=smartcontracts/evm/runs/2026-10-26-t8d2b-fix-sizes.txt
{ echo "# t8d2b fix size gate at the committed set (n2304-kmax4096), commit $(/usr/bin/git rev-parse --short HEAD)"
  cd smartcontracts/evm
  ../../scripts/capped forge build src --sizes --json > "${TMPDIR:-/tmp}/t8d2b-fix-sizes.json" 2>/dev/null
  python3 -I ../../scripts/size_gate.py "${TMPDIR:-/tmp}/t8d2b-fix-sizes.json" size-baseline.json; echo "rc=$?"; } > $L 2>&1
echo done
