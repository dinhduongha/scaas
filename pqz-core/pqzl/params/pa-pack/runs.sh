#!/bin/sh
# Spike PACK: every forge run behind results-pack.md, from the worktree root (forge 1.8.5). Each job takes a
# `scripts/capped` slot (they queue). W = a scratch work dir (never committed), L = smartcontracts/evm/lib.
#   sh pqz-core/pqzl/params/pa-pack/runs.sh <scratch dir> [scan|confirm|func|all]
set -eu
W=$1 WHAT=${2:-all}
P=pqz-core/pqzl/params/pa-pack L=smartcontracts/evm/lib
SCAN_C='PqzPackGasTest|PqzPackRoundTripTest|PqzPackMicroTest'
SCAN_T='test_pack_|test_gas_prepareAcc_half._relayedFullTx|test_roundTrip|test_micro'
PINS='PqzStatePinGasTest|PqzStateTrivialRollGasTest|PqzPackGasTest|PqzPackRoundTripTest'
run() { # <log> <env> <args...>
  log=$1 envs=$2; shift 2
  echo "\$ $envs scripts/capped $*" | sed "s|$W|<scratch>|g" > "$P/$log"
  env $envs scripts/capped "$@" >> "$P/$log" 2>&1 || echo "  (exit $? — see $log)"
}
if [ "$WHAT" = scan ] || [ "$WHAT" = all ]; then
  run gas-a64-r128.txt "" $P/gasa.sh $W/w64 $L 128 --match-contract "$SCAN_C" --match-test "$SCAN_T" -vv
  run gas-a46-r128.txt PACK=46 $P/gasa.sh $W/w46 $L 128 --match-contract "$SCAN_C" --match-test "$SCAN_T" -vv
  run gas-a51-r256.txt PACK=51 $P/gasa.sh $W/w51 $L 256 --match-contract "$SCAN_C" --match-test "$SCAN_T" -vv
  # the two earlier P46 loops (logs kept: naive spread, unrolled spread; both without the rollover accumulator)
  run gas-a46v1-r128.txt PACK=46v1 $P/gasa.sh $W/w46v1 $L 128 --match-contract "$SCAN_C" --match-test "$SCAN_T" -vv
  run gas-a46v2-r128.txt PACK=46v2 $P/gasa.sh $W/w46v2 $L 128 --match-contract "$SCAN_C" --match-test "$SCAN_T" -vv
fi
if [ "$WHAT" = confirm ] || [ "$WHAT" = all ]; then
  run gas-a64-r96.txt "" $P/gasa.sh $W/w64 $L 96 --match-contract "$PINS" -vv
  run gas-a46-r80.txt PACK=46 $P/gasa.sh $W/w46 $L 80 --match-contract "$PINS" -vv
  run gas-a51-r144.txt PACK=51 $P/gasa.sh $W/w51 $L 144 --match-contract "$PINS" -vv
fi
if [ "$WHAT" = func ] || [ "$WHAT" = all ]; then
  # differential check: the functional PQZ suites at set (a), 64-bit lanes vs each packed layout (the fixture's
  # statement vectors are n = 2048, so some tests fail at set (a) in every tree; compare the lists). The committed
  # func logs had every line over 400 characters (assertion hex) cut to 300 characters plus a note.
  for t in 64 46 51; do
    run func-a$t.txt "" sh -c "cd $W/w$t/evm && forge test --match-path 'test/pqz/*' --no-match-contract 'GasTest|InvariantTest'"
  done
fi
