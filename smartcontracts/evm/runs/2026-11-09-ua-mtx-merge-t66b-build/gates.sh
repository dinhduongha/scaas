#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Plan T66b build (spec 2026-11-09-t66b-library-organisation.md §12) gate steps, one at a time, from the repository root:
#   sh smartcontracts/evm/runs/2026-11-09-ua-mtx-merge-t66b-build/gates.sh <step> [<step> ...]
# Each step logs to smartcontracts/evm/runs/2026-11-09-ua-mtx-merge-t66b-<LABEL>-<step>.log (git-ignored) and ends it with
# `rc=<n>`; a step whose log ends with `rc=0` is skipped (RERUN=1 runs it again). LABEL (default `b`) names the task run.
# Heavy commands go through scripts/capped, foreground. The committed summary is summary.txt here.
set -u
ROOT=$(cd "$(dirname "$0")/../../../.." && pwd)
cd "$ROOT"
EVM=smartcontracts/evm
HERE=$EVM/runs/2026-11-09-ua-mtx-merge-t66b-build
L=${LABEL:-b}
export PATH="$HOME/.foundry/bin:$PATH" # at-set.sh calls `forge` by name

step() {
  case $1 in
    forge-*) # one test directory (the T66a forge-dirs.sh, label t66b-<LABEL>); `forge-top` the files directly in test/
      d=$(echo "${1#forge-}" | tr '-' '/'); [ "$d" = top ] || d=test/$d
      scripts/capped sh $EVM/runs/2026-11-08-ua-mtx-merge-t66a/forge-dirs.sh "t66b-$L" "$d" ;;
    lint) (cd $EVM && FOUNDRY_SPARSE_MODE=true FOUNDRY_OUT=out/t66b-lint FOUNDRY_CACHE_PATH=cache/t66b-lint \
        ../../scripts/capped forge test -j 2 --match-path test/ExpectRevertLint.t.sol) ;;
    pair-gas) (cd $EVM && FOUNDRY_TEST=runs/2026-11-09-ua-mtx-merge-t66b-build FOUNDRY_OUT=out/t66b-gas \
        FOUNDRY_CACHE_PATH=cache/t66b-gas ../../scripts/capped forge test -j 2 --match-test test_t66bPair -vv) ;;
    deploy-gas) (cd $EVM && FOUNDRY_TEST=runs/2026-11-09-ua-mtx-merge-t66b-build FOUNDRY_OUT=out/t66b-gas \
        FOUNDRY_CACHE_PATH=cache/t66b-gas ../../scripts/capped forge test -j 2 -vv) ;;
    ua-pins) (cd $EVM && FOUNDRY_SPARSE_MODE=true FOUNDRY_OUT=out/t66b-ua FOUNDRY_CACHE_PATH=cache/t66b-ua \
        ../../scripts/capped forge test -j 2 --isolate --match-path 'test/ua/{UAGas,UARegistryGroups}.t.sol' -vv) ;;
    size) (cd $EVM && mkdir -p out/t66b-sizes && FOUNDRY_OUT=out FOUNDRY_CACHE_PATH=cache ../../scripts/capped forge build src \
        --sizes --json > out/t66b-sizes/sizes-$L.json 2> runs/2026-11-09-ua-mtx-merge-t66b-$L-size-build.log; \
        python3 ../../scripts/size_gate.py out/t66b-sizes/sizes-$L.json size-baseline.json) ;;
    ua8-gas-*) # the UA-8 gas rows (GAS| lines) at one set; GAS_REPIN=1 prints them without the pin check (the test ends FAILED)
      GAS_REPIN=${GAS_REPIN:-0} FOUNDRY_TEST=test/ua scripts/capped $EVM/script/pqz/at-set.sh "${1#ua8-gas-}" test -j 2 \
        --match-path test/ua/UARegistryUA8.t.sol --match-test 'test_T_GAS_' -vv; r=$?
      git diff --exit-code -- $EVM/src/pqz/PqzSet.sol || r=3
      return $r ;;
    size-self) python3 scripts/size_gate.py --self-test && echo self-test ok ;;
    docs) python3 scripts/docs_check.py check ;;
    *) echo "unknown step $1"; return 2 ;;
  esac
}

for s in "$@"; do
  log=$EVM/runs/2026-11-09-ua-mtx-merge-t66b-$L-$s.log
  if [ "${RERUN:-0}" != 1 ] && [ -f "$log" ] && tail -1 "$log" | grep -qx 'rc=0'; then echo "$s: done"; continue; fi
  { step "$s"; echo "rc=$?"; } > "$log" 2>&1
  echo "$s: $(tail -1 "$log")"
done
