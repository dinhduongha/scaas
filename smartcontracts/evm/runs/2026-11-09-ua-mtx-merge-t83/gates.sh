#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Plan T83 (payNo as bytes32, PayMeta.save, the on-chain pay records; owner 2026-11-09) gate steps, one at a time, from the
# repository root:
#   sh smartcontracts/evm/runs/2026-11-09-ua-mtx-merge-t83/gates.sh <step> [<step> ...]
# Each step logs to smartcontracts/evm/runs/2026-11-09-ua-mtx-merge-t83-<step>.log (git-ignored) and ends it with `rc=<n>`; a
# step whose log ends with `rc=0` is skipped (RERUN=1 runs it again). Heavy commands go through scripts/capped, foreground.
# The committed summary is summary.txt in this directory (`step | commit | rc | counts`).
set -u
ROOT=$(cd "$(dirname "$0")/../../../.." && pwd)
cd "$ROOT"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
EVM=smartcontracts/evm
export PATH="$HOME/.foundry/bin:$PATH" # at-set.sh calls `forge` by name
PAY='test/metatx/PayRecords.t.sol,test/metatx/PayMeta.t.sol,test/metatx/PayLanes.t.sol'

step() {
  case $1 in
    forge-*) # one test directory (forge-dirs.sh, label t83); `forge-top` the files directly in test/
      d=$(echo "${1#forge-}" | tr '-' '/'); [ "$d" = top ] || d=test/$d
      scripts/capped sh $EVM/runs/2026-11-08-ua-mtx-merge-t66a/forge-dirs.sh t83 "$d" ;;
    lint) (cd $EVM && FOUNDRY_SPARSE_MODE=true FOUNDRY_OUT=out/t83-lint FOUNDRY_CACHE_PATH=cache/t83-lint \
        ../../scripts/capped ~/.foundry/bin/forge test -j 2 --match-path test/ExpectRevertLint.t.sol) ;;
    kinds-*) # the pay and record tests (the PQZ kinds of the parity rigs) and the confidential regulated kinds at one set;
      # at-set.sh restores src/pqz/PqzSet.sol (checked after)
      FOUNDRY_SPARSE_MODE=true scripts/capped $EVM/script/pqz/at-set.sh "${1#kinds-}" test -j 2 \
        --match-path "{$PAY,test/as/confidential/TaxConfidential.t.sol}"; r=$?
      git diff --exit-code -- $EVM/src/pqz/PqzSet.sol || r=3
      return $r ;;
    gas) (cd $EVM && FOUNDRY_SPARSE_MODE=true FOUNDRY_OUT=out/t83-gas FOUNDRY_CACHE_PATH=cache/t83-gas \
        ../../scripts/capped ~/.foundry/bin/forge test -j 2 --match-path test/v2/MetaTxGasV2.t.sol --match-test 'test_gasP_' -vv) ;;
    size) (cd $EVM && FOUNDRY_OUT=out/t83-sizes FOUNDRY_CACHE_PATH=cache/t83-sizes ../../scripts/capped ~/.foundry/bin/forge build src \
        --sizes --json > "$T"/t83-sizes.json 2> runs/2026-11-09-ua-mtx-merge-t83-size-build.log; \
        python3 ../../scripts/size_gate.py "$T"/t83-sizes.json size-baseline.json) ;;
    vectors) # every writer twice, then no diff against the work tree's vectors (run after the files are written once)
      for i in 1 2; do
        (cd $EVM && PAYMETA_WRITE=1 FOUNDRY_SPARSE_MODE=true FOUNDRY_OUT=out/t83-vec FOUNDRY_CACHE_PATH=cache/t83-vec \
          ../../scripts/capped ~/.foundry/bin/forge test -j 2 --match-path 'test/metatx/Pay{Records,Meta}.t.sol' \
          --match-test 'Vectors') || return 1
        (cd $EVM && WRITE_KAT=1 FOUNDRY_SPARSE_MODE=true FOUNDRY_OUT=out/t83-vec FOUNDRY_CACHE_PATH=cache/t83-vec \
          ../../scripts/capped ~/.foundry/bin/forge test -j 2 --match-path test/account/AccountKat.t.sol) || return 1
        (cd $EVM && PAYTAX_WRITE=1 FOUNDRY_SPARSE_MODE=true FOUNDRY_OUT=out/t83-vec FOUNDRY_CACHE_PATH=cache/t83-vec \
          ../../scripts/capped ~/.foundry/bin/forge test -j 2 --match-path test/as/Tax.t.sol --match-test test_payTaxVectors) || return 1
        (cd clients/clientkeys && node scripts/typed-ops-vectors.mjs && node scripts/ua-sig-vectors.mjs) || return 1
        git diff --exit-code --stat -- smartcontracts/vectors $EVM/test/vectors > "$T"/t83-vec-$i.diff
        git status --short -- smartcontracts/vectors $EVM/test/vectors >> "$T"/t83-vec-$i.diff
      done
      cmp "$T"/t83-vec-1.diff "$T"/t83-vec-2.diff && cat "$T"/t83-vec-2.diff ;;
    clientkeys) (cd clients/clientkeys && ../../scripts/capped npm test) ;;
    node-test) (cd scaas-node && CAPPED_MEM=6G ../scripts/capped cargo test) ;;
    node-clippy) (cd scaas-node && ../scripts/capped cargo clippy --all-targets -- -D warnings) ;;
    docs) python3 scripts/docs_check.py check ;;
    *) echo "unknown step $1"; return 2 ;;
  esac
}

for s in "$@"; do
  log=$EVM/runs/2026-11-09-ua-mtx-merge-t83-$s.log
  if [ "${RERUN:-0}" != 1 ] && [ -f "$log" ] && tail -1 "$log" | grep -qx 'rc=0'; then echo "$s: done"; continue; fi
  { step "$s"; echo "rc=$?"; } > "$log" 2>&1
  echo "$s: $(tail -1 "$log")"
done
