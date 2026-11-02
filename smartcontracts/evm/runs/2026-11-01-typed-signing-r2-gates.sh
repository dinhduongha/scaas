#!/bin/bash
# typed-signing R2: the affected steps, one resumable log per step (no full pqz-core gate: TS-D20).
#   2026-11-01-typed-signing-r2-gates.sh [--only <step>]      GATES_FRESH=1 re-runs a step
# Step <s> writes runs/2026-11-01-typed-signing-r2-<s>.txt: first line "# <s> at commit <sha>", last line "rc=<n>". A step is
# skipped when its log ends rc=0 at the current commit and the tree is clean (runs/ apart). Stops at the first failure.
W=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$W" || exit 2
R=smartcontracts/evm/runs
P=2026-11-01-typed-signing-r2
OTHERS="n2048-kmax1024 n2560-kmax16384 n2816-kmax65536"
ALL="n2048-kmax1024 n2304-kmax4096 n2560-kmax16384 n2816-kmax65536"
STEPS="forge-n2304-kmax4096"
for s in $OTHERS; do STEPS="$STEPS ua-pqz-$s"; done
for s in $ALL; do STEPS="$STEPS gas-$s hotpath-$s"; done
STEPS="$STEPS overhead-n2048-kmax1024 clientkeys e2e-linked sizes docs"

at_set() { scripts/capped smartcontracts/evm/script/pqz/at-set.sh "$@"; }
run_step() {
  case $1 in
    forge-n2304-kmax4096) cd smartcontracts/evm && ../../scripts/capped forge test ;;
    ua-pqz-*) at_set "${1#ua-pqz-}" test --match-path 'test/{ua,pqz}/*' ;;
    gas-*) at_set "${1#gas-}" test --match-path test/pqz/PqzStateGas.t.sol --match-contract PqzStatePinGasTest --match-test test_gasTable -vv ;;
    hotpath-*) at_set "${1#hotpath-}" test --match-path 'test/ua/*' --match-test 'test_gasHotPath|test_deployGas|test_msigPopAtTheBudget|test_split_storePqzPopWithAVerify' -vv ;;
    overhead-*) at_set "${1#overhead-}" test --match-test test_splitOverhead_dataSizeBound ;;
    clientkeys) cd clients/clientkeys && ../../scripts/capped npm test ;;
    e2e-linked) python3 -I smartcontracts/evm/script/pqz/test_e2e_linked.py && python3 -I smartcontracts/evm/script/pqz/e2e.py --self-test && python3 -I scripts/size_gate.py --self-test ;;
    sizes) cd smartcontracts/evm || return 1
      j=$(mktemp) && ../../scripts/capped forge build src --sizes --json > "$j" &&
        python3 -I ../../scripts/size_gate.py "$j" size-baseline.json; rc=$?; rm -f "$j"; return $rc ;;
    docs) python3 scripts/test_docs_check.py && python3 scripts/docs_check.py check ;;
    *) echo "unknown step $1"; return 2 ;;
  esac
}

sha=$(git rev-parse --short HEAD)
clean() { [ -z "$(git status --porcelain -- . ":(exclude)$R")" ]; }
one() {
  l=$R/$P-$1.txt
  if [ -z "$GATES_FRESH" ] && clean && [ -f "$l" ] && [ "$(head -1 "$l")" = "# $1 at commit $sha" ] && [ "$(tail -1 "$l")" = rc=0 ]; then
    echo "skip $1 (done at $sha)"; return 0
  fi
  echo "# $1 at commit $sha" > "$l"
  (run_step "$1") >> "$l" 2>&1
  rc=$?
  echo "rc=$rc" >> "$l"
  echo "$1 rc=$rc"
  return $rc
}

if [ "$1" = --only ]; then one "$2"; exit $?; fi
for s in $STEPS; do one "$s" || exit 1; done
