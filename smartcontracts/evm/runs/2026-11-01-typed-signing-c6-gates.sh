#!/bin/bash
# typed-signing C6: the affected steps, one resumable log per step (no full pqz-core gate: TS-D20).
#   2026-11-01-typed-signing-c6-gates.sh [--only <step>]      GATES_FRESH=1 re-runs a step
# Step <s> writes runs/2026-11-01-typed-signing-c6-<s>.txt: first line "# <s> at commit <sha>", last line "rc=<n>". A step is
# skipped when its log ends rc=0 at the current commit and the tree is clean (runs/ apart). Stops at the first failure.
W=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$W" || exit 2
R=smartcontracts/evm/runs
P=${P:-2026-11-01-typed-signing-c6}
OTHERS="n2048-kmax1024 n2560-kmax16384 n2816-kmax65536"
STEPS="forge-n2304-kmax4096"
for s in $OTHERS; do STEPS="$STEPS v2-metatx-$s"; done
for s in n2048-kmax1024 n2304-kmax4096 n2560-kmax16384 n2816-kmax65536; do STEPS="$STEPS gas-$s"; done
STEPS="$STEPS overhead-n2048-kmax1024 clientkeys vectors-twice sizes docs"

run_step() {
  case $1 in
    forge-n2304-kmax4096) cd smartcontracts/evm && ../../scripts/capped forge test ;;
    v2-metatx-*) scripts/capped smartcontracts/evm/script/pqz/at-set.sh "${1#v2-metatx-}" test --match-path 'test/{v2,metatx}/*' ;;
    gas-*) scripts/capped smartcontracts/evm/script/pqz/at-set.sh "${1#gas-}" test --match-path test/pqz/PqzStateGas.t.sol --match-contract PqzStatePinGasTest --match-test test_gasTable -vv ;;
    overhead-*) scripts/capped smartcontracts/evm/script/pqz/at-set.sh "${1#overhead-}" test --match-test test_splitOverhead_dataSizeBound ;;
    clientkeys) cd clients/clientkeys && ../../scripts/capped npm test ;;
    vectors-twice) cd clients/clientkeys && node scripts/typed-ops-vectors.mjs && node scripts/ua-sig-vectors.mjs >/dev/null && git diff --exit-code --stat -- ../../smartcontracts/vectors ;;
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
