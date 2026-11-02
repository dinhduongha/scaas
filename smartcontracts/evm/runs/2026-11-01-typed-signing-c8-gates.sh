#!/bin/bash
# typed-signing C8: the affected steps, one resumable log per step (no full pqz-core gate, no src change).
#   2026-11-01-typed-signing-c8-gates.sh        GATES_FRESH=1 re-runs a step
# Step <s> writes runs/2026-11-01-typed-signing-c8-<s>.txt: first line "# <s> at commit <sha>", last line "rc=<n>". A step is
# skipped when its log ends rc=0 at the current commit and the tree is clean (runs/ apart). Stops at the first failure.
W=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$W" || exit 2
R=smartcontracts/evm/runs
P=2026-11-01-typed-signing-c8
STEPS="build self-test linked zether-e2e deploy deploy-hedera-dry ua-deploy docs mutants"
free() { ! ss -ltn | grep -qE ":$1\b" || { echo "port $1 in use"; return 1; }; }

run_step() {
  case $1 in
    build) cd smartcontracts/evm && ../../scripts/capped forge build ;;
    self-test) for s in n2048-kmax1024 n2304-kmax4096 n2560-kmax16384 n2816-kmax65536; do
        echo "== $s"; PQZ_SET=$s python3 -I smartcontracts/evm/script/pqz/e2e.py --self-test || return 1; done ;;
    linked) python3 -I smartcontracts/evm/script/pqz/test_e2e_linked.py ;;
    zether-e2e) free 18545 && PORT=18545 scripts/capped scripts/e2e-zether.sh ;;
    deploy) free 31993 && cd smartcontracts/evm && python3 -I runs/2026-11-01-typed-signing-r2-deploy.py ;;
    deploy-hedera-dry) free 31994 && cd smartcontracts/evm && python3 -I runs/2026-11-01-typed-signing-c8-hedera-dry.py ;;
    ua-deploy) cd smartcontracts/evm && ../../scripts/capped forge test --match-path test/ua/UADeploy.t.sol ;;
    docs) python3 scripts/test_docs_check.py && python3 scripts/docs_check.py check ;;
    mutants) free 18545 && python3 -I $R/$P-mutants.py ;;
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

for s in $STEPS; do one "$s" || exit 1; done
