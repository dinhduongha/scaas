#!/bin/bash
# near-algorand T2: the EVM gates the UAKinds bytecode change triggers (spec 2026-10-28 §8: forge at the four sets,
# the size gate, docs_check; not the pqz-core gate), one resumable step per log. Same rules as 2026-10-27-review2-gates.sh:
#   2026-10-28-t2-gates.sh [--only <step>]      GATES_FRESH=1 re-runs every step
# Step <s> writes runs/2026-10-28-t2-<s>.txt: first line "# <s> at commit <sha>", last line "rc=<n>"; a step is skipped
# when its log ends rc=0 at the current commit and the tree is clean (smartcontracts/evm/runs/ excluded).
W=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$W" || exit 2
R=smartcontracts/evm/runs
STEPS="forge-n2048-kmax1024 forge-n2304-kmax4096 forge-n2560-kmax16384 forge-n2816-kmax65536 forge-isolate sizes docs"
export CAPPED_SLOTS=${CAPPED_SLOTS:-2} CAPPED_MEM=${CAPPED_MEM:-3G}

run_step() { # the command of one step (runs in a subshell, rc = the step's rc)
  case $1 in
    forge-isolate) cd smartcontracts/evm && ../../scripts/capped forge test --isolate --match-path 'test/ua/{UAGas,UARegistryGroups}.t.sol' ;;
    forge-*) scripts/capped smartcontracts/evm/script/pqz/at-set.sh "${1#forge-}" test ;;
    sizes) cd smartcontracts/evm || return 1
      j=$(mktemp) && ../../scripts/capped forge build src --sizes --json > "$j" &&
        python3 -I ../../scripts/size_gate.py "$j" size-baseline.json; rc=$?; rm -f "$j"; return $rc ;;
    docs) python3 scripts/test_docs_check.py && python3 -I scripts/docs_check.py check ;;
    *) echo "unknown step $1"; return 2 ;;
  esac
}

done_at_head() { # log ends rc=0, first line names HEAD, tree clean apart from the logs
  L=$R/2026-10-28-t2-$1.txt
  [ -f "$L" ] && [ "$(tail -n1 "$L")" = "rc=0" ] && [ "$(head -n1 "$L")" = "# $1 at commit $(git rev-parse --short HEAD)" ] &&
    [ -z "$(git status --porcelain -- . ":(exclude)$R")" ]
}

only=
[ "$1" = "--only" ] && only=$2
[ -z "$only" ] || case " $STEPS " in *" $only "*) ;; *) echo "unknown step $only" >&2; exit 2 ;; esac
fail=0
for s in $STEPS; do
  [ -z "$only" ] || [ "$s" = "$only" ] || continue
  if [ -z "$GATES_FRESH" ] && done_at_head "$s"; then echo "skip $s (rc=0 at $(git rev-parse --short HEAD))"; continue; fi
  L=$R/2026-10-28-t2-$s.txt
  echo "run  $s"
  { echo "# $s at commit $(git rev-parse --short HEAD)"; (run_step "$s") 2>&1; echo "rc=$?"; } > "$L" 2>&1
  tail -n1 "$L" | grep -qx 'rc=0' || { echo "FAIL $s ($L)"; fail=1; break; }
done
exit $fail
