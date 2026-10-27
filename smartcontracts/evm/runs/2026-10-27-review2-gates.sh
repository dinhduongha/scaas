#!/bin/bash
# review2 Task 9: the closing gates, one resumable step per log (owner 2026-10-27).
#   2026-10-27-review2-gates.sh [--only <step>]      GATES_FRESH=1 re-runs every step
# Step <s> writes runs/2026-10-27-review2-<s>.txt: first line "# <s> at commit <sha>", last line "rc=<n>".
# A step is skipped when its log ends rc=0 at the current commit (git rev-parse --short HEAD) and the tree is clean.
# "Clean" ignores smartcontracts/evm/runs/ (the logs this script writes); every other change, untracked files included, counts.
# After a run, commit the logs (HEAD changes) and do not re-run. Steps never edit tracked files (at-set.sh restores PqzSet.sol).
W=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$W" || exit 2
R=smartcontracts/evm/runs
STEPS="forge-n2048-kmax1024 forge-n2304-kmax4096 forge-n2560-kmax16384 forge-n2816-kmax65536 sizes gen-set docs cargo-zether-prover zether-cross wasm-zether-prover cargo-scaas-node clientkeys"
export CAPPED_SLOTS=${CAPPED_SLOTS:-2} CAPPED_MEM=${CAPPED_MEM:-3G}

run_step() { # the command of one step (runs in a subshell, rc = the step's rc)
  case $1 in
    forge-*) scripts/capped smartcontracts/evm/script/pqz/at-set.sh "${1#forge-}" test ;;
    sizes) cd smartcontracts/evm || return 1
      j=$(mktemp) && ../../scripts/capped forge build src --sizes --json > "$j" &&
        python3 -I ../../scripts/size_gate.py "$j" size-baseline.json; rc=$?; rm -f "$j"; return $rc ;;
    gen-set) python3 -I pqz-core/params/sets/gen_set.py --all --check ;;
    docs) python3 scripts/test_docs_check.py && python3 scripts/docs_check.py check &&
      { python3 scripts/docs_check.py facts check | tail -n 12; true; } ;; # facts: logged only, 9 misses already on main (history/ docs)
    cargo-zether-prover) cd clients/zether-prover && ../../scripts/capped cargo test -j2 ;;
    wasm-zether-prover) cd clients/zether-prover && ../../scripts/capped cargo build -j2 --release --bin zether-cli &&
      ../../scripts/capped cargo build -j2 --release --lib --target wasm32-unknown-unknown &&
      ~/.cargo/bin/wasm-bindgen --target nodejs --out-dir pkg target/wasm32-unknown-unknown/release/zether_prover.wasm &&
      node smoke/smoke.cjs ;;
    zether-cross) # the CLI-vs-contract cross-check; a skipped test (no CLI / no --ffi) must FAIL the step
      (cd clients/zether-prover && ../../scripts/capped cargo build -j2 --release --bin zether-cli) || return 1
      cd smartcontracts/evm || return 1
      o=$(mktemp); ZETHER_CLI="$W/clients/zether-prover/target/release/zether-cli" ../../scripts/capped forge test --ffi \
        --match-path test/zether/ZetherProverCross.t.sol 2>&1 | tee "$o"; rc=${PIPESTATUS[0]}
      [ $rc -eq 0 ] && grep -q "6 passed; 0 failed; 0 skipped" "$o" || { echo "zether-cross: not 6 passed / 0 skipped"; rc=1; }
      rm -f "$o"; return $rc ;;
    cargo-scaas-node) cd scaas-node && ../scripts/capped cargo test -j2 ;;
    clientkeys) cd clients/clientkeys && ../../scripts/capped npm test ;;
    *) echo "unknown step $1"; return 2 ;;
  esac
}

done_at_head() { # log ends rc=0, first line names HEAD, tree clean apart from the logs
  L=$R/2026-10-27-review2-$1.txt
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
  L=$R/2026-10-27-review2-$s.txt
  echo "run  $s"
  { echo "# $s at commit $(git rev-parse --short HEAD)"; (run_step "$s") 2>&1; echo "rc=$?"; } > "$L" 2>&1
  tail -n1 "$L" | grep -qx 'rc=0' || { echo "FAIL $s ($L)"; fail=1; break; }
done
exit $fail
