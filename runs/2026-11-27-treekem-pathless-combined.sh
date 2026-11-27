#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# The path-less round's combined matrix (delta §14 P10, controller 2026-11-27), once, on the final tree: treekem-pathless with
# the P9 fixes and pqchat-g125 merged. Every forge directory at the default set (one directory per capped call; test/research
# has its own runner), the top-level tests, `test/modules` with its pre-split side, the UA gas pins, the size gate, the deploy
# e2e; the set-sensitive tests and `modules` at the other three sets (`at-set.sh --clean others ...`, parallel lanes); the
# node (lib, clippy, e2e on anvil); ua-rs, clientkeys, the SDK, pqchat-core (tests, clippy, wasm32, reads, tree rows, chain
# on anvil, the e2e on Synapse `--memory 1g`, the bindings check), pqvault-core; format.sh --check over every language; docs.
# From the worktree root:
#   runs/2026-11-27-treekem-pathless-combined.sh --list
#   runs/2026-11-27-treekem-pathless-combined.sh [--force] <step>...
# Several invocations may run side by side (capped holds the slots); the summary row is written under a lock.
# Each step writes runs/2026-11-27-treekem-pathless-combined-<step>.log (git-ignored; first line `# <step> at commit <sha>`,
# last `rc=<n>`) and, on a clean tree, one row `step | commit | rc | counts` of 2026-11-27-treekem-pathless-combined-summary.txt.
# A step done (rc=0) at the same commit on a clean tree is skipped unless --force. Heavy steps through scripts/capped, in the
# foreground.
set -uo pipefail
W=$(git rev-parse --show-toplevel)
cd "$W" || exit 2
R=runs
SUMMARY=$R/2026-11-27-treekem-pathless-combined-summary.txt
TOOLS="$(cd "$(git rev-parse --git-common-dir)/.." && pwd)/scratchpad/tools"
export PATH="$TOOLS/bin:$HOME/.foundry/bin:$PATH" CARGO_INCREMENTAL=0
C="--locked --offline -j2"
cap="$W/scripts/capped"
# research has its own runner
DIRS="account as confidential factory fork gas governance hedera helpers liquidity merge metatx p6f pqchat pqvault pqz pqzh ua v2 wallet wrap zether"
F="vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots,app-core,pqchat-records"
PT="CARGO_TARGET_DIR=../scaas-sdk/target"
fdir() { echo "FOUNDRY_TEST=test/$1 FOUNDRY_SCRIPT=test/$1 $cap forge test -j 1"; }
STEPS=(
    "forge-top|smartcontracts/evm|rm -rf test-s-top && mkdir test-s-top && cp test/*.t.sol test-s-top/ && FOUNDRY_TEST=test-s-top FOUNDRY_SCRIPT=test-s-top $cap forge test -j 1; r=\$?; rm -rf test-s-top; exit \$r"
    "forge-modules|smartcontracts/evm|PYTHONPATH=$W/pqz-core/nethermind/chain python3 script/modules/legacy_artifacts.py build && $(fdir modules) --match-contract '^(Diff|Modules|Paths|Groups)'"
    "uagas|smartcontracts/evm|FOUNDRY_TEST=test/ua FOUNDRY_SCRIPT=test/ua $cap forge test -j 1 --isolate --match-path 'test/ua/{UAGas,UARegistryGroups}.t.sol'"
    "sets-sensitive|smartcontracts/evm|sh script/pqz/at-set.sh --clean others sensitive"
    "sets-modules|smartcontracts/evm|sh script/pqz/at-set.sh --clean others modules"
    "size|smartcontracts/evm|T=\$(mktemp -d) && $cap forge build src --sizes --json --out \"\$T\"/out --cache-path \"\$T\"/cache > \"\$T\"/sizes.json; python3 ../../scripts/size_gate.py \"\$T\"/sizes.json size-baseline.json; r=\$?; rm -rf \"\$T\"; exit \$r"
    "node-test|scaas-node|$cap cargo test $C && $cap cargo clippy $C --all-targets -- -D warnings"
    "ua-test|clients/ua-rs|$cap cargo test $C --features wallet,vectors && $cap cargo test $C --features app-core,vectors --test tree --test app_core --test pqchat_keys && $cap cargo clippy $C --all-targets --features app-core,vectors -- -D warnings"
    "ck-test|clients/clientkeys|$cap npm test && node scripts/pqchat-vectors.mjs --check"
    "sdk-test|clients/scaas-sdk|$cap cargo test $C --features $F && $cap cargo clippy $C --all-targets --features $F,vectors -- -D warnings"
    "pqc-test|clients/pqchat-core|$PT $cap cargo test $C --features vectors && $PT $cap cargo clippy $C --all-targets --features vectors -- -D warnings && $PT $cap cargo check $C --target wasm32-unknown-unknown && python3 -I runs/check_reads.py && python3 -I ../scaas-sdk/gas/pqchat_tree_rows.py ../scaas-sdk/gas/pqchat-tree-forge.txt --check"
    "pqc-chain|clients/pqchat-core|$PT $cap cargo test $C -- --ignored --test-threads 1 chain_"
    "pqc-e2e|clients/pqchat-core|$PT $cap cargo test $C --features vectors --test e2e -- --ignored --test-threads 1 --nocapture"
    "pqc-bind|.|bash clients/pqchat-core/runs/2026-11-17-pqchat-core-bind.sh"
    "pqvault-test|clients/pqvault-core|$cap cargo test $C && $cap cargo test $C --features vectors --test vectors && $cap cargo clippy $C --all-targets -- -D warnings"
    "format|.|bash scripts/format.sh --check"
    "docs|.|python3 scripts/test_docs_check.py && python3 scripts/docs_check.py check && python3 scripts/docs_check.py facts check && python3 scripts/docs_check.py paths && python3 scripts/docs_check.py consumer"
    "deploy-e2e|smartcontracts/evm|for t in script/test_*.py; do echo \"## \$t\"; python3 \"\$t\" || exit 1; done && T=\$(mktemp -d) && $cap forge build src/pqchat/PqChatStore.sol test/forkcheck --extra-output evm.legacyAssembly --out \"\$T\"/out --cache-path \"\$T\"/cache && python3 -I script/forkcheck.py exec cancun test/forkcheck/cases.json --out \"\$T\"/out && python3 -I script/forkcheck.py control cancun --out \"\$T\"/out && python3 -I script/deploy_pqchatstore.py local --out \"\$T\"/out; r=\$?; rm -rf \"\$T\"; exit \$r"
    "node-e2e|scaas-node|(cd ../clients/zether-prover && $cap cargo build $C --release --bin zether-cli --features hazmat) && $cap cargo test $C --test e2e -- --ignored --test-threads=1"
)
for d in $DIRS; do STEPS+=("forge-$d|smartcontracts/evm|$(fdir "$d")"); done
cmd_of() {
    local s
    for s in "${STEPS[@]}"; do [[ ${s%%|*} == "$1" ]] && {
        echo "$s"
        return 0
    }; done
    return 1
}
[[ ${1:-} == --list ]] && {
    for s in "${STEPS[@]}"; do echo "${s%%|*}"; done
    exit 0
}
FORCE=
[[ ${1:-} == --force ]] && {
    FORCE=1
    shift
}
[[ $# -ge 1 ]] || {
    echo "usage: $0 [--list] [--force] <step>..."
    exit 2
}
for s in "$@"; do cmd_of "$s" >/dev/null || {
    echo "[G] no such step: $s (--list)" >&2
    exit 2
}; done
sha=$(git rev-parse --short=9 HEAD)
X=":!$SUMMARY"
clean() { git diff --quiet HEAD -- . "$X" && git diff --quiet --cached HEAD -- . "$X"; }

counts() { # the test counts of a log, by runner (the pqchat-core plan's runner's)
    awk '/^test result:/ { for (i = 1; i <= NF; i++) { if ($(i+1) ~ /^passed/) p += $i; if ($(i+1) ~ /^failed/) f += $i; if ($(i+1) ~ /^ignored/) g += $i }; n++ }
       /^Ran [0-9]+ test suites/ { for (i = 1; i <= NF; i++) { if ($(i+1) == "tests" && $(i+2) == "passed,") fp += $i; if ($(i+1) == "failed,") ff += $i }; fn++ }
       /^(# |ℹ )pass / { np += $3; nn++ } /^(# |ℹ )fail / { nf += $3 }
       /size gate: / || /^check: / || /mutants, .* killed/ || /^ok [0-9]+\/[0-9]+$/ { r = r (r ? "; " : "") $0 }
       END { o = "";
             if (n) o = sprintf("%d passed, %d failed, %d ignored (%d binaries)", p, f, g, n);
             if (fn) o = o (o ? "; " : "") sprintf("forge: %d passed, %d failed", fp, ff);
             if (nn) o = o (o ? "; " : "") sprintf("node: %d pass, %d fail", np, nf);
             if (r) o = o (o ? "; " : "") r;
             printf "%s", (o ? o : "-") }' "$1"
}

worst=0
for s in "$@"; do
    IFS='|' read -r name dir cmd <<<"$(cmd_of "$s")"
    log=$R/2026-11-27-treekem-pathless-combined-$name.log
    if [[ -z $FORCE && -f $log ]] && clean && [[ $(head -1 "$log") == "# $name at commit $sha" ]] && [[ $(tail -1 "$log") == rc=0 ]]; then
        echo "[G] $name: done at $sha (clean tree), skipped"
        continue
    fi
    state=clean
    clean || state=dirty
    {
        echo "# $name at commit $sha"
        echo "# tree $state; $dir: $cmd"
    } >"$log"
    echo "[G] $name start ($dir, tree $state)"
    t0=$SECONDS
    (while sleep 30; do echo "[G] $name running $((SECONDS - t0)) s"; done) &
    hb=$!
    (cd "$dir" && bash -c "$cmd") >>"$log" 2>&1
    rc=$?
    kill "$hb" 2>/dev/null
    wait "$hb" 2>/dev/null
    echo "rc=$rc" >>"$log"
    n=$(counts "$log")
    if [[ $state == clean ]]; then
        (
            flock 9
            touch "$SUMMARY"
            grep -v "^$name | " "$SUMMARY" >"$SUMMARY.$name.new" || true
            echo "$name | $sha | $rc | $n" >>"$SUMMARY.$name.new"
            sort -o "$SUMMARY" "$SUMMARY.$name.new" && rm -f "$SUMMARY.$name.new"
        ) 9>"$(git rev-parse --git-dir)/combined-summary.lock"
    else
        n="$n; tree dirty, no summary row"
    fi
    if ((rc == 0)); then echo "[G] $name ok in $((SECONDS - t0)) s: $n"; else
        echo "[G] $name FAIL rc=$rc in $((SECONDS - t0)) s: $n ($log)"
        worst=1
    fi
done
exit $worst
