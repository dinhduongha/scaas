#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# The path-less round's task-level matrix gaps (delta P4, P5; controller 2026-11-27): the forge directories at the default set
# not run in their tasks (one directory per capped call), the top-level tests, `test/modules` with its pre-split side, the UA
# gas pins, the other three sets (`at-set.sh <set> sensitive`, then `<set> modules`, one set after another: one capped job
# at a time on a shared machine), the deploy e2e of CI's contract job
# (PqChatStore's path on anvil at cancun), and the node e2e on anvil. From the worktree root:
#   runs/2026-11-27-treekem-pathless-matrix.sh --list
#   runs/2026-11-27-treekem-pathless-matrix.sh [--force] <step>...
# Each step writes runs/2026-11-27-treekem-pathless-matrix-<step>.log (git-ignored; first line `# <step> at commit <sha>`,
# last `rc=<n>`) and, on a clean tree, one row `step | commit | rc | counts` of 2026-11-27-treekem-pathless-matrix-summary.txt.
# A step done (rc=0) at the same commit on a clean tree is skipped unless --force. Heavy steps through scripts/capped, in the
# foreground, one at a time, at capped's default settings.
set -uo pipefail
W=$(git rev-parse --show-toplevel)
cd "$W" || exit 2
R=runs
SUMMARY=$R/2026-11-27-treekem-pathless-matrix-summary.txt
TOOLS="$(cd "$(git rev-parse --git-common-dir)/.." && pwd)/scratchpad/tools"
export PATH="$TOOLS/bin:$HOME/.foundry/bin:$PATH" CARGO_INCREMENTAL=0
C="--locked --offline -j2"
cap="$W/scripts/capped"
# test/pqchat, pqvault, governance, factory, v2 and helpers ran in P4 (76c19707c, 301c484ba); research has its own runner
DIRS="account as confidential fork gas hedera liquidity merge metatx p6f pqz pqzh ua wallet wrap zether"
fdir() { echo "FOUNDRY_TEST=test/$1 FOUNDRY_SCRIPT=test/$1 $cap forge test -j 1"; }
STEPS=(
    "forge-top|smartcontracts/evm|rm -rf test-s-top && mkdir test-s-top && cp test/*.t.sol test-s-top/ && FOUNDRY_TEST=test-s-top FOUNDRY_SCRIPT=test-s-top $cap forge test -j 1; r=\$?; rm -rf test-s-top; exit \$r"
    "forge-modules|smartcontracts/evm|PYTHONPATH=$W/pqz-core/nethermind/chain python3 script/modules/legacy_artifacts.py build && $(fdir modules) --match-contract '^(Diff|Modules|Paths|Groups)'"
    "uagas|smartcontracts/evm|FOUNDRY_TEST=test/ua FOUNDRY_SCRIPT=test/ua $cap forge test -j 1 --isolate --match-path 'test/ua/{UAGas,UARegistryGroups}.t.sol'"
    "sets-sensitive|smartcontracts/evm|r=0; for x in n2048-kmax1024 n2560-kmax16384 n2816-kmax65536; do sh script/pqz/at-set.sh \$x sensitive || r=1; done; exit \$r"
    "sets-modules|smartcontracts/evm|r=0; for x in n2048-kmax1024 n2560-kmax16384 n2816-kmax65536; do sh script/pqz/at-set.sh \$x modules || r=1; done; exit \$r"
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
    log=$R/2026-11-27-treekem-pathless-matrix-$name.log
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
        touch "$SUMMARY"
        grep -v "^$name | " "$SUMMARY" >"$SUMMARY.new" || true
        echo "$name | $sha | $rc | $n" >>"$SUMMARY.new"
        sort -o "$SUMMARY" "$SUMMARY.new" && rm -f "$SUMMARY.new"
    else
        n="$n; tree dirty, no summary row"
    fi
    if ((rc == 0)); then echo "[G] $name ok in $((SECONDS - t0)) s: $n"; else
        echo "[G] $name FAIL rc=$rc in $((SECONDS - t0)) s: $n ($log)"
        worst=1
    fi
done
exit $worst
