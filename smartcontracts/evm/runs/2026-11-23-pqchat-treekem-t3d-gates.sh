#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Plan 2026-11-23-pqchat-treekem T3d (owner 2026-11-24, option A; CTR-CHAT-27): the task's gates, from the worktree root:
#   smartcontracts/evm/runs/2026-11-23-pqchat-treekem-t3d-gates.sh --list
#   smartcontracts/evm/runs/2026-11-23-pqchat-treekem-t3d-gates.sh [--force] <step>...
# Each step writes smartcontracts/evm/runs/2026-11-23-pqchat-treekem-t3d-<step>.log (git-ignored; first line `# <step> at commit <sha>`,
# last `rc=<n>`) and, on a clean tree, one row `step | commit | rc | counts` of 2026-11-23-pqchat-treekem-t3d-summary.txt. A step done
# (rc=0) at the same commit on a clean tree is skipped unless --force. Heavy steps go through scripts/capped, in the foreground.
# Scope (AGENTS.md, "any other contract change"): every forge directory at the default set, then the set-sensitive tests and
# test/modules at the three other sets, one set at a time (memory allows one lane: `sets-<set>-sensitive`, then
# `sets-<set>-modules`); the gas file under `--enable-tx-gas-limit` with its positive control (`treegas`); every treekem
# mutant runner's check mode; the docs. clientkeys did not change in T3d. The round's matrix (node, e2e, every client)
# runs once at its end (T10b).
set -uo pipefail
W=$(git rev-parse --show-toplevel)
cd "$W" || exit 2
R=smartcontracts/evm/runs
SUMMARY=$R/2026-11-23-pqchat-treekem-t3d-summary.txt
export PATH="$HOME/.foundry/bin:$PATH" CAPPED_SLOTS=${CAPPED_SLOTS:-4} CARGO_INCREMENTAL=0
cap="$W/scripts/capped"
DIRS="account as confidential factory fork gas governance hedera liquidity merge metatx p6f pqchat pqvault pqz pqzh research ua v2
  wallet wrap zether"
fdir() { echo "FOUNDRY_TEST=test/$1 FOUNDRY_SCRIPT=test/$1 $cap forge test -j 1"; }
STEPS=(
    "forge-top|smartcontracts/evm|rm -rf test-s-top && mkdir test-s-top && cp test/*.t.sol test-s-top/ && FOUNDRY_TEST=test-s-top FOUNDRY_SCRIPT=test-s-top $cap forge test -j 1; r=\$?; rm -rf test-s-top; exit \$r"
    "forge-modules|smartcontracts/evm|PYTHONPATH=$W/pqz-core/nethermind/chain python3 script/modules/legacy_artifacts.py build && $(fdir modules) --match-contract '^(Diff|Modules|Paths|Groups)'"
    "uagas|smartcontracts/evm|FOUNDRY_TEST=test/ua FOUNDRY_SCRIPT=test/ua $cap forge test -j 1 --isolate --match-path 'test/ua/{UAGas,UARegistryGroups}.t.sol'"
    "size|smartcontracts/evm|T=\$(mktemp -d) && $cap forge build src --sizes --json > \"\$T\"/sizes.json && python3 ../../scripts/size_gate.py \"\$T\"/sizes.json size-baseline.json; r=\$?; rm -rf \"\$T\"; exit \$r"
    "fmt|smartcontracts/evm|forge fmt --check src test"
    "treegas|smartcontracts/evm|TREE_GAS_CAP=1 FOUNDRY_TEST=test/pqchat FOUNDRY_SCRIPT=test/pqchat $cap forge test -j 1 --enable-tx-gas-limit --match-path test/pqchat/PqChatTreeGas.t.sol -vv"
    "mutants|.|for x in a b c d; do python3 -I smartcontracts/evm/runs/2026-11-23-pqchat-treekem-t3\$x-mutants.py check || exit 1; done && bash clients/clientkeys/runs/2026-11-23-pqchat-treekem-t1a-mutants.sh check && bash clients/clientkeys/runs/2026-11-23-pqchat-treekem-t1b-mutants.sh check && bash clients/ua-rs/runs/2026-11-23-pqchat-treekem-t2-mutants.sh check"
    "docs|.|python3 scripts/docs_check.py check && python3 scripts/docs_check.py paths && python3 scripts/test_docs_check.py"
)
for d in $DIRS; do STEPS+=("forge-$d|smartcontracts/evm|$(fdir "$d")"); done
for set in n2048-kmax1024 n2560-kmax16384 n2816-kmax65536; do
    STEPS+=("sets-${set%%-*}-sensitive|smartcontracts/evm|PYTHONPATH=$W/pqz-core/nethermind/chain sh script/pqz/at-set.sh $set sensitive")
    STEPS+=("sets-${set%%-*}-modules|smartcontracts/evm|PYTHONPATH=$W/pqz-core/nethermind/chain sh script/pqz/at-set.sh $set modules")
done

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
    log=$R/2026-11-23-pqchat-treekem-t3d-$name.log
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
