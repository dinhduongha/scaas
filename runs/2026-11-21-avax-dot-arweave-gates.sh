#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# The Avalanche / Polkadot / Arweave plan's gate runner (docs/superpowers/plans/2026-11-21-avax-polkadot-arweave.md, T0), from
# the worktree root:
#   runs/2026-11-21-avax-dot-arweave-gates.sh --list
#   runs/2026-11-21-avax-dot-arweave-gates.sh --only <step>[,<step>…] [--force]
# Each step writes runs/2026-11-21-avax-dot-arweave-<step>.log (git-ignored; first line `# <step> at commit <sha>`, last
# `rc=<n>`) and one row `step | commit | rc | counts` of 2026-11-21-avax-dot-arweave-summary.txt. A step done (rc=0) at the
# same commit on a clean tree (no tracked change) is skipped unless --force. Heavy steps run through scripts/capped, in the
# foreground, one at a time; the node's suite and e2e at CAPPED_MEM=6G. An unknown step exits 2 and writes nothing.
# forge-all, forge-sets and node-e2e are the round end's (T22).
set -uo pipefail
W=$(git rev-parse --show-toplevel)
cd "$W" || exit 2
R=runs
SUMMARY=$R/2026-11-21-avax-dot-arweave-summary.txt
export PATH="$HOME/.foundry/bin:$PATH"
# J: the build jobs (default -j2). T: test threads of the e2e step (default all).
C="--locked --offline ${J:--j2}"
TT=${T:+ --test-threads=$T}
cap="$W/scripts/capped"

# step | directory | command (run with bash -c from the directory)
STEPS=(
    "forge-chat|smartcontracts/evm|$cap forge test --match-path 'test/pqchat/**'"
    # forge-all: every forge directory at the default set (the forge-* jobs of .github/workflows/ci.yml)
    "forge-all|smartcontracts/evm|$cap forge test && $cap forge test --isolate --match-path 'test/ua/{UAGas,UARegistryGroups}.t.sol'"
    "forge-sets|smartcontracts/evm|trap 'git checkout -- src/pqz/PqzSet.sol' EXIT; script/pqz/at-set.sh others sensitive && script/pqz/at-set.sh others modules"
    "size|smartcontracts/evm|T=\$(mktemp -d) && trap 'rm -rf \"\$T\"' EXIT && $cap forge build src --sizes --json > \"\$T\"/sizes.json && python3 ../../scripts/size_gate.py \"\$T\"/sizes.json size-baseline.json"
    "deploy-py|smartcontracts/evm|for t in script/test_*.py; do echo \"## \$t\"; python3 \"\$t\" || exit 1; done"
    "ck-test|clients/clientkeys|$cap npm test"
    "ua-test|clients/ua-rs|$cap cargo test $C --all-features"
    "rpc-test|clients/scaas-rpc|$cap cargo test $C --all-features && $cap cargo clippy $C --all-targets --all-features -- -D warnings"
    "rpc-wasm|clients/scaas-rpc|$cap cargo check $C --target wasm32-unknown-unknown --no-default-features --features evm\$(grep -q '^arweave *=' Cargo.toml && echo ,arweave)"
    "sdk-test|clients/scaas-sdk|$cap cargo test $C --all-features && $cap cargo clippy $C --all-targets --all-features -- -D warnings"
    "node-test|scaas-node|CAPPED_MEM=6G $cap cargo test $C && $cap cargo clippy $C --all-targets -- -D warnings"
    "node-e2e|scaas-node|CAPPED_MEM=6G $cap cargo test $C --test e2e -- --ignored$TT"
    "docs|.|python3 scripts/docs_check.py check && python3 scripts/docs_check.py paths && python3 scripts/test_docs_check.py"
)

cmd_of() {
    local s
    for s in "${STEPS[@]}"; do [[ ${s%%|*} == "$1" ]] && {
        echo "$s"
        return 0
    }; done
    return 1
}

case "${1:-}" in
    --list)
        for s in "${STEPS[@]}"; do
            IFS='|' read -r n d c <<<"$s"
            printf '%-16s %s: %s\n' "$n" "$d" "$c"
        done
        exit 0
        ;;
    --only) [[ -n "${2:-}" ]] || {
        echo "[G] --only needs a step (--list)" >&2
        exit 2
    } ;;
    *)
        echo "usage: $0 --list | --only <step>[,<step>…] [--force]" >&2
        exit 2
        ;;
esac
IFS=',' read -ra WANT <<<"$2"
FORCE=${3:-}
for s in "${WANT[@]}"; do cmd_of "$s" >/dev/null || {
    echo "[G] no such step: $s (--list)" >&2
    exit 2
}; done

sha=$(git rev-parse --short=9 HEAD)
X=":!$SUMMARY"
clean() { git diff --quiet HEAD -- . "$X" && git diff --quiet --cached HEAD -- . "$X"; }

counts() { # sum of the `test result:` lines of a log
    awk '/^test result:/ { for (i = 1; i <= NF; i++) { if ($(i+1) ~ /^passed/) p += $i; if ($(i+1) ~ /^failed/) f += $i; if ($(i+1) ~ /^ignored/) g += $i }; n++ }
       /^RESULT / { sub(/^RESULT /, ""); r = r (r ? "; " : "") $0 }
       /^Ran [0-9]+ test suites?/ { for (i = 1; i <= NF; i++) { if ($(i+1) ~ /^tests?$/ && $(i+2) == "passed,") p += $i; if ($(i+1) == "failed,") f += $i; if ($(i+1) ~ /^skipped/) g += $i }; n++ }
       /^# (pass|fail|skipped|todo) [0-9]+$/ { if ($2 == "pass") p += $3; else if ($2 == "fail") f += $3; else g += $3; if ($2 == "pass") n++ }
       /^ok [0-9]+\/[0-9]+$/ { split($2, a, "/"); p += a[1]; f += a[2] - a[1]; n++ }
       /^check: [0-9]+ error/ { r = r (r ? "; " : "") $0 }
       END { if (n) printf "%d passed, %d failed, %d ignored (%d binaries)%s", p, f, g, n, (r ? "; " r : ""); else if (r) printf "%s", r; else printf "-" }' "$1"
}

row() { # replace the step's summary row
    touch "$SUMMARY"
    grep -v "^$1 |" "$SUMMARY" >"$SUMMARY.new" || true
    echo "$1 | $2 | $3 | $4" >>"$SUMMARY.new"
    mv "$SUMMARY.new" "$SUMMARY"
}

worst=0
for s in "${WANT[@]}"; do
    IFS='|' read -r name dir cmd <<<"$(cmd_of "$s")"
    log=$R/2026-11-21-avax-dot-arweave-$name.log
    if [[ $FORCE != --force && -f $log ]] && clean && [[ $(head -1 "$log") == "# $name at commit $sha" ]] && [[ $(tail -1 "$log") == rc=0 ]]; then
        echo "[G] $name: done at $sha (clean tree), skipped"
        continue
    fi
    state=clean
    clean || state=dirty
    echo "# $name at commit $sha" >"$log"
    echo "# tree $state; $dir: $cmd" >>"$log"
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
    [[ $state == dirty ]] && n="$n; tree dirty"
    row "$name" "$sha" "$rc" "$n"
    if ((rc == 0)); then echo "[G] $name ok in $((SECONDS - t0)) s: $n"; else
        echo "[G] $name FAIL rc=$rc in $((SECONDS - t0)) s: $n (see $log)"
        worst=$rc
    fi
done
exit "$worst"
