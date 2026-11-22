#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# The pqchat-core build plan's gate runner (docs/superpowers/plans/2026-11-17-pqchat-core.md, T0; the scaas-sdk plan's runner
# as the model), from the worktree root:
#   clients/pqchat-core/runs/2026-11-17-pqchat-core-gates.sh --list
#   TASK=T<n> clients/pqchat-core/runs/2026-11-17-pqchat-core-gates.sh --only <step>[,<step>…] [--force]
# Each step writes clients/pqchat-core/runs/2026-11-17-pqchat-core-<step>.log (git-ignored; first line `# <step> at commit
# <sha>`, last `rc=<n>`) and, on a clean tree only, one row `task | step | commit | rc | counts` of
# 2026-11-17-pqchat-core-summary.txt (keyed by task and step; no row is written by hand; notes are `#` lines). A step done
# (rc=0) at the same commit on a clean tree is skipped unless --force. Heavy steps run through scripts/capped, in the
# foreground. An unknown step exits 2 and writes nothing.
set -uo pipefail
W=$(git rev-parse --show-toplevel)
cd "$W" || exit 2
R=clients/pqchat-core/runs
SUMMARY=$R/2026-11-17-pqchat-core-summary.txt
TASK=${TASK:--}
export PATH="$HOME/.foundry/bin:$PATH"
C="--locked --offline ${J:--j2}"
cap="$W/scripts/capped"
# the SDK's CI feature set (its gate runner's F)
F="vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots,app-core,pqchat-records"
# every mutant script of this plan loads (its `old` texts occur once); stale records printed, not failed
MCHECK='bad=0; for f in clients/pqchat-core/runs/*-mutants.py; do [[ -e $f ]] || continue; python3 "$f" check || bad=1; done; exit $bad'

# step | directory | command (run with bash -c from the directory)
STEPS=(
    "pqc-test|clients/pqchat-core|$cap cargo test $C"
    "pqc-clippy|clients/pqchat-core|$cap cargo clippy $C --all-targets -- -D warnings"
    "pqc-deny|clients/pqchat-core|$cap cargo deny check && $cap cargo audit"
    "pqc-tree|clients/pqchat-core|$cap cargo test $C --test deps"
    "pqc-reads|.|python3 -I clients/pqchat-core/runs/check_reads.py"
    "pqc-wasm|clients/pqchat-core|$cap cargo check $C --target wasm32-unknown-unknown"
    "pqc-vectors|clients/pqchat-core|$cap cargo test $C --features vectors --test vectors"
    "pqc-chain|clients/pqchat-core|$cap cargo test $C -- --ignored --test-threads 1 chain_"
    "pqc-e2e|clients/pqchat-core|$cap cargo test $C --test e2e -- --ignored --test-threads 1 --nocapture"
    "sdk-test|clients/scaas-sdk|$cap cargo test $C --features $F"
    "sdk-clippy|clients/scaas-sdk|$cap cargo clippy $C --all-targets --features $F,vectors -- -D warnings"
    "sdk-vectors|clients/scaas-sdk|$cap cargo test $C --features $F,vectors --test pqchat_keys"
    "ua-test|clients/ua-rs|$cap cargo test $C --features wallet,vectors"
    "ua-appcore|clients/ua-rs|$cap cargo clippy $C --all-targets --features app-core,vectors -- -D warnings && $cap cargo test $C --features app-core,vectors --test app_core --test pqchat_keys && python3 -I scripts/gen_app_refusals.py --check"
    "ck-test|clients/clientkeys|$cap npm test"
    "ck-vectors|clients/clientkeys|node scripts/pqchat-vectors.mjs && git diff --exit-code -- ../../smartcontracts/vectors/pqchat"
    "bind|.|bash clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gen.sh --check"
    "docs|.|python3 scripts/docs_check.py check && python3 scripts/test_docs_check.py"
    "mutants-check|.|$MCHECK"
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
            printf '%-12s %s: %s\n' "$n" "$d" "$c"
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

counts() { # the test counts of a log, by runner
    awk '/^test result:/ { for (i = 1; i <= NF; i++) { if ($(i+1) ~ /^passed/) p += $i; if ($(i+1) ~ /^failed/) f += $i; if ($(i+1) ~ /^ignored/) g += $i }; n++ }
       /^(# |ℹ )pass / { np += $3; nn++ } /^(# |ℹ )fail / { nf += $3 } /^(# |ℹ )skipped / { ns += $3 }
       /tests passed, .* tests failed out of/ { ct = $0; sub(/^.*% tests passed, /, "", ct) }
       /^[0-9:]+ \+[0-9]+/ { d = $2 }
       /^RESULT / { sub(/^RESULT /, ""); r = r (r ? "; " : "") $0 }
       END { o = "";
             if (n) o = sprintf("%d passed, %d failed, %d ignored (%d binaries)", p, f, g, n);
             if (nn) o = o (o ? "; " : "") sprintf("node: %d pass, %d fail, %d skipped", np, nf, ns);
             if (ct != "") o = o (o ? "; " : "") "ctest: " ct;
             if (d != "") o = o (o ? "; " : "") "dart: " d;
             if (r) o = o (o ? "; " : "") r;
             printf "%s", (o ? o : "-") }' "$1"
}

row() { # replace the step's summary row
    touch "$SUMMARY"
    grep -v "^$TASK | $1 |" "$SUMMARY" >"$SUMMARY.new" || true
    echo "$TASK | $1 | $2 | $3 | $4" >>"$SUMMARY.new"
    mv "$SUMMARY.new" "$SUMMARY"
}

worst=0
for s in "${WANT[@]}"; do
    IFS='|' read -r name dir cmd <<<"$(cmd_of "$s")"
    log=$R/2026-11-17-pqchat-core-$name.log
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
    if [[ -d $dir ]]; then
        (cd "$dir" && bash -c "$cmd") >>"$log" 2>&1
        rc=$?
    else
        echo "no directory $dir" >>"$log"
        rc=3
    fi
    kill "$hb" 2>/dev/null
    wait "$hb" 2>/dev/null
    echo "rc=$rc" >>"$log"
    n=$(counts "$log")
    # a summary row is the runner's record of a clean tree only; a dirty run keeps its log and prints its result
    if [[ $state == clean ]]; then row "$name" "$sha" "$rc" "$n"; else n="$n; tree dirty, no summary row"; fi
    if ((rc == 0)); then echo "[G] $name ok in $((SECONDS - t0)) s: $n"; else
        echo "[G] $name FAIL rc=$rc in $((SECONDS - t0)) s: $n (see $log)"
        worst=$rc
    fi
done
exit "$worst"
