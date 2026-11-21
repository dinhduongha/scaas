#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# The scaas-sdk build plan's gate runner (docs/superpowers/plans/2026-11-17-scaas-sdk.md, T0), from the worktree root:
#   clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gates.sh --list
#   clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gates.sh --only <step>[,<step>…] [--force]
# Each step writes clients/scaas-sdk/runs/2026-11-17-scaas-sdk-<step>.log (git-ignored; first line `# <step> at commit <sha>`,
# last `rc=<n>`) and, on a clean tree only, one row `step | commit | rc | counts` of 2026-11-17-scaas-sdk-summary.txt (no row is
# written by hand; notes are `#` lines). A step done (rc=0) at the same
# commit on a clean tree (no tracked change) is skipped unless --force. Heavy steps run through scripts/capped, in the
# foreground; the e2e at CAPPED_MEM=6G. Counts: cargo's `test result:` lines, node's `# pass` / `# fail`, ctest's summary,
# dart's last `+N` line. An unknown step exits 2 and writes nothing.
set -uo pipefail
W=$(git rev-parse --show-toplevel)
cd "$W" || exit 2
R=clients/scaas-sdk/runs
SUMMARY=$R/2026-11-17-scaas-sdk-summary.txt
export PATH="$HOME/.foundry/bin:$PATH"
C="--locked --offline ${J:--j2}"
cap="$W/scripts/capped"
F="vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots,app-core,pqchat-records,near,algorand,cosmos"
# with the test feature `vectors` (pqchat-core T1): built by clippy, run only by its own test (a `vectors` build refuses
# scaas-ua key handles until a test unlocks them, so the whole suite stays without it)
V="$F,vectors"
SETS_CMD=""
for s in n2048-kmax1024 n2560-kmax16384 n2816-kmax65536; do
    m="--no-default-features --features vault,account,wallet,pqz,pqz-set-$s"
    SETS_CMD+="$cap cargo check $C $m && $cap cargo test $C $m --test sets && "
done
SETS_CMD+="true"
# every mutant script loads (its `old` texts occur once); the stale records are printed, not failed (plan Global constraints)
MCHECK='python3 -I clients/scaas-sdk/runs/test_mutants_lib.py || exit 1; bad=0; for f in clients/scaas-sdk/runs/*-mutants.py; do python3 "$f" check || bad=1; done; exit $bad'

# step | directory | command (run with bash -c from the directory)
STEPS=(
    "sdk-test|clients/scaas-sdk|$cap cargo test $C --features $F"
    "sdk-min|clients/scaas-sdk|$cap cargo test $C --no-default-features --features vault,file-store"
    "sdk-sets|clients/scaas-sdk|$SETS_CMD"
    "sdk-clippy|clients/scaas-sdk|$cap cargo clippy $C --all-targets --features $V -- -D warnings"
    "sdk-vectors|clients/scaas-sdk|$cap cargo test $C --features $V --test pqchat_keys --test app_core_vault_rows"
    "sdk-e2e|clients/scaas-sdk|CAPPED_MEM=6G $cap cargo test $C --features $F --test e2e -- --ignored"
    "sdk-wasm|clients/scaas-sdk|$cap cargo check $C --target wasm32-unknown-unknown --no-default-features --features vault,account,wallet"
    "sdk-deny|clients/scaas-sdk|$cap cargo deny --all-features check && $cap cargo audit"
    "ua-test|clients/ua-rs|$cap cargo test $C"
    "ua-clippy|clients/ua-rs|$cap cargo clippy $C --all-targets -- -D warnings"
    "ck-test|clients/clientkeys|$cap npm test"
    "rpc-test|clients/scaas-rpc|$cap cargo test $C --all-features"
    "frb-dart|clients/ua-dart-frb|(cd rust && $cap cargo build $C) && $cap dart test --reporter expanded --no-color"
    "bind-dart|clients/scaas-sdk/bindings/dart|bash ./run.sh"
    "bind-gen|.|bash clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gen.sh --check"
    "bind-cpp|clients/scaas-sdk/bindings/cpp|$cap cmake -B build && $cap cmake --build build && cd build && $cap ctest --output-on-failure"
    "sdk-opaque|clients/scaas-sdk|$cap cargo test $C --features $F,opaque-calls --test wallet_ops"
    "ua-vectors|clients/ua-rs|$cap cargo clippy $C --all-targets --features vectors,roots -- -D warnings && $cap cargo test $C --features vectors,roots"
    "ua-appcore|clients/ua-rs|$cap cargo clippy $C --all-targets --features app-core,vectors -- -D warnings && $cap cargo test $C --features app-core,vectors --test app_core && python3 -I scripts/gen_app_refusals.py --check"
    "ua-verify-only|clients/ua-rs|$cap cargo test $C --no-default-features"
    "ua-wallet-rows|clients/ua-rs|$cap cargo test $C --features vectors --test pqz_wallet_rows -- --ignored --exact write_wallet_rows && git diff --exit-code -- ../../smartcontracts/vectors"
    "rpc-clippy|clients/scaas-rpc|$cap cargo clippy $C --all-targets --all-features -- -D warnings"
    "rpc-wasm|clients/scaas-rpc|$cap cargo check $C --target wasm32-unknown-unknown --no-default-features --features evm,node-client"
    "ua-c|clients/ua-c|$cap cargo clippy $C --all-targets -- -D warnings && $cap cargo build $C && $cap cargo test $C && python3 -m unittest tests.test_vectors"
    "ua-c-release|clients/ua-c|$cap cargo build $C --release"
    "ua-py|clients/ua-py|python3 -m unittest tests.test_vectors tests.test_wallet"
    "ua-go|clients/ua-go|go vet ./... && $cap env LD_LIBRARY_PATH=$W/clients/ua-c/target/release go test -count=1 ./..."
    "ua-cs|clients/ua-cs|$cap dotnet test Scaas.Ua.Tests; rc=\$?; dotnet build-server shutdown >/dev/null 2>&1; exit \$rc"
    "ua-cxx|clients/ua-cxx|$cap cargo clippy $C --all-targets -- -D warnings && $cap cmake -S . -B build -G Ninja && $cap cmake --build build && $cap ctest --test-dir build"
    "ffi|clients/scaas-sdk/ffi|$cap cargo clippy $C --all-targets -- -D warnings && $cap cargo test $C"
    "gas-gen|clients/scaas-sdk/gas|python3 -I generate.py --check && python3 -I test_generate.py"
    "docs|.|python3 scripts/docs_check.py check && python3 scripts/test_docs_check.py"
    "features|.|python3 scripts/check_test_features.py && cd clients/scaas-sdk && $cap cargo test $C --test feature_tree"
    "sdk-raw|clients/scaas-sdk|$cap cargo test $C --lib --features $F,native-networks,raw-native && $cap cargo clippy $C --all-targets --features $V,native-networks,raw-native -- -D warnings"
    "mutants-check|.|$MCHECK"
    # plan T22: the CLI `scaas`, its release build and its dev-profiles build (the CI job scaas-cli)
    "cli|clients/scaas-cli|$cap cargo test $C && $cap cargo test $C --features dev-profiles && $cap cargo clippy $C --all-targets --features dev-profiles -- -D warnings"
    # plan T22's gap (a): the SDK e2e's chain driven through the CLI (its own anvil, stopped after)
    "cli-e2e|clients/scaas-cli|$cap cargo test $C --features dev-profiles --test e2e -- --ignored"
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
    grep -v "^$1 |" "$SUMMARY" >"$SUMMARY.new" || true
    echo "$1 | $2 | $3 | $4" >>"$SUMMARY.new"
    mv "$SUMMARY.new" "$SUMMARY"
}

worst=0
for s in "${WANT[@]}"; do
    IFS='|' read -r name dir cmd <<<"$(cmd_of "$s")"
    log=$R/2026-11-17-scaas-sdk-$name.log
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
