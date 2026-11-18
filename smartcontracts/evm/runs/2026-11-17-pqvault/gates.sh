#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# The gates of the PqVault plan's Part R (docs/superpowers/plans/2026-11-17-pqvault.md), a copy of
# runs/2026-11-12-ua-mtx-merge-final-gate/gates.sh cut to Part R's steps, forge at -j 1. From the repository root:
#   sh smartcontracts/evm/runs/2026-11-17-pqvault/gates.sh <step> [<step> ...]
# GATE_TAG=<task> names the log directory (default r): runs/2026-11-17-pqvault/<tag>/<step>.log (git-ignored), ending with
# `rc=<n>`; a step whose log ends with `rc=0` is skipped (RERUN=1 runs it again; a red log is kept as <step>.red.log). One line
# per step on stdout and in <tag>/progress.log. Heavy commands go through scripts/capped, foreground, one at a time. The
# committed record is runs/2026-11-17-pqvault-summary.txt (task | step | commit | rc | counts). Steps:
#   forge-<dir>      FOUNDRY_TEST=test/<dir> at the default set (out/t66a-test-<dir>); forge-top: test/*.t.sol;
#                    forge-modules: the differential (out/t66b-legacy first) and Modules, Paths, Groups
#   uagas            forge test --isolate --match-path 'test/ua/{UAGas,UARegistryGroups}.t.sol' (AGENTS.md, the CI header)
#   size             size_gate.py --self-test; forge build src --sizes --json; size_gate.py against size-baseline.json
#   set-<set>-<dir>  the set-sensitive tests of test/<dir> at <set> (at-set.sh list), src/pqz/PqzSet.sol checked after
#   node-guard       scaas-node cargo test guard (the allow-list and PqChat row tests)
#   clientkeys, ua-rs-<cell>, ua-py, ua-go, ua-cs, ua-c, ua-cxx, ua-dart, ua-dart-frb, ua-qt   the clients' own tests (the
#                    CI header's commands; ua-rs per CI cell)
#   docs, docs-test, ci-guards
set -u
ROOT=$(cd "$(dirname "$0")/../../../.." && pwd)
cd "$ROOT"
EVM=smartcontracts/evm
HERE=$EVM/runs/2026-11-17-pqvault/${GATE_TAG:-r}
mkdir -p "$HERE" "$EVM/out"
C="$ROOT/scripts/capped"
export PATH="$HOME/.foundry/bin:$PATH"      # at-set.sh calls forge by name
L=$EVM/out/${GATE_LOCK:-pqvault-gates}.lock # GATE_LOCK: a second lane (never beside a set-* step: at-set.sh rewrites PqzSet.sol)
exec 9>"$L"
flock -n 9 || {
    echo "gates.sh: another run holds $L"
    exit 1
}

uars() { (cd clients/ua-rs && "$C" cargo clippy -j 2 --locked --all-targets "$@" -- -D warnings && "$C" cargo test -j 2 --locked "$@" $T); }

step() {
    case $1 in
        forge-top) # the files directly in test/, copied to a sibling directory (their `../src` imports hold); removed after
            (
                cd $EVM && rm -rf test-pv-top && mkdir test-pv-top && cp test/*.t.sol test-pv-top/ && FOUNDRY_TEST=test-pv-top \
                    FOUNDRY_SCRIPT=test-pv-top FOUNDRY_OUT=out/t66b-top FOUNDRY_CACHE_PATH=cache/t66b-top "$C" forge test -j 1
                r=$?
                rm -rf test-pv-top
                exit $r
            ) ;;
        forge-modules)
            (cd $EVM && { [ -f out/t66b-legacy/dex.json ] || python3 script/modules/legacy_artifacts.py build; } && FOUNDRY_TEST=test/modules \
                FOUNDRY_SCRIPT=test/modules FOUNDRY_OUT=out/t66a-test-modules FOUNDRY_CACHE_PATH=cache/t66a-test-modules "$C" forge test -j 1 \
                --match-contract '^(Diff|Modules|Paths|Groups)')
            ;;
        forge-*)
            d=test/${1#forge-}
            n=t66a-test-${1#forge-}
            (cd $EVM && FOUNDRY_TEST=$d FOUNDRY_SCRIPT=$d FOUNDRY_OUT=out/$n FOUNDRY_CACHE_PATH=cache/$n "$C" forge test -j 1)
            ;;
        uagas)
            (cd $EVM && FOUNDRY_TEST=test/ua FOUNDRY_SCRIPT=test/ua FOUNDRY_OUT=out/t66a-test-ua FOUNDRY_CACHE_PATH=cache/t66a-test-ua \
                "$C" forge test -j 1 --isolate --match-path 'test/ua/{UAGas,UARegistryGroups}.t.sol' -vv)
            ;;
        size)
            (cd $EVM && python3 ../../scripts/size_gate.py --self-test && mkdir -p out/pv-sizes && FOUNDRY_OUT=out FOUNDRY_CACHE_PATH=cache \
                "$C" forge build -j 1 src --sizes --json >out/pv-sizes/sizes.json && python3 ../../scripts/size_gate.py out/pv-sizes/sizes.json size-baseline.json)
            ;;
        set-*) # set-<set>-<dir>: the set-sensitive tests of test/<dir> (at-set.sh list), test/<dir> alone in the compile set (the whole
            # sensitive list in one compile was OOM-killed at 4 GB)
            s=$(echo "$1" | cut -d- -f2-3)
            d=$(echo "$1" | cut -d- -f4-)
            m=$(sh $EVM/script/pqz/at-set.sh x list | grep "^test/$d/" | paste -sd, -)
            [ -n "$m" ] || {
                echo "no set-sensitive test in test/$d"
                return 2
            }
            FOUNDRY_TEST=test/$d FOUNDRY_SCRIPT=test/$d "$C" $EVM/script/pqz/at-set.sh "$s" test -j 1 --match-path "{$m}"
            r=$?
            git diff --exit-code -- $EVM/src/pqz/PqzSet.sol || r=3
            return $r
            ;;
        node-guard) (cd scaas-node && "$C" cargo test -j 2 --lib guard) ;;
        clientkeys) (cd clients/clientkeys && "$C" npm test) ;;
        ua-rs-default) T= uars ;;
        ua-rs-vectors) T= uars --features vectors ;;
        ua-rs-verify-only) T= uars --no-default-features ;;
        ua-rs-pq) T="--test pq --test ua8" uars --no-default-features --features pq ;;
        ua-rs-wallet-mlock) T= uars --no-default-features --features wallet,mlock ;;
        ua-rs-signers) T="--test groups_verify" uars --no-default-features --features signers ;;
        ua-rs-json) T="--test json" uars --no-default-features --features json ;;
        ua-rs-zether-only) T="--lib --test facade_zether" uars --no-default-features --features wallet,zether,mlock ;;
        ua-rs-pqz-n2048) T="--lib --bin pqz-read --test pqz_read --test facade_pqz_state --test facade_pqz --test pqz_backup --test no_oracle" \
            uars --no-default-features --features wallet,zether,pqz,pqz-set-n2048-kmax1024,mlock ;;
        ua-c-release) (cd clients/ua-c && "$C" cargo build -j 2 --release --locked) ;; # ua-py, ua-go, ua-cs link it (CI header)
        ua-py) (cd clients/ua-py && python3 -m unittest tests.test_vectors tests.test_wallet) ;;
        ua-go) (cd clients/ua-go && "$C" go vet ./... && LD_LIBRARY_PATH=$PWD/../ua-c/target/release "$C" go test -count=1 ./...) ;;
        ua-cs) (
            cd clients/ua-cs && "$C" dotnet test Scaas.Ua.Tests
            r=$?
            dotnet build-server shutdown >/dev/null
            exit $r
        ) ;;
        ua-dart) (cd clients/ua-dart && "$C" dart analyze && "$C" dart test && "$C" dart test -p node &&
            "$C" dart run test/vectors_test.dart) ;;
        ua-c) (cd clients/ua-c && "$C" cargo clippy --locked --all-targets -- -D warnings && "$C" cargo build --locked &&
            "$C" cargo test --locked && cc -std=c99 -Wall -Wextra -Werror -Iinclude tests/smoke.c target/debug/libscaas_ua_c.a \
            -lpthread -ldl -lm -o target/smoke && target/smoke && python3 -m unittest -v tests.test_vectors) ;;
        ua-cxx) (cd clients/ua-cxx && "$C" cargo clippy --locked --all-targets -- -D warnings && "$C" sh -c \
            'cmake -S . -B build -G Ninja > /dev/null && cmake --build build && ctest --test-dir build --output-on-failure') ;;
        ua-qt) (
            Q=$HOME/usr/Qt/6.12.0/gcc_64
            cd clients/ua-qt && QMAKE=$Q/bin/qmake6 LD_LIBRARY_PATH=$Q/lib QT_QPA_PLATFORM=offscreen \
                "$C" sh -c "cmake -S . -B build -G Ninja -DCMAKE_PREFIX_PATH=$Q > /dev/null && cmake --build build -j2 && ctest --test-dir build --output-on-failure"
        ) ;;
        ua-dart-frb) (cd clients/ua-dart-frb && "$C" dart pub get --enforce-lockfile && "$C" cargo build --locked \
            --manifest-path rust/Cargo.toml && "$C" dart test) ;;
        docs) python3 scripts/docs_check.py check ;;
        docs-test) python3 scripts/test_docs_check.py ;;
        ci-guards) ! git grep -nE '/[t]mp/' -- . ':!*/legacy/*' ':!docs/history/*' ;;
        *)
            echo "unknown step $1"
            return 2
            ;;
    esac
}

for st in "$@"; do
    log=$HERE/$st.log
    if [ "${RERUN:-0}" != 1 ] && [ -f "$log" ] && tail -1 "$log" | grep -qx 'rc=0'; then
        echo "$st: done"
        continue
    fi
    [ ! -f "$log" ] || mv "$log" "$HERE/$st.red.log"
    echo "$(date +%H:%M:%S) $st: start" | tee -a $HERE/progress.log
    {
        step "$st"
        echo "rc=$?"
    } >"$log" 2>&1
    line="$(date +%H:%M:%S) $st: $(tail -1 "$log") | $(grep -aE '^Ran |^test result|tests? (passed|failed)|passed|^## summary|errors?,|^# (pass|fail)' "$log" | tail -2 | tr '\n' ' ' | cut -c1-220)"
    echo "$line" | tee -a $HERE/progress.log
done
