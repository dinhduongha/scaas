#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# The review-fix round's closing matrix (round-end gate, owner 2026-11-18), once, on the final tree, from the worktree root:
#   smartcontracts/evm/runs/2026-11-26-round-matrix.sh --list
#   smartcontracts/evm/runs/2026-11-26-round-matrix.sh --only <step>[,<step>…] [--force]
#   smartcontracts/evm/runs/2026-11-26-round-matrix.sh --group <evm|sets|node|pq|other> [--force]
# Pattern of 2026-11-18-prefreeze-matrix.sh. Each step writes scratchpad/2026-11-26-round-matrix/<step>.log (git-ignored;
# first line `# <step> at commit <sha>`, last `rc=<n>`) and one row `step | commit | rc | counts` of
# runs/2026-11-26-round-matrix-summary.txt. A step done (rc=0) at the same commit on a clean tree is skipped unless --force.
# Heavy commands go through scripts/capped in the foreground; at-set.sh without an outer capped (its lanes take their own
# slots); the node's suite and e2e at CAPPED_MEM=6G, alone (group node). Group pq starts the local Nethermind copy
# (pqz-core/nethermind/chain/copy.sh, image scaas/nethermind-pqz:2.2.0-pqz11, the compose file's mem_limit per container),
# never the live testnet stack, and stops it after. Progress lines every 30 s; no key is printed.
set -uo pipefail
W=$(git rev-parse --show-toplevel)
cd "$W" || exit 2
R=smartcontracts/evm/runs
M=2026-11-26-round-matrix
L=$W/scratchpad/$M
SUMMARY=$R/$M-summary.txt
mkdir -p "$L"
G=$(git rev-parse --path-format=absolute --git-common-dir)/.. # the main checkout: its scratchpad/tools (the pinned format tools)
export PATH="$G/scratchpad/tools/bin:$HOME/.foundry/bin:$PATH"
cap="$W/scripts/capped"
C="--locked -j1"
N="CAPPED_MEM=6G $cap"
Q=$HOME/usr/Qt/6.12.0/gcc_64
WB=${WASM_BINDGEN:-$G/scratchpad/tools/wasm-bindgen/bin/wasm-bindgen} # the crate's pin 0.2.130
SDKF=vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots,app-core,pqchat-records,near,algorand,cosmos,aptos,solana,soroban,sui,ton
FORGE_DIRS="account as confidential factory fork gas governance hedera liquidity merge metatx p6f pqchat pqvault pqz pqzh research
  ua v2 wallet wrap zether"
CS=$W/pqz-core/nethermind/chain
SIGNER=http://10.76.22.10:8545 # docker-compose.copy.yml's signer (no rate limit)

# forge at the committed set over test/<dir>, from an empty out/ and cache/ of its own
fdir() { echo "rm -rf out/m-$1 cache/m-$1 && FOUNDRY_TEST=test/$1 FOUNDRY_SCRIPT=test/$1 FOUNDRY_OUT=out/m-$1 FOUNDRY_CACHE_PATH=cache/m-$1 $cap forge test -j 1 ${2:-}"; }
# a fresh local copy (its own dir under the log dir), up, blocks produced; down on exit
copy_up() { echo "export COPY=$L/copy-\$(date +%s); mkdir -p \$COPY; sh $CS/copy.sh down >/dev/null 2>&1; trap 'sh $CS/copy.sh down' EXIT; sh $CS/copy.sh init && sh $CS/copy.sh genesis0 $CS/engine-pqz-provisional-n2304.json && python3 -I script/onchain/copygen.py \$COPY && sh $CS/copy.sh up scaas/nethermind-pqz:2.2.0-pqz11 genesis.pqz0.json && for i in \$(seq 180); do [ \"\$(cast block-number --rpc-url $SIGNER 2>/dev/null || echo 0)\" -ge 2 ] && break; [ \$i -lt 180 ] || { echo 'the copy produced no block'; exit 1; }; sleep 1; done && echo \"copy up: chain \$(cast chain-id --rpc-url $SIGNER)\""; }
# e2e.py's prover and its artifacts at the default set (matrix.sh's pq group)
pq_build() { echo "$cap sh -c 'cd ../../pqz-core/ffi && cargo build --release --locked -j 2 --features prove --example pqz_prove' && FOUNDRY_OUT=out/m-e2e FOUNDRY_CACHE_PATH=cache/m-e2e $cap forge build -j 1 src test/helpers/Mocks.sol script/onchain/OnchainForwarder.sol"; }
# every [outDir] clientkeys generator into a temp dir, each file compared with the committed one of its name (step vec-regen)
vregen() {
    local T bad=0 n=0 g f c
    declare -A VDIR=(["arweave"]="arweave|pqchat" ["pqvault"]=pqvault ["typed-ops"]=typed ["ua-portable"]=ua ["ua-sig"]=ua ["ua-wallet"]=ua ["registration-blob"]=ua)
    T=$(mktemp -d)
    for g in appcore arweave families id-display keystore keys native-tx pqvault registration-blob typed-ops ua-portable ua-sig ua ua-wallet; do
        mkdir -p "$T/$g"
        (cd clients/clientkeys && node "scripts/$g-vectors.mjs" "$T/$g" >/dev/null) || {
            echo "FAIL $g: generator rc"
            bad=1
            continue
        }
        for f in $(cd "$T/$g" && find . -type f | sed 's|^\./||'); do
            c=$(git ls-files smartcontracts/vectors | grep -E "(^|/)$f\$")
            # several of that name: the one in the generator's default directory
            [ "$(echo "$c" | grep -c .)" -le 1 ] || c=$(echo "$c" | grep -E "^smartcontracts/vectors/(${VDIR[$g]:-$g})/[^/]*\$")
            [ "$(echo "$c" | grep -c .)" = 1 ] || {
                echo "skip $g/$f: no unique committed file"
                continue
            }
            n=$((n + 1))
            if cmp -s "$T/$g/$f" "$c"; then echo "same $g/$f"; else
                echo "DIFF $g/$f vs $c"
                bad=1
            fi
        done
    done
    rm -rf "$T"
    echo "RESULT $n regenerated files compared, $([ $bad = 0 ] && echo all byte-identical || echo some differ)"
    return $bad
}
export -f vregen

# step | group | directory | command (bash -c from the directory)
STEPS=(
    "forge-top|evm|smartcontracts/evm|rm -rf test-m-top out/m-top cache/m-top && mkdir test-m-top && cp test/*.t.sol test-m-top/ && FOUNDRY_TEST=test-m-top FOUNDRY_SCRIPT=test-m-top FOUNDRY_OUT=out/m-top FOUNDRY_CACHE_PATH=cache/m-top $cap forge test -j 1; r=\$?; rm -rf test-m-top; exit \$r"
    "forge-modules|evm|smartcontracts/evm|rm -rf out/t66b-legacy && python3 script/modules/legacy_artifacts.py build && $(fdir modules)"
    "uagas|evm|smartcontracts/evm|rm -rf out/m-uagas cache/m-uagas && FOUNDRY_TEST=test/ua FOUNDRY_SCRIPT=test/ua FOUNDRY_OUT=out/m-uagas FOUNDRY_CACHE_PATH=cache/m-uagas $cap forge test -j 1 --isolate --match-path 'test/ua/{UAGas,UARegistryGroups}.t.sol' -vv"
    "clientkeys-mldsa|evm|smartcontracts/evm|export MLDSA_CLIENTKEYS=../../clients/clientkeys && $(fdir liquidity "--ffi --match-path test/liquidity/DexLiquidityMldsa.t.sol")"
    "size|evm|smartcontracts/evm|python3 ../../scripts/size_gate.py --self-test && rm -rf cache/m-sizes && mkdir -p out && FOUNDRY_OUT=out FOUNDRY_CACHE_PATH=cache/m-sizes $cap forge build -j 1 src --sizes --json > out/m-sizes.json && python3 ../../scripts/size_gate.py out/m-sizes.json size-baseline.json"
    "testnet-build|evm|smartcontracts/evm|rm -rf out/m-testnet cache/m-testnet && FOUNDRY_PROFILE=scaas-testnet FOUNDRY_OUT=out/m-testnet FOUNDRY_CACHE_PATH=cache/m-testnet $cap forge build -j 1 src script && echo RESULT src and script built"
    "sets-sensitive|sets|smartcontracts/evm|sh script/pqz/at-set.sh --clean others sensitive; r=\$?; git diff --exit-code -- src/pqz/PqzSet.sol || r=3; exit \$r"
    "sets-modules|sets|smartcontracts/evm|sh script/pqz/at-set.sh others modules; r=\$?; git diff --exit-code -- src/pqz/PqzSet.sol || r=3; exit \$r"
    "node-test|node|scaas-node|$N cargo test $C"
    "node-clippy|node|scaas-node|$cap cargo clippy $C --all-targets -- -D warnings"
    "node-e2e|node|scaas-node|(cd ../clients/zether-prover && $cap cargo build $C --release --bin zether-cli --features hazmat) && $N cargo test $C --test e2e -- --ignored --test-threads=1"
    "pq-e2e|pq|smartcontracts/evm|$(pq_build) && $(copy_up) && EVM_OUT=out/m-e2e DEPLOY_NAME=local-pq-testnet python3 -I script/pqz/e2e.py --rpc $SIGNER --log $L/pq-e2e-run.txt"
    "pq-offchain|pq|smartcontracts/evm|$(pq_build) && $(copy_up) && MATRIX_OUT=$L/pq-offchain-out EVM_OUT=out/m-e2e DEPLOY_NAME=local-pq-testnet python3 -I script/onchain/pq.py --net local --rpc $SIGNER --offchain"
    "clientkeys|other|clients/clientkeys|$cap npm test"
    "ua-rs-app-core-vectors|other|clients/ua-rs|$cap cargo clippy $C --all-targets --features app-core,vectors -- -D warnings && $cap cargo test $C --all-targets --features app-core,vectors"
    "ua-rs-groups-regen|other|clients/ua-rs|$cap cargo test $C --features vectors --test groups -- --ignored write_groups_json && git diff --exit-code -- ../../smartcontracts/vectors/ua/groups.json && echo RESULT groups.json regenerated byte-identical"
    "ua-rs-wasm-falcon|other|clients/ua-rs/tests/fndsa/wasm|WASM_BINDGEN=$WB ./run.sh"
    "pqchat-core|other|clients/pqchat-core|$cap cargo clippy $C --all-targets --features vectors -- -D warnings && $cap cargo test $C --features vectors"
    "pqvault-core|other|clients/pqvault-core|$cap cargo clippy $C --all-targets --features vectors -- -D warnings && $cap cargo test $C --features vectors"
    "scaas-sdk|other|clients/scaas-sdk|$cap cargo test $C --features $SDKF && $cap cargo test $C --features $SDKF,vectors --test pqchat_keys --test app_core_vault_rows && $cap cargo clippy $C --all-targets --features $SDKF,vectors,native-networks,raw-native -- -D warnings && python3 -I gas/generate.py --check && python3 -I gas/test_generate.py && echo RESULT gas table in sync"
    "scaas-cli|other|clients/scaas-cli|$cap cargo test $C && $cap cargo test $C --features dev-profiles && $cap cargo clippy $C --all-targets --features dev-profiles -- -D warnings"
    "zether-prover|other|clients/zether-prover|$cap cargo clippy $C --all-targets -- -D warnings && $cap cargo clippy $C --all-targets --features hazmat -- -D warnings && $cap cargo test $C && $cap cargo test $C --features hazmat"
    "ua-c|other|clients/ua-c|$cap cargo clippy $C --all-targets -- -D warnings && $cap cargo build $C && $cap cargo test $C && cc -std=c99 -Wall -Wextra -Werror -Iinclude tests/smoke.c target/debug/libscaas_ua_c.a -lpthread -ldl -lm -o target/smoke && target/smoke && python3 -m unittest -v tests.test_vectors && $cap tests/asan-smoke.sh && $cap cargo build $C --release"
    "ua-py|other|clients/ua-py|python3 -m unittest tests.test_vectors tests.test_wallet"
    "ua-go|other|clients/ua-go|$cap go vet ./... && LD_LIBRARY_PATH=\$PWD/../ua-c/target/release $cap go test -count=1 ./..."
    "ua-cs|other|clients/ua-cs|$cap dotnet test Scaas.Ua.Tests; r=\$?; dotnet build-server shutdown >/dev/null; exit \$r"
    "ua-cxx|other|clients/ua-cxx|$cap cargo clippy $C --all-targets -- -D warnings && $cap sh -c 'cmake -S . -B build -G Ninja > /dev/null && cmake --build build -j2 && ctest --test-dir build --output-on-failure'"
    "ua-qt|other|clients/ua-qt|QMAKE=$Q/bin/qmake6 LD_LIBRARY_PATH=$Q/lib QT_QPA_PLATFORM=offscreen $cap sh -c 'cmake -S . -B build -G Ninja -DCMAKE_PREFIX_PATH=$Q > /dev/null && cmake --build build -j2 && ctest --test-dir build --output-on-failure'"
    "ua-dart|other|clients/ua-dart|$cap dart pub get && $cap dart analyze && $cap dart test && $cap dart test -p node && $cap dart run test/vectors_test.dart"
    "ua-dart-frb|other|clients/ua-dart-frb|$cap dart pub get --enforce-lockfile && $cap cargo build $C --manifest-path rust/Cargo.toml && $cap cargo test $C --manifest-path rust/Cargo.toml && $cap dart test"
    "fam-soroban|other|.|$cap smartcontracts/scripts/test.sh soroban"
    "vec-check|other|.|set -e; (cd clients/clientkeys && for g in pqchat pqz3k pqz-leaf soroban-ua-ops; do node scripts/\$g-vectors.mjs --check; echo RESULT \$g --check ok; done); for g in metatx/gen_servicepull ua/gen_liquidity wraplimits/gen_wraplimits pqz/pqz_kat; do python3 -I smartcontracts/vectors/\$g.py --check; echo RESULT \$g --check ok; done; python3 -I pqz-core/params/sets/gen_set.py --all --check && python3 -I pqz-core/pqzl/params/to_rust.py --check && python3 -I smartcontracts/evm/script/pqz/gas-inputs.py --check && echo RESULT generated set files and gas inputs in sync"
    "vec-regen|other|.|vregen"
    "features|other|.|python3 scripts/check_test_features.py"
    "docs|other|.|python3 scripts/docs_check.py check && python3 scripts/docs_check.py paths && python3 scripts/test_docs_check.py && echo RESULT docs ok"
    "ci-guards|other|.|! git grep -nE '(^|[^[:alnum:]_.-])/[t]mp/' -- . ':!*/legacy/*' ':!docs/history/*' && echo RESULT no temp path"
    "vendor|other|.|scripts/vendor.sh check"
    "format|other|.|scripts/format.sh --check"
)
for d in $FORGE_DIRS; do STEPS+=("forge-$d|evm|smartcontracts/evm|$(fdir "$d")"); done

cmd_of() {
    local s
    for s in "${STEPS[@]}"; do [[ ${s%%|*} == "$1" ]] && {
        echo "$s"
        return 0
    }; done
    return 1
}

WANT=()
case "${1:-}" in
    --list)
        for s in "${STEPS[@]}"; do
            IFS='|' read -r n g d c <<<"$s"
            printf '%-26s %-6s %s\n' "$n" "$g" "$d"
        done
        exit 0
        ;;
    --only) IFS=',' read -ra WANT <<<"${2:-}" ;;
    --group) for s in "${STEPS[@]}"; do
        IFS='|' read -r n g d c <<<"$s"
        [[ $g == "${2:-}" ]] && WANT+=("$n")
    done ;;
    *)
        echo "usage: $0 --list | --only <step>[,<step>…] [--force] | --group <evm|sets|node|pq|other> [--force]" >&2
        exit 2
        ;;
esac
[[ ${#WANT[@]} -gt 0 ]] || {
    echo "[M] no step (--list)" >&2
    exit 2
}
FORCE=${3:-}
for s in "${WANT[@]}"; do cmd_of "$s" >/dev/null || {
    echo "[M] no such step: $s (--list)" >&2
    exit 2
}; done

X=":!$SUMMARY"
clean() { git diff --quiet HEAD -- . "$X" && git diff --quiet --cached HEAD -- . "$X"; }

counts() { # forge suites, cargo `test result:` lines, node / dart / ctest / unittest / dotnet totals, or RESULT lines
    awk '/^test result:/ { for (i = 1; i <= NF; i++) { if ($(i+1) ~ /^passed/) p += $i; if ($(i+1) ~ /^failed/) f += $i; if ($(i+1) ~ /^ignored/) g += $i }; n++ }
       /^Suite result:/ { for (i = 1; i <= NF; i++) { if ($(i+1) ~ /^passed/) fp += $i; if ($(i+1) ~ /^failed/) ff += $i; if ($(i+1) ~ /^skipped/) fs += $i }; fn++ }
       /^# (pass|fail) [0-9]+/ || /^ℹ (pass|fail) [0-9]+/ || /tests passed, [0-9]+ tests failed/ || /^Ran [0-9]+ tests? in/ || /^[0-9:]+ \+[0-9]+.*All tests passed/ || /^Passed!|^Failed!/ || /^## summary/ { o = o (o ? "; " : "") $0 }
       /^RESULT / { sub(/^RESULT /, ""); r = r (r ? "; " : "") $0 }
       END { s = ""
             if (fn) s = sprintf("forge %d passed, %d failed, %d skipped (%d suites)", fp, ff, fs, fn)
             if (n) s = s (s ? "; " : "") sprintf("cargo %d passed, %d failed, %d ignored (%d binaries)", p, f, g, n)
             if (o) s = s (s ? "; " : "") o
             if (r) s = s (s ? "; " : "") r
             print (s ? s : "-") }' "$1" | cut -c1-400
}

row() { # replace the step's summary row (flock: two runner processes share the file)
    (
        flock 7
        touch "$SUMMARY"
        grep -v "^$1 |" "$SUMMARY" >"$SUMMARY.new" || true
        echo "$1 | $2 | $3 | $4" >>"$SUMMARY.new"
        sort -t'|' -k1,1 "$SUMMARY.new" >"$SUMMARY"
        rm -f "$SUMMARY.new"
    ) 7>"$L/summary-lock.log"
}

worst=0
for s in "${WANT[@]}"; do
    IFS='|' read -r name grp dir cmd <<<"$(cmd_of "$s")"
    sha=$(git rev-parse --short=9 HEAD)
    log=$L/$name.log
    if [[ $FORCE != --force && -f $log ]] && clean && [[ $(head -1 "$log") == "# $name at commit $sha" ]] && [[ $(tail -1 "$log") == rc=0 ]]; then
        echo "[M] $name: done at $sha (clean tree), skipped"
        continue
    fi
    state=clean
    clean || state=dirty
    echo "# $name at commit $sha" >"$log"
    echo "# tree $state; $dir" >>"$log"
    echo "[M] $(date +%H:%M:%S) $name start ($dir, tree $state)"
    t0=$SECONDS
    (while sleep 30; do echo "[M] $name running $((SECONDS - t0)) s"; done) &
    hb=$!
    (cd "$dir" && bash -c "$cmd") >>"$log" 2>&1
    rc=$?
    kill "$hb" 2>/dev/null
    wait "$hb" 2>/dev/null
    echo "rc=$rc" >>"$log"
    n=$(counts "$log")
    [[ $state == dirty ]] && n="$n; tree dirty"
    row "$name" "$sha" "$rc" "$n"
    if ((rc == 0)); then echo "[M] $(date +%H:%M:%S) $name ok in $((SECONDS - t0)) s: $n"; else
        echo "[M] $(date +%H:%M:%S) $name FAIL rc=$rc in $((SECONDS - t0)) s: $n (see scratchpad/$M/$name.log)"
        worst=$rc
    fi
done
exit "$worst"
