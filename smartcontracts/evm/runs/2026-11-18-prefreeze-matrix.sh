#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# The pre-freeze contract round's closing matrix (round-end gate, owner 2026-11-18), from the worktree root:
#   smartcontracts/evm/runs/2026-11-18-prefreeze-matrix.sh --list
#   smartcontracts/evm/runs/2026-11-18-prefreeze-matrix.sh --only <step>[,<step>…] [--force]
#   smartcontracts/evm/runs/2026-11-18-prefreeze-matrix.sh --group <evm|sets|other> [--force]
# FORMAT_PARTS limits the format step to those parts of scripts/format.sh (default every part).
# Each step writes smartcontracts/evm/runs/2026-11-18-prefreeze-matrix/<step>.log (git-ignored *.log; first line
# `# <step> at commit <sha>`, last `rc=<n>`) and one row `step | commit | rc | counts` of
# runs/2026-11-18-prefreeze-matrix-summary.txt. A step done (rc=0) at the same commit on a clean tree is skipped unless
# --force. Clean builds: step `clean` removes every build directory the steps use (forge out/ and cache/, each crate's
# target/, the CMake build/ trees, the family artifacts); each forge step also starts from its own empty out/ and cache/.
# Heavy commands go through scripts/capped in the foreground (the node's suite and e2e at CAPPED_MEM=6G, -j1). Two
# processes may run at once (two capped slots): group `evm` (forge at the committed set) beside group `other`; group
# `sets` (at-set.sh rewrites src/pqz/PqzSet.sol) runs alone, after both. Progress lines every 30 s; no key is printed.
set -uo pipefail
W=$(git rev-parse --show-toplevel)
cd "$W" || exit 2
R=smartcontracts/evm/runs
# MATRIX names a later round's log directory and summary (default this round's): MATRIX=2026-11-19-pr-a-matrix
M=${MATRIX:-2026-11-18-prefreeze-matrix}
L=$R/$M
SUMMARY=$R/$M-summary.txt
mkdir -p "$L"
export PATH="$HOME/.foundry/bin:$PATH"
cap="$W/scripts/capped"
C="--locked -j1"
N="CAPPED_MEM=6G $cap"
SETS="n2048-kmax1024 n2560-kmax16384 n2816-kmax65536"
FORGE_DIRS="account as confidential factory fork gas governance hedera liquidity merge metatx modules p6f pqchat pqz pqzh research
  ua v2 wallet wrap zether"
SET_DIRS="as governance metatx pqz pqzh research ua v2 wrap"
Q=$HOME/usr/Qt/6.12.0/gcc_64

# forge at the committed set over test/<dir>, from an empty out/ and cache/ of its own
fdir() { echo "rm -rf out/m-$1 cache/m-$1 && FOUNDRY_TEST=test/$1 FOUNDRY_SCRIPT=test/$1 FOUNDRY_OUT=out/m-$1 FOUNDRY_CACHE_PATH=cache/m-$1 $cap forge test -j 1 ${2:-}"; }
# the set-sensitive tests of test/<dir> at <set> (at-set.sh list), test/<dir> alone in the compile set; PqzSet.sol checked after
fset() { echo "m=\$(sh script/pqz/at-set.sh x list | grep '^test/$2/' | paste -sd, -) && rm -rf out/at-set-$1 cache/at-set-$1 && FOUNDRY_TEST=test/$2 FOUNDRY_SCRIPT=test/$2 $cap script/pqz/at-set.sh $1 test -j 1 --match-path \"{\$m}\"; r=\$?; git diff --exit-code -- src/pqz/PqzSet.sol || r=3; exit \$r"; }
uars() { echo "$cap cargo clippy $C --all-targets $1 -- -D warnings && $cap cargo test $C $1 ${2:-}"; }

# step | group | directory | command (bash -c from the directory)
STEPS=(
    "clean|other|.|rm -rf smartcontracts/evm/out smartcontracts/evm/cache scaas-node/target scaas-pqz-verifier/target clients/scaas-rpc/target clients/ua-rs/target clients/ua-c/target clients/ua-cxx/target clients/ua-cxx/build clients/ua-qt/target clients/ua-qt/build clients/zether-prover/target clients/ua-dart-frb/rust/target smartcontracts/cosmos/target smartcontracts/cosmos/artifacts smartcontracts/solana/target smartcontracts/near/target smartcontracts/soroban/target smartcontracts/ton/build && echo RESULT build directories removed"
    "forge-top|evm|smartcontracts/evm|rm -rf test-m-top out/m-top cache/m-top && mkdir test-m-top && cp test/*.t.sol test-m-top/ && FOUNDRY_TEST=test-m-top FOUNDRY_SCRIPT=test-m-top FOUNDRY_OUT=out/m-top FOUNDRY_CACHE_PATH=cache/m-top $cap forge test -j 1; r=\$?; rm -rf test-m-top; exit \$r"
    "forge-modules|evm|smartcontracts/evm|rm -rf out/t66b-legacy && python3 script/modules/legacy_artifacts.py build && $(fdir modules "--match-contract '^(Diff|Modules|Paths|Groups)'")"
    "uagas|evm|smartcontracts/evm|rm -rf out/m-uagas cache/m-uagas && FOUNDRY_TEST=test/ua FOUNDRY_SCRIPT=test/ua FOUNDRY_OUT=out/m-uagas FOUNDRY_CACHE_PATH=cache/m-uagas $cap forge test -j 1 --isolate --match-path 'test/ua/{UAGas,UARegistryGroups}.t.sol' -vv"
    "clientkeys-mldsa|evm|smartcontracts/evm|export MLDSA_CLIENTKEYS=../../clients/clientkeys && $(fdir liquidity "--ffi --match-path test/liquidity/DexLiquidityMldsa.t.sol")"
    "size|evm|smartcontracts/evm|python3 ../../scripts/size_gate.py --self-test && rm -rf cache/m-sizes && mkdir -p out && FOUNDRY_OUT=out FOUNDRY_CACHE_PATH=cache/m-sizes $cap forge build -j 1 src --sizes --json > out/m-sizes.json && python3 ../../scripts/size_gate.py out/m-sizes.json size-baseline.json"
    # the scaas-testnet profile over src/ and script/ (CI builds the whole tree at once, on a 16 GB runner; here one solc
    # over the 658 files was OOM-killed at 6 GB): test/ is compiled per directory by the forge-* cells, at the same settings
    "testnet-build|evm|smartcontracts/evm|rm -rf out/m-testnet cache/m-testnet && FOUNDRY_PROFILE=scaas-testnet FOUNDRY_OUT=out/m-testnet FOUNDRY_CACHE_PATH=cache/m-testnet $cap forge build -j 1 src script && echo RESULT src and script built"
    "gen-set|other|.|python3 -I pqz-core/params/sets/gen_set.py --all --check && python3 -I pqz-core/pqzl/params/to_rust.py --check && echo RESULT generated files in sync"
    "node-test|other|scaas-node|$N cargo test $C"
    "node-clippy|other|scaas-node|$cap cargo clippy $C --all-targets -- -D warnings"
    "node-e2e|other|scaas-node|(cd ../clients/zether-prover && $cap cargo build $C --release --bin zether-cli --features hazmat) && $N cargo test $C --test e2e -- --ignored --test-threads=1"
    # UA portable registration: a UA record copied EVM <-> Soroban on a local Protocol 30 host (round ua-portable-soroban)
    "node-e2e-ua-portable-soroban|other|.|smartcontracts/soroban/scripts/e2e-ua-portable-local.sh"
    "node-e2e-hedera|other|scaas-node|(cd ../smartcontracts/evm && $cap forge build test/hedera/HederaMocks.sol) && $N cargo test $C --test e2e_hedera -- --ignored --test-threads=1"
    "node-e2e-soroban|other|scaas-node|CARGO_BUILD_JOBS=2 $cap ../smartcontracts/scripts/build.sh soroban && ../smartcontracts/soroban/scripts/quickstart.sh up && trap '../smartcontracts/soroban/scripts/quickstart.sh down' EXIT && ../smartcontracts/soroban/scripts/quickstart.sh wait && $N cargo test $C --test e2e_soroban -- --ignored --test-threads=1 && $N cargo test $C --test e2e_soroban_ua -- --ignored --test-threads=1"
    "node-e2e-solana|other|scaas-node|CARGO_BUILD_JOBS=2 $cap ../smartcontracts/scripts/build.sh solana && $N bash -c \"../smartcontracts/solana/scripts/devnet.sh up --upgradeable-program BDo6exf1vzqX44BJc1WDf4Pw6sGZcxqmuVmQPfgUgS3d ../smartcontracts/solana/target/deploy/scaas.so 73VoVWyfxmaWC6gUjsse6xzNTLLoEhazMCcKakXWbebm --bpf-program A4PasPZEK899MesXpT3MSA4ufnpHcyfxjKuxRXmcZnRJ ../smartcontracts/solana/target/deploy/cpi_wrapper.so && trap '../smartcontracts/solana/scripts/devnet.sh down' EXIT && cargo test $C --test e2e_solana -- --ignored --test-threads=1\""
    "node-e2e-near|other|scaas-node|CARGO_BUILD_JOBS=2 $cap ../smartcontracts/scripts/build.sh near && (cd ../smartcontracts/near && $cap cargo test --no-run -j2) && $N cargo test $C --test e2e_near -- --ignored --test-threads=1"
    "node-e2e-algorand|other|scaas-node|D=../smartcontracts/scripts/devnet.sh; \$D algorand down >/dev/null 2>&1; trap '\$D algorand down >/dev/null 2>&1' EXIT; $cap \$D algorand up && $N cargo test $C --test e2e_algorand -- --ignored --test-threads=1"
    "node-e2e-aptos|other|scaas-node|D=../smartcontracts/move/aptos/scripts/devnet.sh; \$D down >/dev/null 2>&1; trap '\$D down >/dev/null 2>&1' EXIT; systemd-run --user --scope --quiet -p MemoryMax=3G -p MemorySwapMax=1G -- \$D up && $cap \$D publish && docker update --memory 2g --memory-swap 2g \$(docker ps -q --filter name=local-testnet) >/dev/null && $N cargo test $C --test e2e_aptos -- --ignored --test-threads=1"
    "node-e2e-sui|other|scaas-node|$N cargo test $C --test e2e_sui -- --ignored --test-threads=1"
    "node-e2e-ton|other|scaas-node|TD=../smartcontracts/ton; { [ -d \$TD/node_modules ] || (cd \$TD && $cap npm ci); } && (cd \$TD && $cap npx tact --config tact.config.json) && $N cargo test $C --test e2e_ton -- --ignored --test-threads=1"
    "node-e2e-cosmos|other|scaas-node|(cd ../smartcontracts/cosmos && $cap sh build-wasm.sh) && $N cargo test $C --test e2e_cosmos -- --ignored --test-threads=1"
    "rpc-test|other|clients/scaas-rpc|$cap cargo test $C --all-features"
    "rpc-clippy|other|clients/scaas-rpc|$cap cargo clippy $C --all-targets --all-features -- -D warnings"
    "rpc-anvil|other|clients/scaas-rpc|$cap cargo test $C --features evm --test anvil -- --ignored"
    "rpc-wasm|other|clients/scaas-rpc|$cap cargo check $C --target wasm32-unknown-unknown --no-default-features --features evm,node-client && ! git grep -n 'tokio::time' -- src && echo RESULT wasm32 check ok"
    "rpc-deny|other|clients/scaas-rpc|$cap cargo deny --all-features check"
    "ver-test|other|scaas-pqz-verifier|$cap cargo test $C"
    "ver-clippy|other|scaas-pqz-verifier|$cap cargo clippy $C --all-targets -- -D warnings"
    "ua-rs-default|other|clients/ua-rs|$(uars "")"
    "ua-rs-pqz-read|other|clients/ua-rs|ANVIL=$HOME/.foundry/bin/anvil $cap cargo test $C --test pqz_read --bin pqz-read -- --include-ignored"
    "ua-rs-vectors|other|clients/ua-rs|$(uars "--features vectors")"
    "ua-rs-wallet-rows|other|clients/ua-rs|$cap cargo test $C --features vectors --test pqz_wallet_rows -- --ignored --exact write_wallet_rows && git diff --exit-code -- ../../smartcontracts/vectors/pqz/n2304-kmax4096/wallet_state.json"
    "ua-rs-verify-only|other|clients/ua-rs|$(uars "--no-default-features")"
    "ua-rs-signers|other|clients/ua-rs|$(uars "--no-default-features --features signers" "--test groups_verify")"
    "ua-rs-json|other|clients/ua-rs|$(uars "--no-default-features --features json" "--test json")"
    "ua-rs-pq|other|clients/ua-rs|$(uars "--no-default-features --features pq" "--test pq --test ua8")"
    "ua-rs-wallet-mlock|other|clients/ua-rs|$(uars "--no-default-features --features wallet,mlock")"
    "ua-rs-zether-only|other|clients/ua-rs|$(uars "--no-default-features --features wallet,zether,mlock" "--lib --test facade_zether")"
    "ua-rs-pqz-n2048|other|clients/ua-rs|$(uars "--no-default-features --features wallet,zether,pqz,pqz-set-n2048-kmax1024,mlock" "--lib --bin pqz-read --test pqz_read --test facade_pqz_state --test facade_pqz --test pqz_backup --test no_oracle")"
    "ua-rs-pqz-n2048-vectors|other|clients/ua-rs|$(uars "--no-default-features --features wallet,zether,pqz,pqz-set-n2048-kmax1024,mlock,vectors" "--test facade_pqz_state --test facade_pqz --test pqz_backup --test no_oracle")"
    "clientkeys|other|clients/clientkeys|$cap npm test"
    "zp-clippy|other|clients/zether-prover|$cap cargo clippy $C --all-targets -- -D warnings && $cap cargo clippy $C --all-targets --features hazmat -- -D warnings"
    "zp-test|other|clients/zether-prover|$cap cargo test $C && $cap cargo test $C --features hazmat"
    "zp-wasm|other|clients/zether-prover|$cap ./wasm-smoke.sh && ZETHER_HAZMAT=1 $cap ./wasm-smoke.sh && echo RESULT wasm smoke default and hazmat ok"
    "zp-read-balance|other|clients/zether-prover|ANVIL=$HOME/.foundry/bin/anvil $cap cargo test $C --test read_balance --bin zether-read-balance -- --include-ignored && ANVIL=$HOME/.foundry/bin/anvil $cap cargo test $C --features hazmat --test read_balance --bin zether-read-balance -- --include-ignored"
    "ua-c|other|clients/ua-c|$cap cargo clippy $C --all-targets -- -D warnings && $cap cargo build $C && $cap cargo test $C && cc -std=c99 -Wall -Wextra -Werror -Iinclude tests/smoke.c target/debug/libscaas_ua_c.a -lpthread -ldl -lm -o target/smoke && target/smoke && python3 -m unittest -v tests.test_vectors && $cap tests/asan-smoke.sh"
    "ua-c-release|other|clients/ua-c|$cap cargo build $C --release && echo RESULT release library built"
    "ua-py|other|clients/ua-py|python3 -m unittest tests.test_vectors tests.test_wallet"
    "ua-go|other|clients/ua-go|$cap go vet ./... && LD_LIBRARY_PATH=\$PWD/../ua-c/target/release $cap go test -count=1 ./..."
    "ua-cs|other|clients/ua-cs|$cap dotnet test Scaas.Ua.Tests; r=\$?; dotnet build-server shutdown >/dev/null; exit \$r"
    "ua-cxx|other|clients/ua-cxx|$cap cargo clippy $C --all-targets -- -D warnings && $cap sh -c 'cmake -S . -B build -G Ninja > /dev/null && cmake --build build -j2 && ctest --test-dir build --output-on-failure'"
    "ua-qt|other|clients/ua-qt|QMAKE=$Q/bin/qmake6 LD_LIBRARY_PATH=$Q/lib QT_QPA_PLATFORM=offscreen $cap sh -c 'cmake -S . -B build -G Ninja -DCMAKE_PREFIX_PATH=$Q > /dev/null && cmake --build build -j2 && ctest --test-dir build --output-on-failure'"
    "ua-dart|other|clients/ua-dart|$cap dart analyze && $cap dart test && $cap dart test -p node && $cap dart run test/vectors_test.dart"
    "ua-dart-frb|other|clients/ua-dart-frb|$cap dart pub get --enforce-lockfile && $cap cargo build $C --manifest-path rust/Cargo.toml && $cap cargo test $C --manifest-path rust/Cargo.toml && $cap dart test"
    "fam-cosmos|other|.|$cap smartcontracts/scripts/test.sh cosmos"
    "fam-solana|other|.|$cap smartcontracts/scripts/test.sh solana"
    "fam-near|other|.|$cap smartcontracts/scripts/test.sh near"
    "docs|other|.|python3 scripts/docs_check.py check && python3 scripts/docs_check.py paths && python3 scripts/docs_check.py consumer && python3 scripts/docs_check.py facts check && python3 scripts/test_docs_check.py && echo RESULT docs ok"
    "features|other|.|python3 scripts/check_test_features.py"
    "ci-guards|other|.|! git grep -nE '/[t]mp/' -- . ':!*/legacy/*' ':!docs/history/*' && echo RESULT no temp path"
    "format|other|.|scripts/format.sh --check ${FORMAT_PARTS:-}"
)
for d in $FORGE_DIRS; do
    [ "$d" = modules ] || STEPS+=("forge-$d|evm|smartcontracts/evm|$(fdir "$d")")
done
for s in $SETS n2304-kmax4096; do
    STEPS+=("pqzvec-$s|sets|smartcontracts/evm|rm -rf out/at-set-$s cache/at-set-$s && FOUNDRY_TEST=test/pqz FOUNDRY_SCRIPT=test/pqz $cap script/pqz/at-set.sh $s test -j 1 --match-path test/pqz/PqzStateVectors.t.sol; r=\$?; git diff --exit-code -- src/pqz/PqzSet.sol || r=3; exit \$r")
done
for s in $SETS; do for d in $SET_DIRS; do STEPS+=("set-$s-$d|sets|smartcontracts/evm|$(fset "$s" "$d")"); done; done

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
            printf '%-28s %-6s %s\n' "$n" "$g" "$d"
        done
        exit 0
        ;;
    --only) IFS=',' read -ra WANT <<<"${2:-}" ;;
    --group) for s in "${STEPS[@]}"; do
        IFS='|' read -r n g d c <<<"$s"
        [[ $g == "${2:-}" && $n != clean ]] && WANT+=("$n")
    done ;;
    *)
        echo "usage: $0 --list | --only <step>[,<step>…] [--force] | --group <evm|sets|other> [--force]" >&2
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

sha=$(git rev-parse --short=9 HEAD)
X=":!$SUMMARY"
clean() { git diff --quiet HEAD -- . "$X" && git diff --quiet --cached HEAD -- . "$X"; }

counts() { # forge suites, cargo `test result:` lines, jest / dart / ctest / unittest / pytest totals, or RESULT lines
    awk '/^test result:/ { for (i = 1; i <= NF; i++) { if ($(i+1) ~ /^passed/) p += $i; if ($(i+1) ~ /^failed/) f += $i; if ($(i+1) ~ /^ignored/) g += $i }; n++ }
       /^Suite result:/ { for (i = 1; i <= NF; i++) { if ($(i+1) ~ /^passed/) fp += $i; if ($(i+1) ~ /^failed/) ff += $i; if ($(i+1) ~ /^skipped/) fs += $i }; fn++ }
       /^Tests: / || /tests passed, [0-9]+ tests failed/ || /^Ran [0-9]+ tests? in/ || /^[0-9]+ passed/ || /^Test result: / || /^[0-9:]+ \+[0-9]+.*All tests passed/ || /^Passed!|^Failed!/ { o = o (o ? "; " : "") $0 }
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
    ) 7>"$L/summary-lock.log" # a lock file, git-ignored as *.log
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
    echo "# tree $state; $dir: $cmd" >>"$log"
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
        echo "[M] $(date +%H:%M:%S) $name FAIL rc=$rc in $((SECONDS - t0)) s: $n (see $log)"
        worst=$rc
    fi
done
exit "$worst"
