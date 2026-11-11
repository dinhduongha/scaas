#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# The stacked final gate of rounds 3r + 3s + 3t on branch ua-mtx-3t: every broad check once, before the one merge into
# ua-mtx-merge (owner 2026-11-11: each round ran its targeted tests only). From the repository root:
#   CAPPED_SLOTS=3 sh smartcontracts/evm/runs/2026-11-11-stacked-gate/gates.sh <step> [<step> ...]
# Each step logs to <step>.log here (git-ignored) and ends it with `rc=<n>`; a step whose log ends with `rc=0` is skipped
# (RERUN=1 runs it again; a red log is kept as <step>.red.log). One line per step on stdout and in progress.log (start, the
# result and its counts). Heavy commands go through scripts/capped, foreground, one at a time. The committed record is
# summary.txt here (step | commit | rc | counts). Steps:
#   forge-<dir>       FOUNDRY_TEST=test/<dir> at the default set (out/t66a-test-<dir>); forge-top: test/*.t.sol;
#                     forge-modules: the differential (out/t66b-legacy first) and Modules, Paths, Groups
#   liquidity-mldsa   the CI clientkeys job's ffi case (DexLiquidityMldsa with clientkeys' ML-DSA-65)
#   size              size_gate.py --self-test; forge build src --sizes --json; size_gate.py against size-baseline.json
#   gen               gen_faces.py --check, gen_set.py --all --check, the on-chain scripts' Python parses, test_vcheck.py
#   set-<set>-<dir>   test/<dir> at one PQZ set (script/pqz/at-set.sh), src/pqz/PqzSet.sol checked byte-equal after
#   legacy-<set>      legacy-at-set.sh: the modules differential's pre-split side at <set> (legacy-default: back)
#   node-test, node-clippy, node-e2e   scaas-node (CAPPED_MEM=6G; e2e alone, --test-threads=1); node-flaky: the soroban
#                     timing unit test alone (flaky under load)
#   pq-build, e2e-self-test   pqz_prove and out/t66b-e2e for the matrix PQ groups; e2e.py --self-test on that build
#   clientkeys, ua-rs, ua-py, ua-go, ua-c, ua-cxx, ua-cs, ua-dart, ua-dart-frb, ua-qt, zether-prover, zether-cross,
#   verifier, verifier-clippy          the clients' own tests (the CI header's commands)
#   docs, docs-facts, docs-paths, docs-test, ci-guards
#   matrix            script/onchain/matrix.sh local (it puts itself under scripts/capped; the PQ groups on a local
#                     Nethermind copy under scratchpad/, docker, its compose file caps each container)
#   release-gas       release-gas.sh here: anvil at a 60 M block gas limit, deploy.sh evm with every option (public gate)
#   release-probe     every body module and face of the 12 kinds, asked = (regular + state) x 1.05 (the 3p probe)
#   pqchat            pqchat.sh here: the PqChat on-chain group (not a matrix.sh group) as 3c T95 ran it, on its own anvil
#   (matrix and pqchat write under onchain/ here: MATRIX_OUT)
set -u
ROOT=$(cd "$(dirname "$0")/../../../.." && pwd)
cd "$ROOT"
EVM=smartcontracts/evm
HERE=$EVM/runs/2026-11-11-stacked-gate
C="$ROOT/scripts/capped"
export CAPPED_SLOTS=${CAPPED_SLOTS:-3}
export PATH="$HOME/.foundry/bin:$PATH" # at-set.sh and matrix.sh call forge / anvil / cast by name
exec 9> "$EVM/out/stacked-gate.lock"
flock -n 9 || { echo "gates.sh: another run holds $EVM/out/stacked-gate.lock"; exit 1; }

step() {
  case $1 in
    forge-top) # the files directly in test/, copied to a sibling directory (their `../src` imports hold); removed after
      (cd $EVM && rm -rf test-sg-top && mkdir test-sg-top && cp test/*.t.sol test-sg-top/ && FOUNDRY_TEST=test-sg-top \
        FOUNDRY_SCRIPT=test-sg-top FOUNDRY_OUT=out/t66b-top FOUNDRY_CACHE_PATH=cache/t66b-top "$C" forge test -j 2; r=$?
        rm -rf test-sg-top; exit $r) ;;
    forge-modules)
      (cd $EVM && { [ -f out/t66b-legacy/dex.json ] || python3 script/modules/legacy_artifacts.py build; } && FOUNDRY_TEST=test/modules \
        FOUNDRY_SCRIPT=test/modules FOUNDRY_OUT=out/t66a-test-modules FOUNDRY_CACHE_PATH=cache/t66a-test-modules "$C" forge test -j 2 \
        --match-contract '^(Diff|Modules|Paths|Groups)') ;;
    forge-*) d=test/${1#forge-}; n=t66a-test-${1#forge-}
      (cd $EVM && FOUNDRY_TEST=$d FOUNDRY_SCRIPT=$d FOUNDRY_OUT=out/$n FOUNDRY_CACHE_PATH=cache/$n "$C" forge test -j 2) ;;
    liquidity-mldsa)
      (cd $EVM && MLDSA_CLIENTKEYS=../../clients/clientkeys FOUNDRY_TEST=test/liquidity FOUNDRY_SCRIPT=test/liquidity \
        FOUNDRY_OUT=out/t66a-test-liquidity FOUNDRY_CACHE_PATH=cache/t66a-test-liquidity "$C" forge test -j 2 --ffi \
        --match-path test/liquidity/DexLiquidityMldsa.t.sol -vv) ;;
    size)
      (cd $EVM && python3 ../../scripts/size_gate.py --self-test && mkdir -p out/sg-sizes && FOUNDRY_OUT=out FOUNDRY_CACHE_PATH=cache \
        "$C" forge build src --sizes --json > out/sg-sizes/sizes.json && python3 ../../scripts/size_gate.py out/sg-sizes/sizes.json size-baseline.json) ;;
    gen) (cd $EVM && python3 script/modules/gen_faces.py --check && python3 -I ../../pqz-core/params/sets/gen_set.py --all --check \
        && python3 -c "import ast, sys; [ast.parse(open(f).read(), f) for f in sys.argv[1:]]" script/onchain/*.py script/pqz/e2e.py \
        && python3 script/onchain/test_vcheck.py) ;;
    set-*) s=$(echo "$1" | cut -d- -f2-3); dd=$(echo "$1" | cut -d- -f4-); d=test/$dd; m=
      [ "$dd" != modules ] || m="--match-contract ^(Diff|Modules|Paths|Groups)"
      # top: test/*.t.sol in a sibling copy, as forge-top (removed after)
      [ "$dd" != top ] || { d=test-sg-top; rm -rf $EVM/$d && mkdir $EVM/$d && cp $EVM/test/*.t.sol $EVM/$d/; }
      FOUNDRY_TEST=$d FOUNDRY_SCRIPT=$d "$C" $EVM/script/pqz/at-set.sh "$s" test -j 2 $m; r=$?
      [ "$dd" != top ] || rm -rf $EVM/test-sg-top
      git diff --exit-code -- $EVM/src/pqz/PqzSet.sol || r=3
      return $r ;;
    node-test) (cd scaas-node && CAPPED_MEM=6G "$C" cargo test -j 2 --lib) ;;
    node-clippy) (cd scaas-node && CAPPED_MEM=6G "$C" cargo clippy -j 2 --all-targets -- -D warnings) ;;
    node-e2e) (cd scaas-node && CAPPED_MEM=6G "$C" cargo test -j 2 --test e2e -- --ignored --test-threads=1) ;;
    node-flaky) (cd scaas-node && CAPPED_MEM=6G "$C" cargo test -j 2 --lib -- failing_jobs_open_the_budget_and_later_jobs_do_not_send) ;;
    pq-build) # the matrix's PQ groups: pqz_prove (pqz-ffi, feature prove) and a build at the default set in out/t66b-e2e
      (cd pqz-core/ffi && "$C" cargo build -j 2 --release --features prove --example pqz_prove) && (cd $EVM && \
        FOUNDRY_OUT=out/t66b-e2e FOUNDRY_CACHE_PATH=cache/t66b-e2e "$C" forge build src test/helpers/Mocks.sol \
        script/onchain/OnchainForwarder.sol) ;;
    e2e-self-test) (cd $EVM && EVM_OUT=out/t66b-e2e python3 script/pqz/e2e.py --self-test) ;;
    verifier) (cd scaas-pqz-verifier && "$C" cargo test -j 2) ;;
    verifier-clippy) (cd scaas-pqz-verifier && "$C" cargo clippy -j 2 --all-targets -- -D warnings) ;;
    clientkeys) (cd clients/clientkeys && "$C" npm test) ;;
    ua-rs) (cd clients/ua-rs && "$C" cargo test -j 2 && "$C" cargo clippy -j 2 --all-targets -- -D warnings \
        && "$C" cargo test -j 2 --features signers && "$C" cargo test -j 2 --features json && "$C" cargo test -j 2 --features pq) ;;
    ua-py) (cd clients/ua-py && python3 -m unittest tests.test_vectors) ;;
    ua-go) (cd clients/ua-go && "$C" go vet ./... && "$C" go test ./...) ;;
    ua-cs) (cd clients/ua-cs && "$C" dotnet test Scaas.Ua.Tests; r=$?; dotnet build-server shutdown > /dev/null; exit $r) ;;
    ua-dart) (cd clients/ua-dart && "$C" dart analyze && "$C" dart test && "$C" dart test -p node \
        && "$C" dart run test/vectors_test.dart) ;;
    ua-c) (cd clients/ua-c && "$C" cargo clippy --locked --all-targets -- -D warnings && "$C" cargo build --locked \
        && "$C" cargo test --locked && cc -std=c99 -Wall -Wextra -Werror -Iinclude tests/smoke.c target/debug/libscaas_ua_c.a \
        -lpthread -ldl -lm -o target/smoke && target/smoke && python3 -m unittest -v tests.test_vectors) ;;
    ua-cxx) (cd clients/ua-cxx && "$C" cargo clippy --locked --all-targets -- -D warnings && "$C" sh -c \
        'cmake -S . -B build -G Ninja > /dev/null && cmake --build build && ctest --test-dir build --output-on-failure') ;;
    ua-qt) (Q=$HOME/usr/Qt/6.12.0/gcc_64; cd clients/ua-qt && QMAKE=$Q/bin/qmake6 LD_LIBRARY_PATH=$Q/lib QT_QPA_PLATFORM=offscreen \
        "$C" sh -c "cmake -S . -B build -G Ninja -DCMAKE_PREFIX_PATH=$Q > /dev/null && cmake --build build -j2 && ctest --test-dir build --output-on-failure") ;;
    ua-dart-frb) (cd clients/ua-dart-frb && "$C" dart pub get --enforce-lockfile && "$C" cargo build --locked \
        --manifest-path rust/Cargo.toml && "$C" dart test) ;;
    zether-prover) (cd clients/zether-prover && "$C" cargo test -j 2 && "$C" sh -c 'WASM_BINDGEN=wasm-bindgen ./wasm-smoke.sh') ;;
    zether-cross) (cd clients/zether-prover && "$C" cargo build -j 2 --release --bin zether-cli) && (cd $EVM && \
        ZETHER_CLI=$ROOT/clients/zether-prover/target/release/zether-cli FOUNDRY_TEST=test/zether FOUNDRY_SCRIPT=test/zether \
        FOUNDRY_OUT=out/t66a-test-zether FOUNDRY_CACHE_PATH=cache/t66a-test-zether "$C" forge test -j 2 --ffi \
        --match-path test/zether/ZetherProverCross.t.sol) ;;
    docs) python3 scripts/docs_check.py check ;;
    docs-facts) python3 scripts/docs_check.py facts check ;;
    docs-paths) python3 scripts/docs_check.py paths ;;
    docs-test) python3 scripts/test_docs_check.py ;;
    ci-guards) ! git grep -nE '/[t]mp/' -- . ':!*/legacy/*' ':!docs/history/*' ;;
    matrix) (cd $EVM && RPC_7622=http://127.0.0.1:9 COPY=$ROOT/scratchpad/stacked-gate-copy MATRIX_OUT=runs/2026-11-11-stacked-gate/onchain \
        sh script/onchain/matrix.sh local) ;;
    pqchat) (cd $EVM && MATRIX_OUT=runs/2026-11-11-stacked-gate/onchain "$C" sh runs/2026-11-11-stacked-gate/pqchat.sh) ;;
    legacy-*) sh $HERE/legacy-at-set.sh ${1#legacy-} ;; # out/t66b-legacy at a set (or default), for set-<set>-modules
    release-gas) "$C" sh $HERE/release-gas.sh ;;
    release-probe) (cd $EVM && FOUNDRY_TEST=runs/2026-11-10-ua-mtx-3p/probe FOUNDRY_SCRIPT=runs/2026-11-10-ua-mtx-3p/probe \
        FOUNDRY_OUT=out/sg-probe FOUNDRY_CACHE_PATH=cache/sg-probe "$C" forge test -j 2 --match-test test_3pModules -vv) ;;
    *) echo "unknown step $1"; return 2 ;;
  esac
}

for st in "$@"; do # not `s`: step() sets its own `s`
  log=$HERE/$st.log
  if [ "${RERUN:-0}" != 1 ] && [ -f "$log" ] && tail -1 "$log" | grep -qx 'rc=0'; then echo "$st: done"; continue; fi
  [ ! -f "$log" ] || mv "$log" "$HERE/$st.red.log"
  echo "$(date +%H:%M:%S) $st: start" | tee -a $HERE/progress.log
  { step "$st"; echo "rc=$?"; } > "$log" 2>&1
  line="$(date +%H:%M:%S) $st: $(tail -1 "$log") | $(grep -aE '^Ran |^test result|tests? (passed|failed)|passed|^## summary|errors?,' "$log" | tail -2 | tr '\n' ' ' | cut -c1-220)"
  echo "$line" | tee -a $HERE/progress.log
done
