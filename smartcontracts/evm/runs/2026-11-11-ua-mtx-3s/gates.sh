#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# The gates of round 3s on branch ua-mtx-3s (KYC bit 28, the allow and deny lists in the token: CTR-GOV-24, spec 2026-11-10-token-lists), one step at a time,
# from the repository root:
#   CAPPED_SLOTS=3 sh smartcontracts/evm/runs/2026-11-11-ua-mtx-3s/gates.sh <step> [<step> ...]
# Each step logs to <step>.log here (git-ignored) and ends it with `rc=<n>`; a step whose log ends with `rc=0` is skipped
# (RERUN=1 runs it again). Heavy commands go through scripts/capped, foreground, one at a time. The committed record is
# summary.txt here (step | commit | rc | counts). Steps:
#   size                     forge build src --sizes, then scripts/size_gate.py
#   forge-<dir>              FOUNDRY_TEST=test/<dir> (out/t66a-test-<dir>, its cache; scripts only as imported); forge-top: test/*.t.sol
#   set-<set>-<dir>          test/<dir> at one PQZ set (script/pqz/at-set.sh), src/pqz/PqzSet.sol restored and checked
#   scripts                  forge build of Deploy.s.sol, DeploySend.s.sol and the on-chain scripts (Liquidity, WrapLimits, Misc, Dex, Gov, Tokens, PqChat, ZetherMore)
#   gen                      gen_faces.py --check, gen_set.py --all --check; the scripts' Python compiles, test_vcheck.py
#   node-test, node-clippy   scaas-node cargo test --lib / cargo clippy --all-targets -- -D warnings (CAPPED_MEM=6G, alone)
#   node-e2e                 cargo test --test e2e -- --ignored (CAPPED_MEM=6G, alone)
#   clientkeys, ua-rs, ua-py, ua-go, ua-cs, ua-dart, ua-c, ua-cxx, ua-qt, ua-dart-frb   the clients' own tests (the CI header's commands)
#   docs, docs-test, ci-guards
set -u
ROOT=$(cd "$(dirname "$0")/../../../.." && pwd)
cd "$ROOT"
EVM=smartcontracts/evm
HERE=$EVM/runs/2026-11-11-ua-mtx-3s
C="$ROOT/scripts/capped"
export PATH="$HOME/.foundry/bin:$PATH" # at-set.sh calls `forge` by name
# one run of this script at a time; `flock smartcontracts/evm/out/m3s-gates.lock true` waits for it (no polling loop)
exec 9> "$EVM/out/m3s-gates.lock"
flock -n 9 || { echo "gates.sh: another run holds $EVM/out/m3s-gates.lock"; exit 1; }

step() {
  case $1 in
    size) # the default out/: size_gate.py measures the libraries from out/<file>.sol/ next to the baseline
      (cd $EVM && mkdir -p out/m3s-sizes && FOUNDRY_OUT=out FOUNDRY_CACHE_PATH=cache "$C" forge build src \
        --sizes --json > out/m3s-sizes/sizes.json && python3 ../../scripts/size_gate.py out/m3s-sizes/sizes.json size-baseline.json) ;;
    forge-top) # the files directly in test/, copied to a sibling directory (their `../src` imports hold) so the compile set is
      # theirs alone (sparse mode over test/ was OOM-killed at 4 GB); the copy is removed after
      (cd $EVM && rm -rf test-m3s-top && mkdir test-m3s-top && cp test/*.t.sol test-m3s-top/ && FOUNDRY_TEST=test-m3s-top \
        FOUNDRY_SCRIPT=test-m3s-top FOUNDRY_OUT=out/t66b-top FOUNDRY_CACHE_PATH=cache/t66b-top "$C" forge test -j 2; r=$?
        rm -rf test-m3s-top; exit $r) ;;
    forge-modules) # T66b §10: the differential against the pre-split releases (out/t66b-legacy, legacy_artifacts.py build once);
      # the imported fixtures' own suites run in their own directories
      (cd $EVM && { [ -f out/t66b-legacy/dex.json ] || python3 script/modules/legacy_artifacts.py build; } && FOUNDRY_TEST=test/modules \
        FOUNDRY_SCRIPT=test/modules FOUNDRY_OUT=out/t66a-test-modules FOUNDRY_CACHE_PATH=cache/t66a-test-modules "$C" forge test -j 2 \
        --match-contract '^(Diff|Modules|Paths|Groups)') ;;
    liquidity-mldsa) # the CI clientkeys job's ffi case: an mldsa65 UA's two SCaaS inputs, signed by clientkeys' ML-DSA-65
      (cd $EVM && MLDSA_CLIENTKEYS=../../clients/clientkeys FOUNDRY_TEST=test/liquidity FOUNDRY_SCRIPT=test/liquidity \
        FOUNDRY_OUT=out/t66a-test-liquidity FOUNDRY_CACHE_PATH=cache/t66a-test-liquidity "$C" forge test -j 2 --ffi \
        --match-path test/liquidity/DexLiquidityMldsa.t.sol -vv) ;;
    forge-*) d=test/${1#forge-}; n=t66a-test-${1#forge-} # the T66a per-directory builds, reused incrementally
      (cd $EVM && FOUNDRY_TEST=$d FOUNDRY_SCRIPT=$d FOUNDRY_OUT=out/$n FOUNDRY_CACHE_PATH=cache/$n "$C" forge test -j 2) ;;
    set-*) s=$(echo "$1" | cut -d- -f2-3); d=test/$(echo "$1" | cut -d- -f4-)
      FOUNDRY_TEST=$d FOUNDRY_SCRIPT=$d "$C" $EVM/script/pqz/at-set.sh "$s" test -j 2; r=$?
      git diff --exit-code -- $EVM/src/pqz/PqzSet.sol || r=3
      return $r ;;
    scripts) (cd $EVM && FOUNDRY_OUT=out/m3s-scripts FOUNDRY_CACHE_PATH=cache/m3s-scripts "$C" forge build \
        script/Deploy.s.sol script/onchain/Liquidity.s.sol script/onchain/WrapLimits.s.sol script/onchain/Misc.s.sol \
        script/onchain/Dex.s.sol script/onchain/Gov.s.sol script/onchain/Tokens.s.sol script/onchain/PqChat.s.sol \
        script/onchain/ZetherMore.s.sol script/DeploySend.s.sol) ;;
    gen) (cd $EVM && python3 script/modules/gen_faces.py --check && python3 -I ../../pqz-core/params/sets/gen_set.py --all --check \
        && python3 -c "import ast, sys; [ast.parse(open(f).read(), f) for f in sys.argv[1:]]" script/onchain/basebook.py script/onchain/pq.py script/onchain/verifiers.py script/pqz/e2e.py \
        && python3 script/onchain/test_vcheck.py) ;;
    node-test) (cd scaas-node && CAPPED_MEM=6G "$C" cargo test -j 2 --lib) ;;
    node-clippy) (cd scaas-node && CAPPED_MEM=6G "$C" cargo clippy -j 2 --all-targets -- -D warnings) ;;
    node-e2e) (cd scaas-node && CAPPED_MEM=6G "$C" cargo test -j 2 --test e2e -- --ignored --test-threads=1) ;; # as CI: one at a time (22 tests in parallel were OOM-killed at 6 GB)
    clientkeys) (cd clients/clientkeys && "$C" npm test) ;;
    ua-rs) (cd clients/ua-rs && "$C" cargo test -j 2 && "$C" cargo clippy -j 2 --all-targets -- -D warnings \
        && "$C" cargo test -j 2 --features signers && "$C" cargo test -j 2 --features json && "$C" cargo test -j 2 --features pq) ;;
    ua-py) (cd clients/ua-py && python3 -m unittest tests.test_vectors) ;;
    ua-go) (cd clients/ua-go && "$C" go vet ./... && "$C" go test ./...) ;;
    ua-cs) (cd clients/ua-cs && "$C" dotnet test Scaas.Ua.Tests; r=$?; dotnet build-server shutdown > /dev/null; exit $r) ;;
    ua-dart) (cd clients/ua-dart && "$C" dart analyze && "$C" dart test && "$C" dart test -p node \
        && "$C" dart run test/vectors_test.dart) ;;
    ua-c) (cd clients/ua-c && "$C" cargo clippy --locked --all-targets -- -D warnings && "$C" cargo build --locked \
        && "$C" cargo test --locked && python3 -m unittest -v tests.test_vectors) ;;
    ua-cxx) (cd clients/ua-cxx && "$C" cargo clippy --locked --all-targets -- -D warnings && "$C" sh -c \
        'cmake -S . -B build -G Ninja > /dev/null && cmake --build build && ctest --test-dir build --output-on-failure') ;;
    ua-qt) (Q=$HOME/usr/Qt/6.12.0/gcc_64; cd clients/ua-qt && QMAKE=$Q/bin/qmake6 LD_LIBRARY_PATH=$Q/lib QT_QPA_PLATFORM=offscreen \
        "$C" sh -c "cmake -S . -B build -G Ninja -DCMAKE_PREFIX_PATH=$Q > /dev/null && cmake --build build -j2 && ctest --test-dir build --output-on-failure") ;;
    ua-dart-frb) (cd clients/ua-dart-frb && "$C" dart pub get --enforce-lockfile && "$C" cargo build --locked \
        --manifest-path rust/Cargo.toml && "$C" dart test) ;;
    docs) python3 scripts/docs_check.py check ;;
    docs-test) python3 scripts/test_docs_check.py ;;
    ci-guards) ! git grep -nE '/[t]mp/' -- . ':!*/legacy/*' ':!docs/history/*' ;;
    *) echo "unknown step $1"; return 2 ;;
  esac
}

for s in "$@"; do
  log=$HERE/$s.log
  if [ "${RERUN:-0}" != 1 ] && [ -f "$log" ] && tail -1 "$log" | grep -qx 'rc=0'; then echo "$s: done"; continue; fi
  { step "$s"; echo "rc=$?"; } > "$log" 2>&1
  echo "$s: $(tail -1 "$log") | $(grep -E '^Ran |^test result|^check:|passed|tests? (passed|failed)' "$log" | tail -2 | tr '\n' ' ' | cut -c1-200)"
done
