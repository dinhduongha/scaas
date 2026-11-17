#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# ua-rs-native: the gates of branch ua-rs-native (plan 2026-11-17-ua-rs-native T1; Bitcoin P2WPKH / P2TR, NEAR, Polkadot sr25519
# and raw-message signing in ua-rs, the native vectors). Not a copy: it sets the step list, the log prefix, its own steps and test
# names, then runs 2026-10-27-metatx-split-gates.sh (the same step contract, resume, named-tests and summary), as
# 2026-11-07-ua-rs-sign-gates.sh. From the worktree root, foreground, one step per call:
#   smartcontracts/evm/runs/2026-11-17-ua-rs-native-gates.sh [--only <step>]      GATES_FRESH=1 re-runs a step that passed
# Step <s> writes runs/2026-11-17-ua-rs-native-<s>.log (git-ignored); `summary` writes the committed
# 2026-11-17-ua-rs-native-summary.txt. First line "# <s> at commit <sha>", last line "rc=<n>"; a step is skipped when its log ends
# rc=0 at the current commit and the tree is clean apart from runs/. Every step that writes a tracked file (vectors-check,
# test-features' positive control) ends with `git diff --exit-code` (runs/ aside). Heavy commands through scripts/capped, -j2,
# --locked --offline. The round touches wallet/mod.rs and the store, which every facade opens through: every ua-rs cell and every
# binding runs (AGENTS.md: full gates on shared changes). No forge step: no contract and no smartcontracts/vectors/ua change.
# Inputs: clients/clientkeys/node_modules as a real directory; NATIVE_DOWNLOADS (vectors-check): a directory holding the pinned
# downloads of native-vectors.mjs (each read only when its sha256 is the pinned one; the list: runs/2026-11-17-ua-rs-native-t0.md);
# QT (ua-qt, ua-sizes); ANDROID_NDK_HOME (ua-sizes). UNAUDITED.
P=${GATES_P:-2026-11-17-ua-rs-native}
LOGEXT=log # step logs are git-ignored (*.log); only <P>-summary.txt is committed (owner 2026-11-02)
STEPS=${STEPS-"docs clientkeys vectors-check ua-rs-nodefault ua-rs-wallet ua-rs ua-rs-vectors ua-rs-zether ua-rs-pqz no-oracle ua-deny ua-fuzz ua-sizes ua-c ua-cxx ua-qt ua-dart-frb ua-py ua-go ua-cs test-features mutant-logs named-tests summary"}
# the base runner's steps this round runs its own way (the CI cells)
OWN_STEPS="vectors-check ua-rs ua-c ua-dart-frb ua-py ua-go ua-cs"
# named-tests: no log of these may show a test binary with 0 passed or a skipped suite
FAMILIES="clientkeys ua-rs-nodefault ua-rs-wallet ua-rs ua-rs-vectors ua-rs-zether ua-rs-pqz no-oracle ua-c ua-cxx ua-qt ua-dart-frb ua-py ua-go ua-cs"
# the mutant records of this round (one per task that has mutants; extended per task)
MUTANT_RECORDS=${MUTANT_RECORDS-"2026-11-17-ua-rs-native-t2 2026-11-17-ua-rs-native-t3 2026-11-17-ua-rs-native-t4 2026-11-17-ua-rs-native-t5 2026-11-17-ua-rs-native-t6 2026-11-17-ua-rs-native-t6a 2026-11-17-ua-rs-native-t6b 2026-11-17-ua-rs-native-t7 2026-11-17-ua-rs-native-t8a 2026-11-17-ua-rs-native-t8b 2026-11-17-ua-rs-native-t9 2026-11-17-ua-rs-native-t10 2026-11-17-ua-rs-native-t11d 2026-11-17-ua-rs-native-t11e 2026-11-17-ua-rs-native-t11f"}
export CAPPED_MEM=${CAPPED_MEM:-4G} # 4G: capped's own default (the base sets 3G)
C="--locked --offline -j2"

cap() { "$W/scripts/capped" "$@"; }
uars() { # one ua-rs cell as CI runs it: clippy over every target, then the tests. Args: <features> [-- <test selection>]
  local f=(); while [ $# -gt 0 ] && [ "$1" != -- ]; do f+=("$1"); shift; done; [ $# -gt 0 ] && shift
  cd clients/ua-rs && cap cargo clippy $C --all-targets "${f[@]}" -- -D warnings && cap cargo test $C "${f[@]}" "$@"
}
release_ua_c() { cap cargo build --release $C --manifest-path clients/ua-c/Cargo.toml; } # what ua-py, ua-go, ua-cs load
clean() { git diff --exit-code --stat -- . ":(exclude)$R"; } # no tracked file moved (runs/: this runner's own files)

extra_step() { # this branch's own steps (the base runner calls it for a step it does not know, and for OWN_STEPS)
  case $1 in
    # each generator twice (clientkeys first, CLI-UAL-01; then ua-rs's both-ways file rs_native.json); the committed files must not
    # move, and smartcontracts/vectors/ua never moves in this round (spec §12.1)
    vectors-check) : "${NATIVE_DOWNLOADS:?NATIVE_DOWNLOADS: the pinned downloads (see the header)}"
      [ -f clients/clientkeys/scripts/native-vectors.mjs ] || { echo "vectors-check: not yet (native-vectors.mjs, plan T4)"; return 1; }
      local i
      for i in 1 2; do
        (cd clients/clientkeys && NATIVE_DOWNLOADS=$NATIVE_DOWNLOADS cap node scripts/native-vectors.mjs) || return 1
        (cd clients/ua-rs && cap cargo test $C --features vectors --test wallet_native -- --ignored regenerate) || return 1
        clean || return 1
      done
      git diff --exit-code --stat -- smartcontracts/vectors/ua ;;
    # the ua-rs cells of CI (MD-5, T18)
    ua-rs-nodefault) uars --no-default-features ;;
    ua-rs-wallet) uars --no-default-features --features wallet,mlock ;;
    ua-rs) uars ;;
    ua-rs-vectors) uars --features vectors ;;
    ua-rs-zether) uars --no-default-features --features wallet,zether,mlock -- --lib --test facade_zether ;;
    # PQZ without Zether at the committed set (the store's open runs under every facade)
    ua-rs-pqz) uars --no-default-features --features wallet,pqz,pqz-set-n2304-kmax4096,mlock -- --lib --bin pqz-read --test pqz_read \
                 --test facade_pqz_state --test facade_pqz --test facade_pqz_proof --test pqz_backup --test pqz_wallet_rows ;;
    # the oracle harness and the wallet rows at the default set (release cell, then vectors: the positive control)
    no-oracle) (cd clients/ua-rs && cap cargo test $C --test no_oracle --test pqz_wallet_rows &&
                cap cargo test $C --features vectors --test no_oracle --test pqz_wallet_rows) ;;
    # every lockfile over ua-rs resolves as committed; cargo deny by ua-rs/deny.toml; cargo audit with deny.toml's ignores (CI ua-deps)
    ua-deny) local m d ig
      for m in clients/ua-rs clients/ua-c clients/ua-cxx clients/ua-qt clients/ua-dart-frb/rust clients/ua-rs/fuzz clients/zether-prover scaas-node; do
        cap cargo tree --locked --offline -e normal --manifest-path "$m/Cargo.toml" > /dev/null || { echo "cargo tree --locked failed: $m"; return 1; }
      done
      (cd clients/ua-rs && cap cargo deny --all-features check) && (cd clients/ua-c && cap cargo deny --all-features --config ../ua-rs/deny.toml check) &&
        (cd clients/zether-prover && cap cargo deny --all-features --config ../ua-rs/deny.toml check) || return 1
      ig=$(python3 -I -c 'import tomllib; print(" ".join("--ignore " + a["id"] for a in tomllib.load(open("clients/ua-rs/deny.toml", "rb"))["advisories"]["ignore"]))')
      for d in clients/ua-rs clients/ua-c clients/zether-prover; do (cd "$d" && cap cargo audit $ig) || return 1; done ;;
    # T11's libFuzzer binary, then every target a short run over its seeds and regress/ inputs: no finding, no crash
    # (polkadot_path: plan T8b)
    ua-fuzz) local t o bad=0
      cap clients/ua-rs/fuzz/build.sh || return 1
      for t in typed_data expect tx vault manifest container sealed kem_pk mnemonic container_expect members accepted uasig zether_cmd pqz_cmd polkadot_path; do
        o=$(cap clients/ua-rs/fuzz/run.sh "$t" "${UA_FUZZ_SECONDS:-20}" "$P"); echo "== $t"; echo "$o"
        grep -qx '\[fuzz rc=0\]' <<< "$o" && ! grep -qE 'ua-fuzz FINDING|deadly signal|^SUMMARY|^==[0-9]+==ERROR' <<< "$o" || bad=1
      done; [ $bad = 0 ] ;;
    # MD-12's ratchet (T17): every row this host builds (measure resumes per row), check, and every baseline cell measured
    ua-sizes) local m=clients/ua-c/target/ua-sizes-$(git rev-parse --short HEAD).json
      python3 -I clients/ua-c/sizes.py selftest > /dev/null || { echo "sizes.py selftest failed"; return 1; }
      ANDROID_NDK_HOME=${ANDROID_NDK_HOME:-$HOME/usr/Android/sdk/ndk/29.0.13113456} LLVM_STRIP=${LLVM_STRIP:-llvm-strip-18} \
        LLVM_NM=${LLVM_NM:-llvm-nm-18} QMAKE=$QT/bin/qmake6 LD_LIBRARY_PATH=$QT/lib python3 -I clients/ua-c/sizes.py measure "$m" &&
        python3 -I clients/ua-c/sizes.py check "$m" || return 1
      python3 -I -c 'import json, sys; m, b = (json.load(open(f))["sizes"] for f in sys.argv[1:]); miss = sorted(set(b) - set(m))
print("baseline cells not measured:", miss or "none"); sys.exit(1 if miss else 0)' "$m" clients/ua-c/size-baseline.json ;;
    ua-c) (cd clients/ua-c && cap sh -c "cargo clippy $C --all-targets -- -D warnings && cargo build $C && cargo test $C &&
          cc -std=c99 -Wall -Wextra -Werror -Iinclude tests/smoke.c target/debug/libscaas_ua_c.a -lpthread -ldl -lm -o target/smoke &&
          target/smoke && c++ -fsyntax-only -x c++ include/scaas_ua.h" && python3 -m unittest -v tests.test_vectors &&
          cap tests/asan-smoke.sh) ;;
    # the binding's own Rust tests too, which CI's ua-dart-frb job does not run; dart -j 1 (named-tests)
    ua-dart-frb) cd clients/ua-dart-frb && cap sh -c "dart pub get --enforce-lockfile && cargo build $C --manifest-path rust/Cargo.toml &&
        cargo test $C --manifest-path rust/Cargo.toml && dart test -r expanded -j 1" ;;
    ua-py) release_ua_c && cd clients/ua-py && python3 -m unittest -v tests.test_vectors tests.test_wallet ;;
    # -count=1: Go's test cache does not recheck a file outside the module (the shared vectors)
    ua-go) release_ua_c && cd clients/ua-go &&
      cap sh -c 'go vet ./... && LD_LIBRARY_PATH=$PWD/../ua-c/target/release go test -count=1 -v ./...' ;;
    ua-cs) release_ua_c || return 1
      cd clients/ua-cs && cap dotnet test Scaas.Ua.Tests --logger 'console;verbosity=normal'; local rc=$?
      dotnet build-server shutdown > /dev/null 2>&1; return $rc ;; # VBCSCompiler would keep the capped slot
    # no test feature in a production artifact; positive control: ua-c with scaas-ua/vectors forced fails the check
    test-features) local m=clients/ua-c/Cargo.toml r
                   CARGO_NET_OFFLINE=true python3 -I scripts/check_test_features.py || return 1
                   sed -i 's/features = \["json", "wallet"\] }/features = ["json", "wallet", "vectors"] }/' $m
                   CARGO_NET_OFFLINE=true python3 -I scripts/check_test_features.py; r=$?
                   git checkout -q -- $m
                   echo "positive control (scaas-ua/vectors forced in $m): rc=$r (must be 1)"
                   [ $r = 1 ] && clean ;;
    # the round's mutant records: each ends with no survivor, and every harness still applies at this commit (`check`)
    mutant-logs) local t l bad=0
                 for t in $MUTANT_RECORDS; do
                   l=$(tail -n 1 smartcontracts/evm/runs/$t-mutants.txt); echo "$t: $l"
                   grep -Eq ' 0 survived, 0 not loaded$' <<< "$l" || bad=1
                   echo "$t check: $(python3 -I smartcontracts/evm/runs/$t-mutants.py check 2>&1 | tail -n 1)"
                   python3 -I smartcontracts/evm/runs/$t-mutants.py check > /dev/null 2>&1 || bad=1
                 done; [ $bad = 0 ] ;;
    *) echo "unknown step $1"; return 2 ;;
  esac
}

# "<step>|<form>|<name>": the tests this branch adds (forms: see the base runner); filled at T12
NEW_TESTS=$(cat <<'NAMES'
NAMES
)
. "$(dirname "$0")/2026-10-27-metatx-split-gates.sh"
