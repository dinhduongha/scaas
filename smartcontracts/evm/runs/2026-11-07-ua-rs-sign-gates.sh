#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# ua-rs-sign T15i (T15l: the fix wave's mutants, `l-mutant-<n>`; every harness `check`ed by `mutant-logs`): the closing mechanical gates of the ARCH-POS-13 rework ("never a decryption oracle"; spec
# no-decryption-oracle §4.8, §5). From the worktree root, foreground, one step per call:
#   smartcontracts/evm/runs/2026-11-07-ua-rs-sign-gates.sh <step>      GATES_FRESH=1 re-runs a step that passed
#   smartcontracts/evm/runs/2026-11-07-ua-rs-sign-gates.sh steps       (the step list)
# Step <s> writes smartcontracts/evm/runs/2026-11-07-ua-rs-sign-<s>.log (git-ignored): first line "# <s> at commit <sha>", last
# line "rc=<n>". A step is skipped when its log ends rc=0 at the current commit and the tree is clean (resume per step). Every
# step that edits a file (the positive control of test-features, each mutant) ends with `git diff --exit-code`.
# Heavy commands go through scripts/capped. UNAUDITED.
set -u
cd "$(git rev-parse --show-toplevel)"
P=smartcontracts/evm/runs/2026-11-07-ua-rs-sign
H=$P-t15i-mutants.py
L=$P-t15l-mutants.py
CAP=scripts/capped
NMUT=$(python3 -I "$H" count)
LMUT=$(python3 -I "$L" count)
STEPS="no-oracle no-oracle-n2048 no-oracle-ua-py wallet-rows test-features mutant-logs $(seq -f 'mutant-%g' 1 "$NMUT" | tr '\n' ' ')$(seq -f 'l-mutant-%g' 1 "$LMUT" | tr '\n' ' ')rebuild"
CARGO="cargo test --locked --offline -j2"
N2048="--no-default-features --features wallet,zether,pqz,pqz-set-n2048-kmax1024,mlock"

step() {
  case $1 in
    # the oracle harness and the wallet rows at the default set (release cell, then vectors: the positive control)
    no-oracle) (cd clients/ua-rs && ../../$CAP $CARGO --test no_oracle --test pqz_wallet_rows &&
                ../../$CAP $CARGO --features vectors --test no_oracle --test pqz_wallet_rows) ;;
    no-oracle-n2048) (cd clients/ua-rs && ../../$CAP $CARGO $N2048 --test no_oracle &&
                      ../../$CAP $CARGO $N2048,vectors --test no_oracle) ;;
    # the same harness through the C ABI (the release library, which every binding but ua-cxx / ua-dart-frb / ua-qt loads)
    no-oracle-ua-py) $CAP cargo build --release --locked --offline -j2 --manifest-path clients/ua-c/Cargo.toml &&
                     (cd clients/ua-py && python3 -m unittest -v tests.test_wallet.Pqz.test_no_oracle) ;;
    # the rows' generator twice: the same bytes as committed
    wallet-rows) local f=smartcontracts/vectors/pqz/n2304-kmax4096/wallet_state.json a b
                 smartcontracts/vectors/pqz/gen_wallet_state.sh && a=$(sha256sum < $f) &&
                 smartcontracts/vectors/pqz/gen_wallet_state.sh && b=$(sha256sum < $f) &&
                 echo "sha256 $a / $b" && [ "$a" = "$b" ] && git diff --exit-code -- $f ;;
    # no test feature in a production artifact: the manifests and `cargo tree -e features` of ua-c (libscaas_ua_c: ua-py,
    # ua-go, ua-cs), ua-cxx, ua-qt, ua-dart-frb's crate and zether-prover (zether-read-balance); positive control: ua-c with
    # scaas-ua/vectors forced fails the check (both the manifest and the graph check); restored, tree clean
    test-features) local m=clients/ua-c/Cargo.toml r
                   CARGO_NET_OFFLINE=true python3 -I scripts/check_test_features.py || return 1
                   sed -i 's/features = \["json", "wallet"\] }/features = ["json", "wallet", "vectors"] }/' $m
                   CARGO_NET_OFFLINE=true python3 -I scripts/check_test_features.py; r=$?
                   git checkout -q -- $m
                   echo "positive control (scaas-ua/vectors forced in $m): rc=$r (must be 1)"
                   [ $r = 1 ] && git diff --exit-code ;;
    # the mutant records of the earlier tasks of the rework: each ends with no survivor, and (T15l, Fable P3-5) every harness
    # still applies at this commit (`check`: each replacement string found once), so a later change cannot leave a record that
    # no longer tests anything
    mutant-logs) local t bad=0
                 for t in 2026-11-06-ua-rs-sign-t15b 2026-11-06-ua-rs-sign-t15c 2026-11-07-ua-rs-sign-t15c2 2026-11-07-ua-rs-sign-t15e \
                          2026-11-07-ua-rs-sign-t14b 2026-11-07-ua-rs-sign-t15g 2026-11-07-ua-rs-sign-t15k 2026-11-07-ua-rs-sign-t15i \
                          2026-11-07-ua-rs-sign-t15l 2026-11-07-ua-rs-sign-t15m; do
                   l=$(tail -n 1 smartcontracts/evm/runs/$t-mutants.txt); echo "$t: $l"
                   grep -Eq '(survived or not loaded: 0|0 survived, 0 not loaded)$|0 survived, 0 not loaded \(' <<< "$l" || bad=1
                   echo "$t check: $(python3 -I smartcontracts/evm/runs/$t-mutants.py check 2>&1 | tail -n 1)"
                   python3 -I smartcontracts/evm/runs/$t-mutants.py check > /dev/null 2>&1 || bad=1
                 done; [ $bad = 0 ] ;;
    l-mutant-*) local n=${1#l-mutant-}; python3 -I "$L" "$n" "$n"; local r=$?; git diff --exit-code && return $r ;;
    mutant-*) local n=${1#mutant-}; python3 -I "$H" "$n" "$n"; local r=$?; git diff --exit-code && return $r ;;
    # the libraries the binding mutants rebuilt, from the clean tree
    rebuild) $CAP cargo build --release --locked --offline -j2 --manifest-path clients/ua-c/Cargo.toml &&
             $CAP cargo build --locked --offline -j2 --manifest-path clients/ua-c/Cargo.toml &&
             $CAP sh -c 'cmake --build clients/ua-cxx/build -j2' &&
             $CAP cargo build --locked --offline -j2 --manifest-path clients/ua-dart-frb/rust/Cargo.toml && git diff --exit-code ;;
    *) echo "unknown step $1"; return 2 ;;
  esac
}

[ "${1:-}" = steps ] && { echo "$STEPS"; exit 0; }
s=${1:?step (or: steps)}
case " $STEPS " in *" $s "*) ;; *) echo "unknown step $s"; exit 2 ;; esac
log=$P-$s.log head=$(git rev-parse --short HEAD)
if [ -z "${GATES_FRESH:-}" ] && [ -f "$log" ] && [ "$(tail -n 1 "$log")" = rc=0 ] && head -n 1 "$log" | grep -q " at commit $head$" &&
   git diff --quiet && git diff --cached --quiet; then
  echo "$s: done at $head (skipped)"; exit 0
fi
{ echo "# $s at commit $head"; step "$s"; echo "rc=$?"; } > "$log" 2>&1
tail -n 3 "$log"
[ "$(tail -n 1 "$log")" = rc=0 ]
