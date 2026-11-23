#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Plan 2026-11-23-pqchat-signatures (CTR-CHAT-23, CLI-PQC-15/16): the round's gates, from the worktree root:
#   smartcontracts/evm/runs/2026-11-23-pqchat-sigs-gates.sh --list
#   smartcontracts/evm/runs/2026-11-23-pqchat-sigs-gates.sh [--force] <step>...
# Each step writes smartcontracts/evm/runs/2026-11-23-pqchat-sigs-<step>.log (git-ignored; first line `# <step> at commit <sha>`,
# last `rc=<n>`) and, on a clean tree, one row `step | commit | rc | counts` of 2026-11-23-pqchat-sigs-summary.txt. A step done
# (rc=0) at the same commit on a clean tree is skipped unless --force. Heavy steps go through scripts/capped, in the foreground.
# Scope (AGENTS.md, "any other contract change"): every forge directory at the default set, then the set-sensitive tests and
# test/modules at the three other sets through the lanes (ARCH-POS-21); the node, the clients and the docs touched.
set -uo pipefail
W=$(git rev-parse --show-toplevel)
cd "$W" || exit 2
R=smartcontracts/evm/runs
SUMMARY=$R/2026-11-23-pqchat-sigs-summary.txt
export PATH="$HOME/.foundry/bin:$PATH" CAPPED_SLOTS=${CAPPED_SLOTS:-4} CARGO_INCREMENTAL=0
cap="$W/scripts/capped"
C="--locked --offline -j2"
F="vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots,app-core,pqchat-records"
DIRS="account as confidential factory fork gas governance hedera liquidity merge metatx p6f pqchat pqvault pqz pqzh research ua v2
  wallet wrap zether"
fdir() { echo "FOUNDRY_TEST=test/$1 FOUNDRY_SCRIPT=test/$1 $cap forge test -j 1"; }
STEPS=(
    "forge-top|smartcontracts/evm|rm -rf test-s-top && mkdir test-s-top && cp test/*.t.sol test-s-top/ && FOUNDRY_TEST=test-s-top FOUNDRY_SCRIPT=test-s-top $cap forge test -j 1; r=\$?; rm -rf test-s-top; exit \$r"
    "forge-modules|smartcontracts/evm|python3 script/modules/legacy_artifacts.py build && $(fdir modules) --match-contract '^(Diff|Modules|Paths|Groups)'"
    "uagas|smartcontracts/evm|FOUNDRY_TEST=test/ua FOUNDRY_SCRIPT=test/ua $cap forge test -j 1 --isolate --match-path 'test/ua/{UAGas,UARegistryGroups}.t.sol'"
    "size|smartcontracts/evm|T=\$(mktemp -d) && $cap forge build src --sizes --json > \"\$T\"/sizes.json && python3 ../../scripts/size_gate.py \"\$T\"/sizes.json size-baseline.json; r=\$?; rm -rf \"\$T\"; exit \$r"
    "sets-sensitive|smartcontracts/evm|sh script/pqz/at-set.sh others sensitive"
    "sets-modules|smartcontracts/evm|sh script/pqz/at-set.sh others modules"
    "node-test|scaas-node|CAPPED_MEM=6G $cap cargo test --locked -j2"
    "node-clippy|scaas-node|$cap cargo clippy --locked -j2 --all-targets -- -D warnings"
    "node-e2e-instance|scaas-node|CAPPED_MEM=6G $cap cargo test --locked -j2 --test e2e -- --ignored --test-threads 1 router_instance_creations_signed_by_an_eoa"
    "ck-test|clients/clientkeys|$cap npm test"
    "ck-vectors|clients/clientkeys|node scripts/pqchat-vectors.mjs && git diff --exit-code -- ../../smartcontracts/vectors/pqchat"
    "ua-test|clients/ua-rs|$cap cargo test $C --features wallet,app-core,vectors --test pqchat_keys --test app_core --test entries"
    "rpc-test|clients/scaas-rpc|$cap cargo test $C --all-features --test evm_fakes && $cap cargo clippy $C --all-targets --all-features -- -D warnings"
    "sdk-test|clients/scaas-sdk|$cap cargo test $C --features $F,vectors --test pqchat_keys && $cap cargo test $C --features $F --test app_core && $cap cargo clippy $C --all-targets --features $F,vectors -- -D warnings"
    "pqc-test|clients/pqchat-core|$cap cargo test $C"
    "pqc-clippy|clients/pqchat-core|$cap cargo clippy $C --all-targets -- -D warnings"
    "pqc-reads|.|python3 -I clients/pqchat-core/runs/check_reads.py"
    "pqc-abi|.|python3 -I clients/pqchat-core/runs/gen_abi.py --check"
    "pqc-vectors|clients/pqchat-core|$cap cargo test $C --features vectors --test vectors"
    "pqc-wasm|clients/pqchat-core|$cap cargo check $C --target wasm32-unknown-unknown"
    "pqc-chain|clients/pqchat-core|$cap cargo test $C -- --ignored --test-threads 1 chain_"
    "pqc-mutants|.|python3 clients/pqchat-core/runs/2026-11-23-pqchat-sigs-mutants.py run"
    "docs|.|python3 scripts/docs_check.py check && python3 scripts/docs_check.py paths && python3 scripts/test_docs_check.py"
)
for d in $DIRS; do STEPS+=("forge-$d|smartcontracts/evm|$(fdir "$d")"); done

cmd_of() {
    local s
    for s in "${STEPS[@]}"; do [[ ${s%%|*} == "$1" ]] && { echo "$s"; return 0; }; done
    return 1
}
[[ ${1:-} == --list ]] && { for s in "${STEPS[@]}"; do echo "${s%%|*}"; done; exit 0; }
FORCE=
[[ ${1:-} == --force ]] && { FORCE=1; shift; }
[[ $# -ge 1 ]] || { echo "usage: $0 [--list] [--force] <step>..."; exit 2; }
for s in "$@"; do cmd_of "$s" >/dev/null || { echo "[G] no such step: $s (--list)" >&2; exit 2; }; done
sha=$(git rev-parse --short=9 HEAD)
X=":!$SUMMARY"
clean() { git diff --quiet HEAD -- . "$X" && git diff --quiet --cached HEAD -- . "$X"; }

counts() { # the test counts of a log, by runner (the pqchat-core plan's runner's)
    awk '/^test result:/ { for (i = 1; i <= NF; i++) { if ($(i+1) ~ /^passed/) p += $i; if ($(i+1) ~ /^failed/) f += $i; if ($(i+1) ~ /^ignored/) g += $i }; n++ }
       /^Ran [0-9]+ test suites/ { for (i = 1; i <= NF; i++) { if ($(i+1) == "tests" && $(i+2) == "passed,") fp += $i; if ($(i+1) == "failed,") ff += $i }; fn++ }
       /^(# |ℹ )pass / { np += $3; nn++ } /^(# |ℹ )fail / { nf += $3 }
       /size gate: / || /^check: / || /mutants, .* killed/ || /^ok [0-9]+\/[0-9]+$/ { r = r (r ? "; " : "") $0 }
       END { o = "";
             if (n) o = sprintf("%d passed, %d failed, %d ignored (%d binaries)", p, f, g, n);
             if (fn) o = o (o ? "; " : "") sprintf("forge: %d passed, %d failed", fp, ff);
             if (nn) o = o (o ? "; " : "") sprintf("node: %d pass, %d fail", np, nf);
             if (r) o = o (o ? "; " : "") r;
             printf "%s", (o ? o : "-") }' "$1"
}

worst=0
for s in "$@"; do
    IFS='|' read -r name dir cmd <<<"$(cmd_of "$s")"
    log=$R/2026-11-23-pqchat-sigs-$name.log
    if [[ -z $FORCE && -f $log ]] && clean && [[ $(head -1 "$log") == "# $name at commit $sha" ]] && [[ $(tail -1 "$log") == rc=0 ]]; then
        echo "[G] $name: done at $sha (clean tree), skipped"
        continue
    fi
    state=clean
    clean || state=dirty
    { echo "# $name at commit $sha"; echo "# tree $state; $dir: $cmd"; } >"$log"
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
    if [[ $state == clean ]]; then
        touch "$SUMMARY"
        grep -v "^$name | " "$SUMMARY" >"$SUMMARY.new" || true
        echo "$name | $sha | $rc | $n" >>"$SUMMARY.new"
        sort -o "$SUMMARY" "$SUMMARY.new" && rm -f "$SUMMARY.new"
    else
        n="$n; tree dirty, no summary row"
    fi
    if ((rc == 0)); then echo "[G] $name ok in $((SECONDS - t0)) s: $n"; else echo "[G] $name FAIL rc=$rc in $((SECONDS - t0)) s: $n ($log)"; worst=1; fi
done
exit $worst
