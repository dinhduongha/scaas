#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# The gates of the setAuditor plan (docs/superpowers/plans/2026-11-17-set-auditor.md), a copy of the PqVault Part R runner, itself a copy of
# runs/2026-11-12-ua-mtx-merge-final-gate/gates.sh cut to the affected steps, forge at -j 1. From the repository root:
#   sh smartcontracts/evm/runs/2026-11-17-set-auditor/gates.sh <step> [<step> ...]
# GATE_PRUNE=1 removes a green forge step's out/ and cache/ after it. GATE_TAG=<task> names the log directory (default a): runs/2026-11-17-set-auditor/<tag>/<step>.log (git-ignored), ending with
# `rc=<n>`; a step whose log ends with `rc=0` is skipped (RERUN=1 runs it again; a red log is kept as <step>.red.log). One line
# per step on stdout and in <tag>/progress.log. Heavy commands go through scripts/capped, foreground, one at a time. The
# committed record is runs/2026-11-17-set-auditor-summary.txt (task | step | commit | rc | counts). Steps:
#   forge-<dir>      FOUNDRY_TEST=test/<dir> at the default set (out/t66a-test-<dir>); forge-top: test/*.t.sol;
#                    forge-modules: the differential (out/t66b-legacy first) and Modules, Paths, Groups
#   uagas            forge test --isolate --match-path 'test/ua/{UAGas,UARegistryGroups}.t.sol' (AGENTS.md, the CI header)
#   size             size_gate.py --self-test; forge build src --sizes --json; size_gate.py against size-baseline.json
#   set-<set>-<dir>  the set-sensitive tests of test/<dir> at <set> (at-set.sh list), src/pqz/PqzSet.sol checked after
#   pqzvec-<set>     test/pqz/PqzStateVectors.t.sol at <set> (each set's state.json; not in at-set's sensitive list)
#   node-guard       scaas-node cargo test guard (the allow-list and PqChat row tests)
#   zp-clippy, zp-test, zp-wasm, zp-read-balance   clients/zether-prover (the CI header's commands; read_balance runs anvil)
#   clientkeys, ua-rs-<cell>, ua-py, ua-go, ua-cs, ua-c, ua-cxx, ua-dart, ua-dart-frb, ua-qt   the clients' own tests (the
#                    CI header's commands; ua-rs per CI cell)
#   docs, docs-test, ci-guards
#   mut-<task>       runs/2026-11-17-set-auditor/mutants.py <task> all (MUT_IDS="<id> ...": those only), in a lane
#   proof-forge, proof-cargo   the lane cache proof (owner 2026-11-18): incremental vs clean, see below
# Lanes (owner 2026-11-18, "Đồng ý. Làm luôn"): LANE=<n2304-kmax4096|n2048-kmax1024|n2560-kmax16384|n2816-kmax65536|mutants>
# runs the steps in the fixed lane <repo>/scratchpad/lanes/<LANE>/ (git-ignored, on /home; the path never changes) after an
# `rsync -a --delete` of the tree under test (LANE_FROM, default this repository) with every exclude anchored at the root
# (scratchpad/lanes/<LANE>.excludes): /.git, /scratchpad/, /.claude/, /smartcontracts/evm/lib/, this runner's log directories,
# and each out/, cache/, target/, build/, node_modules/ that holds no file of the tree, so forge's cache/ + out/ and cargo's
# target/ stay and the lane builds incrementally; then every file of the tree (git ls-files -co --exclude-standard) outside
# the excludes is checked present and byte-identical in the lane, or the sync fails. smartcontracts/evm/lib/,
# clients/clientkeys/node_modules and smartcontracts/algorand/out are plain copies made once (no hardlink, no symlink). A set
# lane holds its set's PqzSet.sol (installed only when it differs); its set-* steps run forge there directly. One process per
# lane at a time (flock on the lane). GATE_PRUNE has no effect in a lane. Incremental builds serve the per-task loop only;
# evidence (the full matrix after A10, every pre-merge gate) is built clean.
set -u
ROOT=$(cd "$(dirname "$0")/../../../.." && pwd)
if [ -n "${LANE:-}" ] && [ -z "${LANE_IN:-}" ]; then
    FROM=${LANE_FROM:-$ROOT}
    LD=$ROOT/scratchpad/lanes/$LANE
    mkdir -p "$LD"
    exec 8>"$ROOT/scratchpad/lanes/$LANE.lock"
    flock -n 8 || {
        echo "gates.sh: lane $LANE is busy"
        exit 1
    }
    # every exclude anchored at the repository root (a bare `lib/` once dropped the Dart clients' lib/ sources, a bare `build/`
    # was missing and a worktree's CMake cache came along, a bare `.git/` let the worktree's `.git` file through): the fixed
    # ones, and each out/, cache/, target/, build/, node_modules/ found in the tree or the lane that holds no file of the tree
    # under test (git ls-files -co --exclude-standard). After the rsync every file of that list outside the excludes must be
    # in the lane and byte-identical, or the sync fails.
    python3 - "$FROM" "$LD" "$LANE" <<'PY' || {
import fnmatch, os, subprocess, sys
src, dst, lane = sys.argv[1:]
files = subprocess.run(["git", "-C", src, "ls-files", "-co", "--exclude-standard", "-z"], capture_output=True, check=True).stdout
files = [p for p in files.decode().split("\0") if p and os.path.lexists(os.path.join(src, p))]
held = {os.path.dirname(p) for p in files}
held |= {d[: i] for d in list(held) for i in range(len(d)) if d[i] == "/"}
ex = ["/.git", "/scratchpad/", "/.claude/", "/smartcontracts/evm/lib/", "/smartcontracts/evm/runs/2026-11-17-set-auditor/*/"]
if lane.startswith("n"):
    ex.append("/smartcontracts/evm/src/pqz/PqzSet.sol")
for root in (src, dst):
    for d, subs, _ in os.walk(root):
        rel = os.path.relpath(d, root).replace(os.sep, "/").removeprefix(".").lstrip("/")
        keep = []
        for s in subs:
            r = f"{rel}/{s}" if rel else s
            if any(fnmatch.fnmatch("/" + r + "/", e) or ("/" + r + "/").startswith(e) for e in ex if e.endswith("/")):
                continue
            if s in ("out", "cache", "target", "build", "node_modules") and r not in held:
                ex.append(f"/{r}/")
            else:
                keep.append(s)
        subs[:] = keep
exf = os.path.join(os.path.dirname(dst), f"{lane}.excludes")
open(exf, "w").write("".join(e + "\n" for e in sorted(set(ex))))
r = subprocess.run(["rsync", "-a", "--delete", f"--exclude-from={exf}", src + "/", dst + "/"])
if r.returncode:
    sys.exit(r.returncode)
def out(p):
    q = "/" + p
    return any(q == e or q.startswith(e) or fnmatch.fnmatch(q, e + "*") for e in ex)
bad = []
for p in files:
    if out(p):
        continue
    a, b = os.path.join(src, p), os.path.join(dst, p)
    if os.path.islink(a):
        ok = os.path.islink(b) and os.readlink(a) == os.readlink(b)
    else:
        ok = os.path.isfile(b) and not os.path.islink(b) and open(a, "rb").read() == open(b, "rb").read()
    if not ok:
        bad.append(p)
print(f"gates.sh: lane {lane}: {len(files)} files of the tree, {len(ex)} anchored excludes, {len(bad)} missing or different")
for p in bad[:20]:
    print("  differs:", p)
sys.exit(1 if bad else 0)
PY
        echo "gates.sh: lane $LANE sync check failed"
        exit 1
    }
    [ -d "$LD/smartcontracts/evm/lib" ] || cp -r "$FROM/smartcontracts/evm/lib" "$LD/smartcontracts/evm/lib"
    [ -d "$LD/clients/clientkeys/node_modules" ] || [ ! -d "$FROM/clients/clientkeys/node_modules" ] ||
        cp -r "$FROM/clients/clientkeys/node_modules" "$LD/clients/clientkeys/node_modules"
    [ -d "$LD/smartcontracts/algorand/out" ] || [ ! -d "$FROM/smartcontracts/algorand/out" ] ||
        cp -r "$FROM/smartcontracts/algorand/out" "$LD/smartcontracts/algorand/out"
    case $LANE in n*-kmax*)
        P=$LD/pqz-core/params/sets/$LANE/PqzSet.sol
        [ -f "$P" ] || {
            echo "no set $LANE"
            exit 2
        }
        cmp -s "$P" "$LD/smartcontracts/evm/src/pqz/PqzSet.sol" || cp "$P" "$LD/smartcontracts/evm/src/pqz/PqzSet.sol"
        ;;
    esac
    echo "gates.sh: lane $LANE synced from $(basename "$FROM")"
    LANE_IN=1 LANE_BACK=$ROOT/smartcontracts/evm/runs/2026-11-17-set-auditor/lane-$LANE exec sh "$LD/smartcontracts/evm/runs/2026-11-17-set-auditor/gates.sh" "$@"
fi
cd "$ROOT"
EVM=smartcontracts/evm
HERE=$EVM/runs/2026-11-17-set-auditor/${GATE_TAG:-a}
mkdir -p "$HERE" "$EVM/out"
C="$ROOT/scripts/capped"
export PATH="$HOME/.foundry/bin:$PATH"          # at-set.sh calls forge by name
L=$EVM/out/${GATE_LOCK:-set-auditor-gates}.lock # GATE_LOCK: a second lane (never beside a set-* step: at-set.sh rewrites PqzSet.sol)
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
        set-*)
            if [ -n "${LANE_IN:-}" ]; then # in a set lane: forge at the lane's own PqzSet.sol
                s=$(echo "$1" | cut -d- -f2-3)
                d=$(echo "$1" | cut -d- -f4-)
                n=$(sed -n 's/.*string internal constant NAME = "\(.*\)";/\1/p' $EVM/src/pqz/PqzSet.sol)
                [ "$n" = "$s" ] || {
                    echo "lane PqzSet.sol is $n, the step wants $s"
                    return 2
                }
                m=$(sh $EVM/script/pqz/at-set.sh x list | grep "^test/$d/" | paste -sd, -)
                [ -n "$m" ] || {
                    echo "no set-sensitive test in test/$d"
                    return 2
                }
                (cd $EVM && FOUNDRY_TEST=test/$d FOUNDRY_SCRIPT=test/$d FOUNDRY_OUT=out/set-$d FOUNDRY_CACHE_PATH=cache/set-$d \
                    "$C" forge test -j 1 --match-path "{$m}")
                return $?
            fi
            # set-<set>-<dir>: the set-sensitive tests of test/<dir> (at-set.sh list), test/<dir> alone in the compile set (the whole
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
        pqzvec-*) # pqzvec-<set>: the PQZ state vectors of <set> checked (no STATE_VECTORS), PqzStateVectors.t.sol alone (it is not in
            # at-set's sensitive list, yet each set has its own state.json), src/pqz/PqzSet.sol checked after
            s=${1#pqzvec-}
            FOUNDRY_TEST=test/pqz FOUNDRY_SCRIPT=test/pqz "$C" $EVM/script/pqz/at-set.sh "$s" test -j 1 --match-path test/pqz/PqzStateVectors.t.sol
            r=$?
            git diff --exit-code -- $EVM/src/pqz/PqzSet.sol || r=3
            return $r
            ;;
        mut-*) (cd $EVM && if [ -n "${MUT_IDS:-}" ]; then
            python3 runs/2026-11-17-set-auditor/mutants.py ${1#mut-} run $MUT_IDS
        else python3 runs/2026-11-17-set-auditor/mutants.py ${1#mut-} all; fi) ;;
        proof-forge) # build src, change one source file, rebuild incrementally; the same tree built clean in a fresh directory;
            # every contract's init and runtime bytecode compared (identical required)
            P=$ROOT/../proof-clean
            rm -rf "$P"
            mkdir -p "$P"
            (cd $EVM && FOUNDRY_OUT=out/proof FOUNDRY_CACHE_PATH=cache/proof "$C" forge build -j 1 src >/dev/null) || return 1
            printf '\n// lane cache proof: one source file changed\n' >>$EVM/src/governance/GovernanceBits.sol
            (cd $EVM && FOUNDRY_OUT=out/proof FOUNDRY_CACHE_PATH=cache/proof "$C" forge build -j 1 src | grep -E "^Compiling|No files changed")
            rsync -a --exclude=out/ --exclude=cache/ --exclude=target/ --exclude=node_modules/ --exclude=.git/ ./ "$P/" || return 1
            (cd "$P/$EVM" && FOUNDRY_OUT=out/proof FOUNDRY_CACHE_PATH=cache/proof "$C" forge build -j 1 src >/dev/null) || return 1
            python3 - "$EVM/out/proof" "$P/$EVM/out/proof" <<'PY'
import json, os, sys
a, b = sys.argv[1], sys.argv[2]
n = bad = 0
for d, _, fs in os.walk(a):
    for f in fs:
        if not f.endswith(".json") or "build-info" in d: continue
        x = json.load(open(os.path.join(d, f))); y = json.load(open(os.path.join(b, os.path.relpath(d, a), f)))
        for k in ("bytecode", "deployedBytecode"):
            if (x.get(k) or {}).get("object") != (y.get(k) or {}).get("object"): bad += 1; print("DIFF", f, k)
        n += 1
print(f"proof-forge: {n} artifacts compared, {bad} differ")
sys.exit(1 if bad or n == 0 else 0)
PY
            ;;
        proof-cargo) # ua-rs: cargo test in the lane, one source file changed, incremental cargo build + test; the same tree tested
            # in a fresh directory; the test outcomes compared (a test binary's hash is not stable)
            P=$ROOT/../proof-clean-rs
            rm -rf "$P"
            mkdir -p "$P"
            (cd clients/ua-rs && "$C" cargo test -j 2 --locked 2>&1 | grep -E "^test result" >/dev/null) || return 1
            printf '\n// lane cache proof: one source file changed\n' >>clients/ua-rs/src/lib.rs
            (cd clients/ua-rs && "$C" cargo build -j 2 --locked && "$C" cargo test -j 2 --locked 2>&1 | grep -E "^test result" | sort) >$HERE/proof-cargo-incr.txt || return 1
            rsync -a --exclude=target/ --exclude=out/ --exclude=cache/ --exclude=node_modules/ --exclude=.git/ ./ "$P/" || return 1
            (cd "$P/clients/ua-rs" && "$C" cargo test -j 2 --locked 2>&1 | grep -E "^test result" | sort) >$HERE/proof-cargo-clean.txt || return 1
            sed 's/finished in [0-9.]*s//' $HERE/proof-cargo-incr.txt >$HERE/a.txt
            sed 's/finished in [0-9.]*s//' $HERE/proof-cargo-clean.txt >$HERE/b.txt
            cmp -s $HERE/a.txt $HERE/b.txt && echo "proof-cargo: $(wc -l <$HERE/a.txt) test binaries, outcomes identical"
            ;;
        node-lib) (cd scaas-node && "$C" cargo test -j 2 --lib) ;;
        node-clippy) (cd scaas-node && "$C" cargo clippy -j 2 --all-targets -- -D warnings) ;;
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
        zp-clippy) (cd clients/zether-prover && "$C" cargo clippy -j 2 --locked --all-targets -- -D warnings &&
            "$C" cargo clippy -j 2 --locked --all-targets --features hazmat -- -D warnings) ;;
        zp-test) (cd clients/zether-prover && "$C" cargo test -j 2 --locked && "$C" cargo test -j 2 --locked --features hazmat) ;;
        zp-wasm) (cd clients/zether-prover && "$C" ./wasm-smoke.sh && ZETHER_HAZMAT=1 "$C" ./wasm-smoke.sh) ;;
        zp-read-balance) (cd clients/zether-prover && ANVIL=$HOME/.foundry/bin/anvil "$C" cargo test -j 2 --locked --test read_balance \
            --bin zether-read-balance -- --include-ignored && ANVIL=$HOME/.foundry/bin/anvil "$C" cargo test -j 2 --locked \
            --features hazmat --test read_balance --bin zether-read-balance -- --include-ignored) ;;
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
    # GATE_PRUNE=1 (a snapshot on a small disk): a green forge step's own out/ and cache/ are removed (a rerun compiles again)
    if [ "${GATE_PRUNE:-0}" = 1 ] && [ -z "${LANE_IN:-}" ] && tail -1 "$log" | grep -qx 'rc=0'; then
        case $st in forge-top) rm -rf $EVM/out/t66b-top $EVM/cache/t66b-top ;; forge-*) rm -rf $EVM/out/t66a-test-${st#forge-} $EVM/cache/t66a-test-${st#forge-} ;; esac
    fi
done
# in a lane: its logs back to the repository the run was started from (runs/2026-11-17-set-auditor/lane-<LANE>/<tag>/)
if [ -n "${LANE_BACK:-}" ]; then mkdir -p "$LANE_BACK" && cp -r "$HERE" "$LANE_BACK/"; fi
