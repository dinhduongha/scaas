#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Fixed lanes for the PQZ per-set runs (TODO 8g (4), ARCH-POS-20); at-set.sh calls this. UNAUDITED tooling.
#   smartcontracts/evm/script/pqz/lanes.sh [--clean] <set|others> [sensitive|list|modules|forge args ...]
#   smartcontracts/evm/script/pqz/lanes.sh [--clean] mutants <command ...>
# A lane is scratchpad/lanes/<set>/ (LANES_DIR overrides): smartcontracts/evm, smartcontracts/vectors, pqz-core/params/sets
# and pqz-core/nethermind/chain/eth.py copied from this work tree by `rsync --delete --copy-links` (real files, no hardlink,
# no symlink back), its own out/ and cache/ kept (incremental). <set>'s PqzSet.sol is installed in the lane only: the work tree's
# src/pqz/PqzSet.sol is never written, so several sets run at once from one work tree. One writer per lane: a run on a
# busy lane is refused (flock on scratchpad/lanes/<set>.lock). --clean wipes the lane's out/ and cache/ first: the
# round's final matrix and every pre-merge gate use it. forge runs through scripts/capped (directly inside one).
# Scopes (AGENTS.md "Size the per-set run to the change"; default: test/pqz/*) run one forge per test directory, each
# its own compile set, out/t-<dir>, cache/t-<dir>; plain forge args run once, as given, in out/ and cache/:
#   sensitive  test/pqz/*, test/pqzh/* and every other *.t.sol that reads the set (PqzSet., a kmax<N> set name,
#              PQZ_SET) or imports a helper that does. For a non-PQZ contract change.
#   list       print that list and exit (no lane, no forge).
#   modules    test/modules/* at the set, its pre-split side built at that set first (runs/2026-11-11-stacked-gate/
#              legacy-at-set.sh, written into the lane's out/t66b-legacy).
#   others     the scope at every set but the committed one, IN PARALLEL, one lane each. A lane starts when `free -g`
#              shows LANES_LANE_GB (4) above LANES_RESERVE_GB (6) available, one start per LANES_RAMP s (60); the
#              rest wait (heartbeat every 30 s; they give up after LANES_WAIT s (1800) with none of ours running).
#              Output per set in scratchpad/lanes/<set>.log; exit 1 naming the failed sets. Inside an outer
#              scripts/capped (one 4 GB scope) the sets run one after another instead.
#   mutants    a lane at the work tree's own set; <command> runs in its smartcontracts/evm (it calls scripts/capped).
set -eu
CLEAN=
if [ "${1:-}" = --clean ]; then
    CLEAN=1
    shift
fi
[ $# -ge 1 ] || {
    awk 'NR > 2 && /^set -eu/ { exit } NR > 2' "$0"
    exit 2
}
S=$1
shift
EVM=$(cd "$(dirname "$0")/../.." && pwd)
ROOT=$(cd "$EVM/../.." && pwd)
SETS=$ROOT/pqz-core/params/sets
LANES=${LANES_DIR:-$ROOT/scratchpad/lanes}
REL=${LANES#"$ROOT"/}
setname() { sed -n 's/.*string internal constant NAME = "\(.*\)";/\1/p' "$1"; }
dur() { printf '%dm%02ds' $(($1 / 60)) $(($1 % 60)); }
# The set-sensitive test files, computed (not hand-listed, so a new set-reading test is never missed).
sensitive() (
    cd "$EVM"
    pat='PqzSet\.|kmax[0-9]|PQZ_SET'
    helpers=$(grep -rlE "$pat" test --include='*.sol' | grep -v -E '\.t\.sol$|/legacy/' | sed 's|.*/||; s|\.sol$||' | sort -u)
    {
        grep -rlE "$pat" test --include='*.t.sol' | grep -v /legacy/
        for h in $helpers; do grep -rlE "import .*[/\"]$h\.sol" test --include='*.t.sol' | grep -v /legacy/ || true; done
    } | grep -v -E '^test/(pqzh?|modules)/' | sort -u
)
if [ "${1:-}" = list ] && [ "$S" != mutants ]; then
    echo 'test/pqz/*'
    echo 'test/pqzh/*'
    sensitive
    exit 0
fi
# T21 L67: the gas table's inputs (test/vectors/pqz-gas/<set>.json) equal what gas-inputs.py makes of the precompile rows
if [ "$S" != mutants ] && [ -z "${LANES_CHECKED:-}" ]; then
    python3 -I "$EVM/script/pqz/gas-inputs.py" --check || {
        echo "lanes.sh: run gas-inputs.py and commit the pqz-gas files" >&2
        exit 1
    }
    export LANES_CHECKED=1
fi

if [ "$S" = others ]; then
    COMMITTED=$(setname "$EVM/src/pqz/PqzSet.sol")
    todo=
    for d in "$SETS"/n*-kmax*/; do
        s=$(basename "$d")
        [ "$s" = "$COMMITTED" ] || todo="$todo $s"
    done
    failed=
    if [ -n "${CAPPED_SCOPE:-}" ]; then
        echo "[lanes] inside scripts/capped: the sets run one after another (run without an outer capped for parallel lanes)"
        for s in $todo; do sh "$0" ${CLEAN:+--clean} "$s" "$@" || failed="$failed $s"; done
        [ -z "$failed" ] || {
            echo "[lanes] FAIL:$failed" >&2
            exit 1
        }
        exit 0
    fi
    RESERVE=${LANES_RESERVE_GB:-6} LANE_GB=${LANES_LANE_GB:-4} RAMP=${LANES_RAMP:-60} WAIT=${LANES_WAIT:-1800}
    mkdir -p "$LANES"
    t0=$(date +%s)
    last=0 beat=$t0 idle=$t0 sum=0 ok="" waiting=$todo running=""
    # On Ctrl-C / hang-up / TERM: stop our lanes (each subshell's child is its lane's sh or forge), then exit.
    trap 'for r in $running; do pkill -TERM -P "${r#*:}" || true; done; echo "[lanes] interrupted" >&2; exit 130' HUP INT TERM
    echo "[lanes] others:$todo, ${CLEAN:+clean, }up to one lane per ${LANE_GB} GB above a ${RESERVE} GB reserve; logs $REL/<set>.log"
    while [ -n "$waiting$running" ]; do
        now=$(date +%s)
        still=
        for r in $running; do
            s=${r%%:*}
            if [ -f "$LANES/$s.rc" ]; then
                src=$(cat "$LANES/$s.rc")
                st=$(cat "$LANES/$s.t0")
                sum=$((sum + now - st))
                if [ "$src" = 0 ]; then
                    ok="$ok $s"
                    echo "[lanes] ok $s ($(dur $((now - st))))"
                else
                    failed="$failed $s"
                    echo "[lanes] FAIL $s (rc $src, $(dur $((now - st))); $REL/$s.log): $({ grep -m 1 -E '^\[FAIL|^Error|FAIL:' "$LANES/$s.log" || tail -n 2 "$LANES/$s.log"; } | tr '\n' ' ' | cut -c1-200)"
                fi
            else
                still="$still $r"
            fi
        done
        running=$still
        [ -z "$running" ] || idle=$now
        if [ -n "$waiting" ] && [ $((now - last)) -ge "$RAMP" ]; then
            avail=$(free -g | awk '/^Mem:/ { print $7 }')
            if [ "$avail" -ge $((RESERVE + LANE_GB)) ]; then
                s=
                rest=
                for w in $waiting; do if [ -z "$s" ]; then s=$w; else rest="$rest $w"; fi; done
                waiting=$rest
                rm -f "$LANES/$s.rc"
                echo "$now" >"$LANES/$s.t0"
                (
                    r=0
                    sh "$0" ${CLEAN:+--clean} "$s" "$@" >"$LANES/$s.log" 2>&1 || r=$?
                    echo "$r" >"$LANES/$s.rc"
                ) &
                running="$running $s:$!"
                last=$now
                echo "[lanes] start $s (available ${avail} GB)"
            elif [ -z "$running" ] && [ $((now - idle)) -ge "$WAIT" ]; then
                for w in $waiting; do
                    failed="$failed $w"
                    echo "[lanes] FAIL $w: never ${RESERVE} + ${LANE_GB} GB available in ${WAIT} s (now ${avail} GB)"
                done
                waiting=
            fi
        fi
        if [ $((now - beat)) -ge 30 ]; then
            beat=$now
            line="[lanes] $(dur $((now - t0)))"
            for r in $running; do
                s=${r%%:*}
                line="$line | $s $(dur $((now - $(cat "$LANES/$s.t0")))): $(tail -n 1 "$LANES/$s.log" 2>/dev/null | cut -c1-60)"
            done
            [ -z "$waiting" ] || line="$line | waiting:$waiting (available $(free -g | awk '/^Mem:/ { print $7 }') GB)"
            echo "$line"
        fi
        [ -z "$waiting$running" ] || sleep 5
    done
    echo "[lanes] done: wall $(dur $(($(date +%s) - t0))), lanes' sum $(dur "$sum"); ok:${ok:- none}${failed:+; FAIL:$failed}"
    [ -z "$failed" ] || exit 1
    exit 0
fi

case $S in
    *[!a-z0-9-]*)
        echo "lanes.sh: bad lane name $S" >&2
        exit 2
        ;;
    mutants)
        [ $# -ge 1 ] || {
            echo "lanes.sh: mutants needs a command" >&2
            exit 2
        }
        ;;
    *)
        [ -f "$SETS/$S/PqzSet.sol" ] || {
            echo "lanes.sh: no PqzSet.sol for set $S ($SETS/$S/PqzSet.sol)" >&2
            exit 2
        }
        ;;
esac
# A scope runs per test directory, "<dir> <match-path>" per line: each its own compile set, out/t-<dir> and
# cache/t-<dir> (FOUNDRY_TEST / FOUNDRY_SCRIPT = test/<dir>, as the round matrices do: src, test and script in one solc
# run exceed a 4 GB cap). Plain forge args run as given, in out/ and cache/.
MODULES=
JOBS=
if [ "$S" != mutants ]; then
    case ${1:-} in
        modules)
            shift
            MODULES=1
            JOBS='modules test/modules/*'
            ;;
        sensitive)
            shift
            SL=$(sensitive)
            JOBS=$(
                echo 'pqz test/pqz/*'
                echo 'pqzh test/pqzh/*'
                for d in $(echo "$SL" | cut -d/ -f2 | sort -u); do echo "$d {$(echo "$SL" | grep "^test/$d/" | paste -sd, -)}"; done
            )
            ;;
        '') JOBS='pqz test/pqz/*' ;;
    esac
fi

L=$LANES/$S
LE=$L/smartcontracts/evm
mkdir -p "$LE" "$L/smartcontracts/vectors" "$L/pqz-core/params/sets"
exec 9>"$LANES/$S.lock"
flock -n 9 || {
    echo "lanes.sh: lane $S is busy: another run holds $REL/$S.lock (one writer per lane); wait for it to end" >&2
    exit 3
}
# The set lanes keep their installed PqzSet.sol (excluded, so --delete leaves it); mutants take the work tree's.
X=
[ "$S" = mutants ] || X=--exclude=/src/pqz/PqzSet.sol
rsync -a --delete --copy-links --exclude=/out/ --exclude=/cache/ --exclude=target/ ${X:+"$X"} "$EVM/" "$LE/"
rsync -a --delete --copy-links "$ROOT/smartcontracts/vectors/" "$L/smartcontracts/vectors/"
rsync -a --delete --copy-links "$SETS/" "$L/pqz-core/params/sets/"
# `modules` builds the pre-split side with script/modules/legacy_artifacts.py, which imports the chain tools' keccak
mkdir -p "$L/pqz-core/nethermind/chain"
cp -p "$ROOT/pqz-core/nethermind/chain/eth.py" "$L/pqz-core/nethermind/chain/eth.py"
if [ "$S" != mutants ]; then
    # cp only on a change: an unchanged mtime keeps the lane's cache valid
    cmp -s "$L/pqz-core/params/sets/$S/PqzSet.sol" "$LE/src/pqz/PqzSet.sol" ||
        cp "$L/pqz-core/params/sets/$S/PqzSet.sol" "$LE/src/pqz/PqzSet.sol"
fi
[ -z "$CLEAN" ] || rm -rf "$LE/out" "$LE/cache"
# test/modules reads out/t66b-legacy (the pre-split releases, legacy_artifacts.py): the work tree's, unless `modules`
# writes the lane's own at the set below
if [ -z "$MODULES" ] && [ -d "$EVM/out/t66b-legacy" ]; then
    mkdir -p "$LE/out"
    rsync -a --delete "$EVM/out/t66b-legacy/" "$LE/out/t66b-legacy/"
fi
cd "$LE"
if [ "$S" = mutants ]; then
    echo "== lanes.sh: mutants ($(setname src/pqz/PqzSet.sol)) in $REL/mutants${CLEAN:+, clean}: $*"
    exec "$@"
fi
[ -z "$MODULES" ] || LEGACY_EVM=$LE sh "$EVM/runs/2026-11-11-stacked-gate/legacy-at-set.sh" "$S"
fg() {
    if [ -n "${CAPPED_SCOPE:-}" ]; then forge "$@" </dev/null; else "$ROOT/scripts/capped" forge "$@" </dev/null; fi
}
echo "== lanes.sh: $S ($(setname src/pqz/PqzSet.sol)) in $REL/$S${CLEAN:+, clean}, forge ${JOBS:+test --match-path <per directory> }$*"
if [ -z "$JOBS" ]; then
    fg "$@"
    exit 0
fi
bad=
while read -r d m; do
    echo "-- $S test/$d: forge test --match-path $m $*"
    (
        export FOUNDRY_TEST="test/$d" FOUNDRY_SCRIPT="test/$d" FOUNDRY_OUT="out/t-$d" FOUNDRY_CACHE_PATH="cache/t-$d"
        fg test --match-path "$m" "$@"
    ) || bad="$bad test/$d"
done <<EOF
$JOBS
EOF
[ -z "$bad" ] || {
    echo "== lanes.sh: $S FAIL:$bad" >&2
    exit 1
}
echo "== lanes.sh: $S ok"
