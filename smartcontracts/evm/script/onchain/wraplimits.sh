#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Group 3l T104 (spec 2026-11-10-wrap-limits.md §11), group `wraplimits` of the on-chain matrix: WrapLimits.s.sol in seven
# forge runs on one node (setup, p1-p6), each started at or after the time the previous run wrote, plus the time that
# run's broadcast took (its transactions land after its simulation's time): on the local anvil the clock is set to it
# (evm_setNextBlockTimestamp + evm_mine: a forge script's vm.warp moves only its own simulation); on a remote chain the
# run waits for a block at that time (bounded: the time needed + 300 s, then a named FAIL; a line every 30 s). Each
# run's negatives by eth_call at its end (coverage.py neg), then the records, the trace (local, or ONCHAIN_TRACE=1), the
# coverage of the contracts it touched (their static views by eth_call too) and the summary (step | commit | rc |
# counts, every row with its gas and hash).
# WRAPLIMITS_PROFILE (owner 2026-11-15; read by setup, kept in the state file): full (default; notice 1 hour, windows
# 1 hour / 1 day, decay 2 days) or short (the SCaaS testnet: notice 5 min, windows 5 min / 15 min, decay 1 day; on anvil
# a block every 10 s, the testnet's pace). WRAPLIMITS_PHASES (default all seven): the runs of this call, in order; a
# list without setup continues the state of an earlier call (deployments/wraplimits-<net>-*, the same MATRIX_OUT), so
# the decay runs p5 (H/2: 12 h after p2 on short) and p6 (H) can run later; the phases left are written to
# $OUTD/pending.txt with the earliest start of the next one.
# From smartcontracts/evm (matrix.sh sets the environment; a local target through scripts/capped, a remote one under
# matrix.sh's memory scope, compiled first: ONCHAIN_REMOTE=1, forge must skip compilation):
#   NET=local RPC=<url> DEPLOY_JSON=deployments/<key>.json ONCHAIN_K1=… ONCHAIN_K2=… ONCHAIN_K3=… sh script/onchain/wraplimits.sh
# Output: $MATRIX_OUT/wraplimits/ (default runs/<today>-matrix/wraplimits; summary.txt, records-<net>-wraplimits.jsonl, coverage.json,
# table-<net>.txt; the log git-ignored). Keys are never printed.
set -eu
: "${NET:?}" "${RPC:?}" "${ONCHAIN_K1:?}"
REMOTE=${ONCHAIN_REMOTE:-0}
PROFILE=${WRAPLIMITS_PROFILE:-full}
OUTD=${MATRIX_OUT:-runs/$(date +%Y-%m-%d)-matrix}/wraplimits # its own coverage list and table, under matrix.sh's run dir (MATRIX_OUT), else today's
CHAIN=$(cast chain-id --rpc-url "$RPC")
B=broadcast/WrapLimits.s.sol/$CHAIN
R=$OUTD/records-$NET-wraplimits.jsonl
NEXT=deployments/wraplimits-$NET-next.txt
SENDER=$(cast wallet address --private-key "$ONCHAIN_K1")
L=$OUTD/wraplimits-$NET.log
ALL="setup p1 p2 p3 p4 p5 p6"
PHASES=${WRAPLIMITS_PHASES:-$ALL}
NEG=$OUTD/neg-$NET.jsonl # every run's negatives, kept between calls
WL=$OUTD/wl-$NET.txt     # the views' read-back lines, kept between calls
say() { echo "[$NET/wraplimits] $1"; }
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
trap 'exit 1' INT TERM # stop on a signal (a long wait must end when stopped), then the EXIT cleanup
mkdir -p "$OUTD"
case $PROFILE in full|short) ;; *) say "FAIL WRAPLIMITS_PROFILE is full or short, not $PROFILE"; exit 1 ;; esac
first=${PHASES%% *}
if [ "$first" = setup ]; then
  : > "$L"
  : > "$WL"
  : > "$NEG"
  rm -f "$R" "$NEXT" "$OUTD/pending.txt"
  for p in $ALL; do rm -f "$B/$p-latest.json"; done
else
  # a later call: the earlier one's state, its next start and its run dir
  [ -s "$NEXT" ] && [ -s "deployments/wraplimits-$NET-state.json" ] && [ -f "$NEG" ] && [ -s "$WL" ] ||
    { say "FAIL $first: no state of an earlier call ($NEXT, deployments/wraplimits-$NET-state.json, $NEG: the same MATRIX_OUT)"; exit 1; }
  rm -f "$R"
fi
say "profile $PROFILE, phases $PHASES"
if [ "$REMOTE" != 1 ]; then
  # each block a fixed step after the last, whatever the wall clock (full: 1 s; short: 10 s, the SCaaS testnet's pace of
  # ~2 Clique blocks per transaction, so the short windows see the testnet's spread); the broadcast's span is added to
  # the next start either way (the stacked gate's slow --slow broadcast outran a fixed margin: VersionNotYetUsable)
  cast rpc --rpc-url "$RPC" anvil_setBlockTimestampInterval "$([ "$PROFILE" = short ] && echo 10 || echo 1)" > /dev/null
fi
ts() { cast block latest --rpc-url "$RPC" -f timestamp; }
utc() { date -u -d "@$1" '+%Y-%m-%d %H:%M:%S UTC'; }
# remote: wait for a block at or after $1, bounded (the time needed + 300 s), a line every 30 s
wait_for() {
  now=$(ts)
  [ "$now" -lt "$1" ] || return 0
  dl=$(($(date +%s) + $1 - now + 300)) i=0
  say "$p: waiting for a block at $1 ($(utc "$1")), $(($1 - now)) s"
  while [ "$now" -lt "$1" ]; do
    [ "$(date +%s)" -le "$dl" ] || { say "FAIL $p: no block at $1 ($(utc "$1")) by $(utc "$dl"), head at $now"; return 1; }
    sleep 5
    i=$((i + 5))
    now=$(ts)
    [ $((i % 30)) != 0 ] || say "$p: waiting for $1 ($(utc "$1")), $(($1 - now)) s left"
  done
}
SLOW=--slow; [ "$REMOTE" != 1 ] || SLOW=
. script/onchain/fee.sh
rc=0 done_=
for p in $PHASES; do
  if [ -s "$NEXT" ]; then
    if [ "$REMOTE" = 1 ]; then
      wait_for "$(cat "$NEXT")" || { rc=1; break; }
    else
      cast rpc --rpc-url "$RPC" evm_setNextBlockTimestamp "$(cat "$NEXT")" > /dev/null
      cast rpc --rpc-url "$RPC" evm_mine > /dev/null
    fi
    mv "$NEXT" "$T/prev" # back if this run fails (a retry of the same phase)
  fi
  t0=$(ts) w0=$(date +%s)
  echo "## wraplimits $p at $t0" >> "$L"
  say "$p: forge at block time $t0 ($(utc "$t0")) …"
  tc=WrapLimits
  [ "$p" != setup ] || tc=WrapLimitsSetup
  rm -f "$B/$p-latest.json"
  remote_fee "$RPC" # a remote target: a fee with headroom (fee.sh)
  ONCHAIN_NET=$NET WRAPLIMITS_PROFILE=$PROFILE forge script script/onchain/WrapLimits.s.sol --tc "$tc" --sig "$p()" \
    --rpc-url "$RPC" --broadcast $SLOW --sender "$SENDER" --disable-code-size-limit --out out/onchain-wraplimits \
    --cache-path cache/onchain-wraplimits > "$T/$p.log" 2>&1 || rc=$?
  cat "$T/$p.log" >> "$L"
  if [ "$REMOTE" = 1 ] && ! grep -q 'No files changed, compilation skipped' "$T/$p.log"; then
    say "FAIL $p: forge did not skip compilation (a remote run compiles under scripts/capped first)"
    rc=1
  fi
  sed -n 's/^  \(wl .*\)/\1/p' "$T/$p.log" | tee -a "$WL" >> "$L"
  if [ "$rc" != 0 ]; then
    say "FAIL $p: $(grep -E '^Error|revert|require' "$T/$p.log" | tail -1 | cut -c1-160)"
    tail -30 "$T/$p.log"
    # the start of this phase again (the failed run may have written the next one's); a failed setup: none
    if [ -f "$T/prev" ]; then mv "$T/prev" "$NEXT"; else rm -f "$NEXT"; fi
    break
  fi
  # the next start written by the run (its simulation's time) + the span of its broadcast on chain
  t1=$(ts)
  if [ -s "$NEXT" ]; then
    echo $(($(cat "$NEXT") + t1 - t0)) > "$T/next" && mv "$T/next" "$NEXT"
  fi
  done_="$done_ $p"
  python3 -I script/onchain/coverage.py --out "$OUTD" neg "$NET" wraplimits "$RPC" > "$T/neg.txt" 2>&1 || rc=1
  cat "$T/neg.txt" >> "$L"
  [ ! -f "$R" ] || { cat "$R" >> "$NEG"; rm -f "$R"; }
  grep '^BAD' "$T/neg.txt" | sed "s/^/[$NET\/wraplimits] FAIL /" || true
  n=$(python3 -I -c "import json, sys; print(len(json.load(open(sys.argv[1]))['receipts']))" "$B/$p-latest.json")
  say "$p ok: $n tx, block time $t0 -> $t1, $(($(date +%s) - w0)) s$(grep '^negatives' "$T/neg.txt" | tail -1 | sed 's/^/, /')"
  [ "$rc" = 0 ] || break
done
# the phases left after the last one run, and the earliest start of the next
last=${done_##* } left= seen=
for p in $ALL; do [ -z "$seen" ] || left="$left $p"; [ "$p" != "$last" ] || seen=1; done
left=${left# }
[ -z "$last" ] || rm -f "$OUTD/pending.txt"
if [ -n "$last" ] && [ -n "$left" ] && [ -s "$NEXT" ]; then
  echo "$left pending: ${left%% *} from $(cat "$NEXT") ($(utc "$(cat "$NEXT")"))" > "$OUTD/pending.txt"
  say "$(cat "$OUTD/pending.txt")"
fi
# every run of this call and the earlier ones (their broadcast files; a call with setup removed the older ones)
runs=
for p in $ALL; do [ ! -f "$B/$p-latest.json" ] || runs="$runs $B/$p-latest.json"; done
[ -n "$runs" ] || exit 1
# the negatives' rows (run by run) after the transactions' (coverage.py forge writes the file anew)
python3 -I script/onchain/coverage.py --out "$OUTD" forge "$NET" "deployments/onchain-$NET-wraplimits.json" $runs >> "$L"
[ ! -f "$NEG" ] || cat "$NEG" >> "$R"
[ "${ONCHAIN_TRACE:-$([ "$NET" = local ] && echo 1)}" != 1 ] ||
  python3 -I script/onchain/coverage.py --out "$OUTD" trace "$NET" wraplimits "$RPC" >> "$L"
# the coverage of the contracts this group touched (their labels in its book), from this build
python3 -I - "$NET" "$T/groups.json" << 'EOF'
import json, sys
book = set(json.load(open(f"deployments/onchain-{sys.argv[1]}-wraplimits.json")).values())
g = json.load(open("script/onchain/groups.json"))["groups"]
json.dump({"groups": {k: [c for c in v if c["label"] in book] for k, v in g.items() if any(c["label"] in book for c in v)}},
          open(sys.argv[2], "w"))
EOF
ONCHAIN_OUT=out/onchain-wraplimits python3 -I script/onchain/coverage.py --out "$OUTD" gen --groups "$T/groups.json" > /dev/null
python3 -I script/onchain/coverage.py --out "$OUTD" views "$NET" "$RPC" >> "$L"
python3 -I script/onchain/coverage.py --out "$OUTD" table --net "$NET" > "$OUTD/table-$NET.txt"
# the summary: every row of every run (its label from the run's rows file, in send order; forge's own CREATE2 library
# deploys listed apart), the gas by row type, the negatives; the records' `what` set to the row
python3 -I - "$OUTD" "$NET" "$CHAIN" "$rc" "$(git rev-parse --short HEAD)" "$ALL" "$WL" "$PROFILE" << 'EOF'
import collections, json, os, sys
outd, net, chain, rc, commit, phases, wl, profile = sys.argv[1:9]
rows, libs, ran = [], [], []
for p in phases.split():
    f = f"broadcast/WrapLimits.s.sol/{chain}/{p}-latest.json"
    if not os.path.exists(f):
        continue
    ran.append(p)
    b = json.load(open(f))
    rec = {x["transactionHash"]: x for x in b["receipts"]}
    lab = [l.rstrip("\n").split(" | ") for l in open(f"deployments/wraplimits-{net}-{p}-rows.txt")]
    # forge's own library deploys come first (CREATE2, named in the run's `libraries`), then the script's rows in order
    n = len(b["transactions"]) - len(lab)
    named = {x.split(":")[1] for x in b.get("libraries", [])}
    assert n >= 0 and all(t.get("contractName") in named for t in b["transactions"][:n]), (p, n, len(lab))
    for t in b["transactions"][:n]:
        x = rec[t["hash"]]
        libs.append((p, t["contractName"], int(t["transaction"]["gas"], 16), int(x["gasUsed"], 16), int(x["status"], 16),
                     t["hash"]))
    for t, l in zip(b["transactions"][n:], lab):
        x = rec[t["hash"]]
        rows.append((p, l[0], " | ".join(l[1:-1]), int(l[-1]), int(x["gasUsed"], 16), int(x["status"], 16), t["hash"]))
rp = os.path.join(outd, f"records-{net}-wraplimits.jsonl")
what = {r[6]: f"{r[1]}: {r[2]}" for r in rows}
recs = [json.loads(x) for x in open(rp)]
for r in recs:
    r["what"] = what.get(r["tx"], r["what"])
open(rp, "w").writelines(json.dumps(r) + "\n" for r in recs)
neg = [r for r in recs if r["what"].startswith("negative")]
ok = sum(r[5] == 1 for r in rows) + sum(x[4] == 1 for x in libs)
asks = [r[3] for r in rows] + [x[2] for x in libs]
prof = {"full": "notice 1 hour, windows 1 hour / 1 day, decay 2 days", "short": "notice 5 min, windows 5 min / 15 min, decay 1 day"}
pend = open(os.path.join(outd, "pending.txt")).read().strip() if os.path.exists(os.path.join(outd, "pending.txt")) else "none"
out = ["# Group 3l T104: group `wraplimits` of the on-chain matrix (spec 2026-11-10-wrap-limits.md §11), target " + net,
       f"# (chain {chain}; this group's own factory; profile {profile}: {prof[profile]}; "
       + ("the clock set between the runs" if net == "local" else "the run waits for the chain's clock") + ").",
       "# Hybrids H1 (kind 1), H5 (kind 5), H13 (kind 13; the PQZ kinds in the OFFCHAIN verify mode). Q = 10^4 raw",
       f"# units of the 6-decimal leg (unitExp 4). Runs: {' '.join(ran)}; pending: {pend}. UNAUDITED.", "",
       "step | commit | rc | counts",
       f"matrix.sh {net} (MATRIX_GROUPS=wraplimits, {' '.join(ran)}) | {commit} | {rc} | {len(rows) + len(libs)} transactions ({ok} status 1;"
       f" {len(libs)} forge library deploys), {len(neg)} negatives ({sum(r['status'] == 2 for r in neg)} refused as"
       f" expected), the largest ask {max(asks):,} gas", "",
       "## gas by row type: the receipts' gasUsed min / max; the largest ask (the row measured on the fork, regular + EIP-8037",
       "## state gas, x 1.05 for a deploy, x 1.30 + 100,000 for a call; anvil's receipt gasUsed shows the regular gas only); rows"]
by = collections.defaultdict(list)
for r in rows:
    by[r[1]].append(r)
for k, v in by.items():
    out.append(f"{k} | {min(r[4] for r in v):,} / {max(r[4] for r in v):,} | {max(r[3] for r in v):,} | {len(v)}")
out += ["", "## forge's library deploys (CREATE2, forge's own gas: its estimate x 1.30) (run | library | asked | gasUsed | status | hash)"]
out += [f"{x[0]} | {x[1]} | {x[2]:,} | {x[3]:,} | {x[4]} | {x[5]}" for x in libs]
out += ["", "## read back through the views (each run's script, at its start, on the node's state; then its own rows)"]
out += [l.rstrip("\n") for l in open(wl)]
out += ["", "## negatives (eth_call at the end of their run, nothing sent; ok = refused with the named error: the whole revert",
        "## data where it is fixed, the selector where it moves with the clock; the records hold both)"]
out += [f"{'ok ' if r['status'] == 2 else 'BAD'} | {r['what'][len('negative: '):]} | {r['expected'][:10]}"
        f"{' and its arguments' if len(r['expected']) > 10 else ''}" for r in neg]
out += ["", "## every row (run | status | gasUsed | asked | hash | row)"]
out += [f"{r[0]} | {r[5]} | {r[4]:,} | {r[3]:,} | {r[6]} | {r[1]}: {r[2]}" for r in rows]
out += ["", "## coverage of the contracts touched (coverage.py table: state-changing called / reached / views reached)"]
out += [l.rstrip("\n") for l in open(os.path.join(outd, f"table-{net}.txt"))]
open(os.path.join(outd, "summary.txt"), "w").write("\n".join(out) + "\n")
print(out[6])
EOF
exit $rc
