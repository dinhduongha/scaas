#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Group 3l T104 (spec 2026-11-10-wrap-limits.md §11), group `wraplimits` of the on-chain matrix: WrapLimits.s.sol in seven
# forge runs on one node (setup, p1-p6), the chain's clock set between them to the time the previous run wrote
# (evm_setNextBlockTimestamp + evm_mine: a forge script's vm.warp moves only its own simulation), each run's negatives by
# eth_call at its end (coverage.py neg), then the records, the trace, the coverage of the contracts it touched (their
# static views by eth_call too) and the summary (step | commit | rc | counts, every row with its gas and hash). Local
# target only: the windows, the notice and the decay need a clock the run moves (another target: listed as not run).
# From smartcontracts/evm, through scripts/capped, in the foreground (matrix.sh sets the environment):
#   NET=local RPC=<url> DEPLOY_JSON=deployments/<key>.json ONCHAIN_K1=… ONCHAIN_K2=… ONCHAIN_K3=… sh script/onchain/wraplimits.sh
# Output: runs/2026-11-10-ua-mtx-merge-3l-onchain/ (summary.txt, records-<net>-wraplimits.jsonl, coverage.json,
# table-<net>.txt; the log git-ignored). Keys are never printed.
set -eu
: "${NET:?}" "${RPC:?}" "${ONCHAIN_K1:?}"
if [ "$NET" != local ]; then
  echo "not run: wraplimits on $NET (its windows, notice and decay need a clock the run moves: local only)"
  exit 0
fi
OUTD=runs/2026-11-10-ua-mtx-merge-3l-onchain
CHAIN=$(cast chain-id --rpc-url "$RPC")
B=broadcast/WrapLimits.s.sol/$CHAIN
R=$OUTD/records-$NET-wraplimits.jsonl
NEXT=deployments/wraplimits-$NET-next.txt
SENDER=$(cast wallet address --private-key "$ONCHAIN_K1")
L=$OUTD/wraplimits-$NET.log
PHASES="setup p1 p2 p3 p4 p5 p6"
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT INT TERM
mkdir -p "$OUTD"
: > "$L"
rm -f "$R" "$NEXT"
# each block 1 s after the last, whatever the wall clock: a run writes the next start as its simulation's time + the
# notice + 300 s, and a slow broadcast (--slow, one block per transaction) on a loaded machine outran that margin
# (stacked gate: p1 at setup + 3,900 s, the releases usable at setup + 4,282 s, VersionNotYetUsable)
cast rpc --rpc-url "$RPC" anvil_setBlockTimestampInterval 1 > /dev/null
rc=0 runs=
for p in $PHASES; do
  if [ -s "$NEXT" ]; then
    cast rpc --rpc-url "$RPC" evm_setNextBlockTimestamp "$(cat "$NEXT")" > /dev/null
    cast rpc --rpc-url "$RPC" evm_mine > /dev/null
    rm -f "$NEXT"
  fi
  echo "## wraplimits $p at $(cast block latest --rpc-url "$RPC" -f timestamp)" | tee -a "$L"
  tc=WrapLimits
  [ "$p" != setup ] || tc=WrapLimitsSetup
  rm -f "$B/$p-latest.json"
  ONCHAIN_NET=$NET forge script script/onchain/WrapLimits.s.sol --tc "$tc" --sig "$p()" --rpc-url "$RPC" --broadcast --slow \
    --sender "$SENDER" --disable-code-size-limit --out out/onchain-wraplimits --cache-path cache/onchain-wraplimits \
    > "$T/$p.log" 2>&1 || rc=$?
  cat "$T/$p.log" >> "$L"
  sed -n 's/^  \(wl .*\)/\1/p' "$T/$p.log" | tee -a "$T/wl.txt"
  if [ "$rc" != 0 ]; then
    tail -30 "$T/$p.log"
    break
  fi
  runs="$runs $B/$p-latest.json"
  python3 -I script/onchain/coverage.py --out "$OUTD" neg "$NET" wraplimits "$RPC" > "$T/neg.txt" 2>&1 || rc=1
  cat "$T/neg.txt" >> "$L"
  grep '^BAD\|^negatives' "$T/neg.txt" || true
done
[ -n "$runs" ] || exit 1
# the negatives' rows (appended run by run) after the transactions' (coverage.py forge writes the file anew)
[ ! -f "$R" ] || mv "$R" "$T/neg.jsonl"
python3 -I script/onchain/coverage.py --out "$OUTD" forge "$NET" "deployments/onchain-$NET-wraplimits.json" $runs
[ ! -f "$T/neg.jsonl" ] || cat "$T/neg.jsonl" >> "$R"
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
python3 -I - "$OUTD" "$NET" "$CHAIN" "$rc" "$(git rev-parse --short HEAD)" "$PHASES" "$T/wl.txt" << 'EOF'
import collections, json, os, sys
outd, net, chain, rc, commit, phases, wl = sys.argv[1:8]
rows, libs = [], []
for p in phases.split():
    f = f"broadcast/WrapLimits.s.sol/{chain}/{p}-latest.json"
    if not os.path.exists(f):
        continue
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
out = ["# Group 3l T104: group `wraplimits` of the on-chain matrix (spec 2026-11-10-wrap-limits.md §11), target " + net,
       "# (a fresh anvil, chain " + chain + ", Amsterdam; this group's own factory, noticePeriod() 1 hour; the clock set between",
       "# the runs). Hybrids H1 (kind 1), H5 (kind 5), H13 (kind 13; the PQZ kinds in the OFFCHAIN verify mode). Q = 10^4 raw",
       "# units of the 6-decimal leg (unitExp 4). UNAUDITED.", "",
       "step | commit | rc | counts",
       f"matrix.sh {net} (MATRIX_GROUPS=wraplimits) | {commit} | {rc} | {len(rows) + len(libs)} transactions ({ok} status 1;"
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
