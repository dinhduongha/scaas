#!/usr/bin/env python3
"""Plan 5h Task 7b: Foundry's replay of every transaction xcheck7622.py measured on the SCaaS testnet.

  python3 -I replay.py <xcheck7622 log> http://127.0.0.1:8545 >> log
For each MEASURED row: Nethermind's receipt gasUsed and eth_estimateGas, `cast run <hash> --evm-version amsterdam`
(Foundry 1.8.5 re-executes the transaction on the node's state) and the difference.
"""
import json, re, subprocess, sys

log, rpc = sys.argv[1], sys.argv[2]
print("== replay.py: `cast run <hash> -r <rpc> --evm-version amsterdam` per measured transaction")
print("label | block | calldata B | Nethermind eth_estimateGas | Nethermind receipt gasUsed | Foundry cast run gas | Foundry - Nethermind")
for line in open(log):
    if not line.startswith("MEASURED "):
        continue
    r = json.loads(line[9:])
    out = subprocess.run(["cast", "run", r["hash"], "-r", rpc, "--evm-version", "amsterdam"], capture_output=True,
                         text=True, timeout=600).stdout
    m = re.search(r"Gas used: (\d+)", out)
    f = int(m.group(1)) if m else None
    ok = "successfully" in out
    d = "n/a" if f is None else f"{f - r['gasUsed']:+,}"
    print(f"{r['label']} | {r['block']} | {r['calldata']:,} | {r['estimate']:,} | {r['gasUsed']:,} | "
          f"{'n/a' if f is None else format(f, ',')}{'' if ok else ' (replay not successful)'} | {d}")
