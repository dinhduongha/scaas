#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Plan 2026-11-23-pqchat-treekem T8: the SDK's TreeKEM gas rows (clients/scaas-sdk/gas/pqchat-tree.json) replicated as one
transaction each on the local Nethermind copy (EIP-7825's 2^24 and EIP-8037's state gas enforced; script/onchain/
mldsa_on_copy.sh init / up, image scaas/nethermind-pqz:2.2.0-pqz11), as 2026-11-25-treekem512-nethermind.py does for the
bound rows: each row's forge (regular, state) pair is `TreeGasBurner.burnFill(n, k, salt)`'s arguments that
PqChatTreeGasReplicaTest prints (TREE_REPLICA=1, `REPLICA <row> n=<n> k=<k>` lines), read here from that forge log. Per row:
eth_estimateGas, then the transaction with that limit: included (status, gasUsed, block) or refused. Test only.
  python3 -I runs/2026-11-26-pqchat-treekem-t8-nethermind.py <rpc> <TreeGasBurner creation bytecode file> <forge log>
Progress lines on stdout."""

import json
import re
import subprocess
import sys

KEY = "0x" + "00" * 31 + "01"


def cast(*a, check=True):
    r = subprocess.run(["cast", *a], capture_output=True, text=True)
    if check and r.returncode:
        raise RuntimeError(r.stderr.strip()[:400])
    return r


def main(rpc, code_file, log_file):
    rows = re.findall(r"REPLICA: (.+?) n=(\d+) k=(\d+)", open(log_file).read())
    if not rows:
        print("[t8] FAIL no REPLICA rows in the log")
        return 1
    code = open(code_file).read().strip()
    burner = json.loads(cast("send", "--json", "--rpc-url", rpc, "--private-key", KEY, "--create", code).stdout)[
        "contractAddress"
    ]
    print(f"[t8] burner {burner}, {len(rows)} rows", flush=True)
    bad = 0
    for i, (row, n, k) in enumerate(rows):
        data = cast("calldata", "burnFill(uint256,uint256,uint256)", n, k, str(7_000_000 + i)).stdout.strip()
        est = cast("estimate", "--rpc-url", rpc, "--from", "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf", burner, data,
                   check=False)
        if est.returncode:
            res = "refused at estimate: " + est.stderr.strip().splitlines()[-1][:200]
            bad += "control over" not in row
        else:
            e = est.stdout.strip()
            s = cast("send", "--json", "--rpc-url", rpc, "--private-key", KEY, "--gas-limit", e, burner, data, check=False)
            if s.returncode:
                res = "refused: " + s.stderr.strip().splitlines()[-1][:200]
                bad += "control over" not in row
            else:
                rc = json.loads(s.stdout)
                res = f"included: status {int(rc['status'], 16)}, gasUsed {int(rc['gasUsed'], 16)}, estimate {e}"
                bad += "control over" in row
        print(f"[t8] {row} | n={n} k={k} | {res}", flush=True)
    print(f"[t8] RESULT {len(rows)} rows, {bad} unexpected")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:4]))
