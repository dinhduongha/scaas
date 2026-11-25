#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""R8 at 512 (owner 2026-11-25): the PqChat tree rows near the limits, as one transaction each with the row's forge
(regular, state) pair, on a local Nethermind copy whose chainspec has the SCaaS testnet's Amsterdam transitions (EIP-7825's
2^24 and EIP-8037's state gas enforced; script/onchain/mldsa_on_copy.sh init / up, image scaas/nethermind-pqz). The pairs are
`TreeGasBurner.burnFill(n, k, salt)` arguments that PqChatTreeGasReplicaTest prints (TREE_REPLICA=1): n hash rounds for the
regular gas, k new slots for the state gas, so the copy sees each row's gas, not the row's own calls (those need the
test's world: a registry with stand-in verifiers). Per row: eth_estimateGas, then the transaction with that gas limit:
included (receipt status, gasUsed, block) or refused (the node's error). Test keys 0x...01 (copygen.py). Test only.
  python3 -I runs/2026-11-25-treekem512-nethermind.py <rpc> <TreeGasBurner creation bytecode file>   (from smartcontracts/evm)
Progress lines on stdout; the raw answers in the log path given by TREE512_LOG (git-ignored *.log) if set."""

import json
import os
import subprocess
import sys

KEY = "0x" + "00" * 31 + "01"
# (row, n, k): PqChatTreeGasReplicaTest's output for the forge figures (regular within 0.1 %, state within one slot)
ROWS = [
    # at 20 changes (C10, owner 2026-11-25): PqChatTreeGasReplicaTest's output for the pins of that commit
    ("completion at its bounds (20 changes)", 42362, 292),
    ("last live leaf A-8 ML-DSA-87 (20 changes)", 120632, 279),
    ("last live leaf A-8 ML-DSA-65 (20 changes)", 94118, 259),
    # at 32 changes (the run before C10's change)
    ("completion at its bounds (32 changes)", 63667, 412),
    ("record at its bounds ML-DSA-87 (32 changes)", 122200, 274),
    ("record at its bounds ML-DSA-65 (32 changes)", 95715, 254),
    ("last live leaf 4 UAs ML-DSA-87 (32 changes)", 115235, 247),
    ("last live leaf A-8 ML-DSA-87 (32 changes)", 138123, 321),
    ("last live leaf A-8 ML-DSA-65 (32 changes)", 111567, 301),
    ("control under 2^24", 162353, 10),
    ("control over 2^24", 163823, 10),
]


def cast(*a, check=True):
    r = subprocess.run(["cast", *a], capture_output=True, text=True)
    if check and r.returncode:
        raise RuntimeError(r.stderr.strip()[:400])
    return r


def main(rpc, code_file):
    log = open(os.environ["TREE512_LOG"], "a") if os.environ.get("TREE512_LOG") else None
    code = open(code_file).read().strip()
    out = cast("send", "--json", "--rpc-url", rpc, "--private-key", KEY, "--create", code)
    burner = json.loads(out.stdout)["contractAddress"]
    print(f"[tree512] burner {burner}", flush=True)
    for i, (row, n, k) in enumerate(ROWS):
        data = cast("calldata", "burnFill(uint256,uint256,uint256)", str(n), str(k), str(9_000_000 + i)).stdout.strip()
        est = cast(
            "estimate",
            "--rpc-url",
            rpc,
            "--from",
            "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
            burner,
            data,
            check=False,
        )
        e = est.stdout.strip() if est.returncode == 0 else "refused: " + est.stderr.strip().splitlines()[-1][:200]
        if est.returncode:
            res = "refused at estimate"
        else:
            s = cast(
                "send", "--json", "--rpc-url", rpc, "--private-key", KEY, "--gas-limit", e, burner, data, check=False
            )
            if s.returncode:
                res = "refused: " + s.stderr.strip().splitlines()[-1][:200]
            else:
                rc = json.loads(s.stdout)
                res = f"included: status {int(rc['status'], 16)}, gasUsed {int(rc['gasUsed'], 16)}, block {int(rc['blockNumber'], 16)}"
        line = f"{row} | n={n} k={k} | estimate {e} | {res}"
        print(f"[tree512] {line}", flush=True)
        if log:
            log.write(line + "\n" + est.stdout + est.stderr + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:3]))
