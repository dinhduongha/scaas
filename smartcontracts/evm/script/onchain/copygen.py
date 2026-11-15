#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T66b Step 5b: the local copy's genesis for the on-chain matrix, after `copy.sh init` and `copy.sh genesis0`: the
SCaaS testnet's Amsterdam transitions (patch-chainspec.py's AMSTERDAM list, from timestamp 1; EIP-7954 stays off, as a
reset removes it), which `init`'s chainspec lacks (without them the copy caps a transaction at 2^24 and charges no
EIP-8037 state gas), the genesis-funded test keys 0x…01-0x…03 and the deterministic CREATE2 deployer (NET-EVM-05).
  python3 -I script/onchain/copygen.py <copy dir>          (rewrites <copy dir>/genesis.pqz0.json)
Test chains only."""
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PATCH = os.path.join(HERE, "../../../../pqz-core/nethermind/chain/patch-chainspec.py")
CREATE2 = "0x4e59b44847b379578588920ca78fbf26c0b4956c"
CREATE2_CODE = ("0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f580151560"
                "39578182fd5b8082525050506014600cf3")
KEYS = ["0x7e5f4552091a69125d5dfcb7b8c2659029395bdf", "0x2b5ad5c4795c026514f8317c7a215e218dccd6cf",
        "0x6813eb9362372eef6200f3b1dbc3f819671cba69"]  # keys 0x…01, 0x…02, 0x…03


def main(copy):
    spec = importlib.util.spec_from_file_location("patch_chainspec", PATCH)
    pc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pc)
    p = os.path.join(copy, "genesis.pqz0.json")
    g = json.load(open(p))
    if int(g["params"]["chainId"], 16) != pc.TESTNET:
        sys.exit(f"{p}: not a copy of the SCaaS testnet")
    for n in pc.AMSTERDAM:
        if n != 7954:
            g["params"][f"eip{n}TransitionTimestamp"] = 1
    for a in KEYS:
        g["accounts"][a] = {"balance": hex(10**30)}
    g["accounts"][CREATE2] = {"balance": "0x0", "code": CREATE2_CODE}
    json.dump(g, open(p, "w"), indent=1)
    print(f"{p}: Amsterdam from timestamp 1, keys 1-3 funded, CREATE2 deployer")


if __name__ == "__main__":
    main(sys.argv[1])
