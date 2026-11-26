# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The JSON ABI items pqchat-core reads and writes (src/abi.json), cut from forge's build of the contracts' interfaces:
`IPqChat` whole (its tree entries take `IPqGroupTree`'s `TreeAdd` / `TreeRemove`, review A-6: forge inlines them as tuples, so
that file adds no item and is read to fail loudly if it moves), the registry's and the factory's views the crate reads.
Generated, never edited by hand.
  python3 -I clients/pqchat-core/runs/gen_abi.py [--check]     (after `forge build` in smartcontracts/evm)"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
OUT = ROOT / "smartcontracts/evm/out"
DEST = ROOT / "clients/pqchat-core/src/abi.json"
PICK = {
    "IPqChat.sol/IPqChat.json": None,
    "IPqGroupTree.sol/IPqGroupTree.json": [],
    "IUARegistry.sol/IUARegistry.json": ["kemKeyOf", "kemKeyAt", "checkedOf", "memberAccepted", "msigOf"],
    "IOpenFactory.sol/IOpenFactory.json": ["infoOf", "contractsPage"],
}


def items():
    out = {}
    for f, names in PICK.items():
        abi = json.loads((OUT / f).read_text())["abi"]
        contract = f.split("/")[1].removesuffix(".json")
        for it in abi:
            if it.get("type") != "function" or (names is not None and it["name"] not in names):
                continue
            key = f"{contract}.{it['name']}"
            assert key not in out, f"overloaded: {key}"
            out[key] = it
        if names is not None:
            missing = set(names) - {k.split(".")[1] for k in out if k.startswith(contract + ".")}
            assert not missing, f"{contract}: {missing}"
    return dict(sorted(out.items()))


def main():
    text = json.dumps(items(), indent=1, sort_keys=True) + "\n"
    if "--check" in sys.argv:
        if DEST.read_text() != text:
            print("gen_abi: src/abi.json differs from forge's build: regenerate")
            return 1
        print("gen_abi: src/abi.json equals forge's build")
        return 0
    DEST.write_text(text)
    print(f"gen_abi: {len(json.loads(text))} items")
    return 0


if __name__ == "__main__":
    sys.exit(main())
