# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Round 3zb + 3zc (spec 2026-11-13-burner-wrap-caps.md §3.5, §3.6, §3.8, §3.9; CTR-GOV-28 Change, CTR-GOV-30): in
`entries.json`, every role holder's direct entry (24 on the token kinds; the DEX's four are hand-written stubs) and
`setWrapLimits` gain a trailing `bytes32 chainUid_`; the wrapped kinds gain `setMaxSupply`, `setMaxWrapSupply` and the
views `maxWrapSupply`, `totalWrapped`, `reserveValue`, `pendingSupplyCaps` in module W. Idempotent. Selectors by
`cast sig`. usage (from smartcontracts/evm): python3 script/modules/add_chainword_3zbc.py; then gen_faces.py."""

import json
import subprocess

WORD = [
    "mint",
    "mintToUA",
    "disableWrap",
    "proposeRate",
    "cancelRate",
    "executeRate",
    "setWrapMember",
    "setWrapLimits",
    "setAllowed",
    "setDenied",
    "freeze",
    "unfreeze",
    "forceTransfer",
    "pause",
    "unpause",
    "recordOrder",
    "revokeOrder",
    "operatorTransfer",
    "setTaxRate",
    "setTaxRecipient",
    "setProofStore",
]


def sel(sig):
    return subprocess.run(["cast", "sig", sig], capture_output=True, text=True, check=True).stdout.strip()[2:]


def row(name, sig, params, names, mut="nonpayable", guard="nonReentrant", returns=""):
    return {
        "sel": sel(sig),
        "sig": sig,
        "name": name,
        "decl": "WrappedToken",
        "kept": False,
        "mut": mut,
        "guard": guard,
        "params": params,
        "names": names,
        "returns": returns,
        "ifaces": ["IWrappedToken"],
        "vis": "external",
        "domain": "wrapped",
        "group": "W",
    }


NEW = [
    row(
        "setMaxSupply",
        "setMaxSupply(uint256,bytes32)",
        ["uint256 newMaxSupply", "bytes32 chainUid_"],
        ["newMaxSupply", "chainUid_"],
    ),
    row(
        "setMaxWrapSupply",
        "setMaxWrapSupply(uint256,bytes32)",
        ["uint256 newMaxWrapSupply", "bytes32 chainUid_"],
        ["newMaxWrapSupply", "chainUid_"],
    ),
    row("maxWrapSupply", "maxWrapSupply()", [], [], "view", "", "uint256 _p0"),
    row("totalWrapped", "totalWrapped()", [], [], "view", "", "uint256 _p0"),
    row("reserveValue", "reserveValue()", [], [], "view", "", "uint256 _p0"),
    row(
        "pendingSupplyCaps",
        "pendingSupplyCaps()",
        [],
        [],
        "view",
        "",
        "uint256 pendingMaxSupply, uint64 maxSupplyEta, bool maxSupplyLive, uint256 pendingMaxWrapSupply, "
        "uint64 maxWrapSupplyEta, bool maxWrapSupplyLive",
    ),
]

E = json.load(open("script/modules/entries.json"))
moved = 0
for k, rows in E["kinds"].items():
    for e in rows:
        if e["name"] in WORD and e["names"][-1:] != ["chainUid_"]:
            e["params"].append("bytes32 chainUid_")
            e["names"].append("chainUid_")
            e["sig"] = e["sig"][:-1] + (",bytes32)" if e["sig"][-2] != "(" else "bytes32)")
            e["sel"] = sel(e["sig"])
            moved += 1
    if k.startswith("Wrapped"):
        for r in NEW:
            if all(x["name"] != r["name"] for x in rows):
                rows.append(dict(r))
        rows.sort(key=lambda r: (r["name"], r["sig"]))
open("script/modules/entries.json", "w").write(json.dumps(E, indent=1) + "\n")
print("moved", moved)
