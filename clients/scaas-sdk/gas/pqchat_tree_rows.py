# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The SDK's TreeKEM gas rows (gas/pqchat-tree.json, `PqTreeGas`) from forge's measured rows of
smartcontracts/evm/test/pqchat/PqChatTreeGas.t.sol (`GAS <row> regular|state` lines of `forge test -vv`), each pair of
points a line (base + per unit, regular and state apart), the rows with one point taken whole (base 0, conservative). The
same rows are replicated as single transactions on the local Nethermind copy (EIP-7825 and EIP-8037 enforced) by
smartcontracts/evm/runs/2026-11-26-pqchat-treekem-t8-nethermind.py; its summary names the inclusion of each.
  python3 -I clients/scaas-sdk/gas/pqchat_tree_rows.py <forge -vv log> [--check]"""
import json
import re
import sys
from pathlib import Path

DEST = Path(__file__).with_name("pqchat-tree.json")
VERIFY = {"mldsa65": 5_950_000, "mldsa87": 8_860_000}  # accounts.md's verify figures, as PqChatTreeGas.t.sol adds them


def rows(log):
    g = {}
    for m in re.finditer(r"GAS (.+?) (regular|state): (\d+)", log):
        g.setdefault(m.group(1), {}).setdefault(m.group(2), int(m.group(3)))  # the first occurrence of a row
    return g


def pt(g, name):
    r = g[name]
    return r["regular"], r["state"]


def line(a, b, na, nb):
    """`base + per x n` through two points (n = na, nb), regular and state apart, never below 0."""
    per = [max(0, (b[i] - a[i]) // (nb - na)) for i in (0, 1)]
    base = [max(0, a[i] - per[i] * na) for i in (0, 1)]
    return {"base": {"regular": base[0], "state": base[1]}, "per": {"regular": per[0], "state": per[1]}}


def gas(r, s):
    return {"regular": r, "state": s}


def build(g):
    L20, L511 = pt(g, "the list at the bound, 20 targets"), pt(g, "the list of a cold commit, 511 targets")
    K6, K9 = pt(g, "the node keys at the bound, six"), pt(g, "the node keys, depth 9")
    C1, C16 = pt(g, "one ciphertext in addPath"), pt(g, "reachability: a chunk of ciphertexts")
    W15 = pt(g, "15 genesis wraps in one transaction")
    S64, S128 = pt(g, "the session record, 64 member keys"), pt(g, "the session record, 128 member keys")
    RP, RB = pt(g, "commit record, plain, the tree check on a cold tree of 512"), pt(g, "commit record at its bounds, ML-DSA-65")
    CB = pt(g, "completion at its bounds with the held ciphertext")
    wrap = gas(W15[0] // 15, W15[1] // 15)
    return {
        "format": "scaas.pqchat-tree-gas",
        "name": "reference",
        "family": "evm",
        "source": "forge, smartcontracts/evm/test/pqchat/PqChatTreeGas.t.sol (its GAS rows at 512 leaves and 20 changes), by "
        "clients/scaas-sdk/gas/pqchat_tree_rows.py: a line through each pair of measured rows (the list at 20 and 511 "
        "targets, the node keys at 6 and 9, the ciphertexts at 1 and 16, the session record at 64 and 128 keys), the "
        "record's base the plain record on a cold tree of 512 and its per-change the bound record's rest over 20 changes "
        "(admins and info in it), the completion the bound's over 20 changes, a wrap the 15 genesis wraps' fifteenth; each "
        "row replicated on the local Nethermind copy (runs/2026-11-26-pqchat-treekem-t8-nethermind.py). Plan and quote "
        "only: every transaction's limit is its estimate at send time.",
        "verify": VERIFY,
        "session": line(S64, S128, 64, 128),
        "sessionPerAdmin": gas(0, 0),
        "wrap": wrap,
        "wrapFirstOfSubtree": wrap,
        "record": {"base": gas(*RP), "per": gas(max(0, RB[0] - RP[0]) // 20, max(0, RB[1] - RP[1]) // 20)},
        "recordPerAdmin": gas(0, 0),
        "recordPerKibInfo": gas(0, 0),
        "list": line(L20, L511, 20, 511),
        "keys": line(K6, K9, 6, 9),
        "cts": line(C1, C16, 1, 16),
        "completion": {"base": gas(0, 0), "per": gas(CB[0] // 20, CB[1] // 20)},
        "completionPerNode": gas(0, 0),
    }


def main():
    out = json.dumps(build(rows(Path(sys.argv[1]).read_text())), indent=1) + "\n"
    if "--check" in sys.argv:
        ok = DEST.read_text() == out
        print("pqchat_tree_rows: " + ("equal" if ok else "differs: regenerate"))
        return 0 if ok else 1
    DEST.write_text(out)
    print(f"pqchat_tree_rows: wrote {DEST.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
