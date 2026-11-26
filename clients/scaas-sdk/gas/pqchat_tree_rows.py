# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The SDK's TreeKEM gas rows (gas/pqchat-tree.json, `PqTreeGas`) from forge's measured rows of
smartcontracts/evm/test/pqchat/PqChatTreeGasTest (the `GAS <row> regular|state|count` lines of `forge test -vv`; their copy is
gas/pqchat-tree-forge.txt, the evidence `--check` reads). Every term is a line through two measured rows (base + per unit,
regular and state apart, never below 0) or a measured row's rest over the terms before it; no figure is assumed. The verify
caps and signature sizes per kind are docs/contracts/accounts.md's (the registry's own caps). Before writing, the rows are
checked against the measured points they do not come from: the planner's figure is at least each measured one.
  python3 -I clients/scaas-sdk/gas/pqchat_tree_rows.py <forge -vv log or gas/pqchat-tree-forge.txt> [--check]
A forge log is filtered to gas/pqchat-tree-forge.txt when the rows are written."""

import json
import re
import sys
from pathlib import Path

DEST = Path(__file__).with_name("pqchat-tree.json")
EVIDENCE = Path(__file__).with_name("pqchat-tree-forge.txt")
# accounts.md: each kind's verify cap (regular gas) and its signature's bytes (key data and signature as the UASig carries
# them); ML-DSA-87's verify is the cache's measured 8.86 M, as PqChatTreeGas.t.sol adds it
KINDS = {
    "mldsa44": (4_250_000, 2420),
    "mldsa65": (5_950_000, 3309),
    "mldsa87": (8_860_000, 4627),
    "fndsa512": (2_500_000, 666),
    "fndsa1024": (5_250_000, 1280),
    "slhdsa128s": (1_400_000, 7856),
    "ed25519": (210_000, 96),
    "p256": (400_000, 128),
    "webauthn-p256": (400_000, 400),
    "secp256k1": (50_000, 129),
    "bip340": (50_000, 96),
    "schnorr-bn254": (50_000, 160),
    "schnorr-bls12381": (70_000, 288),
    "bls-bn254-minsig": (345_000, 192),
    "bls12381-minsig": (200_000, 384),
    "musig2-secp256k1": (50_000, 64),
    "frost-secp256k1": (50_000, 65),
    "musig2-bn254": (50_000, 96),
    "frost-bn254": (50_000, 96),
    "bls12381-multi": (330_000, 160),
}
SIG65, SIG87 = 3309, 4627  # the rows' signatures (PqChatTreeGas.t.sol SIG65, SIG87)
CAP = 1 << 24
RG = ("regular", "state")


def rows(log):
    g = {}
    for m in re.finditer(r"GAS (.+?) (regular|state|count): (\d+)", log):
        g.setdefault(m.group(1), {}).setdefault(m.group(2), int(m.group(3)))  # the first occurrence of a row
    return g


def pt(g, name):
    r = g[name]
    return r["regular"], r["state"]


def count(g, name):
    return g[name]["count"]


def gas(r, s):
    return {"regular": max(0, r), "state": max(0, s)}


def up(a, n):
    return -(-a // n)


def line(a, b, na, nb):
    """`base + per x n` through two points (n = na, nb), regular and state apart, never below 0 (the slope rounded up)."""
    per = [max(0, up(b[i] - a[i], nb - na)) for i in (0, 1)]
    base = [max(0, a[i] - per[i] * na) for i in (0, 1)]
    return {"base": gas(*base), "per": gas(*per)}


def at(row, n):
    return [row["base"][k] + row["per"][k] * n for k in RG]


def rest(total, minus, n):
    """`(total - minus) / n`, rounded up, regular and state apart."""
    return gas(*[up(total[i] - minus[i], n) for i in (0, 1)])


def sub(a, b):
    return [a[0] - b[0], a[1] - b[1]]


def build(g):
    one_ct = pt(g, "one ciphertext in addPath")
    # the record: its tree term per target (plain records at 31 and 511 targets), per admin and per KiB of info above the
    # plain record's one (the bound record with one admin, with 2 B of info), per Add (the bound record's rest, less a drop
    # per target, below), per Remove (the reachability record's rest)
    P32, P512 = (
        "commit record, plain, on a cold tree of 32",
        "commit record, plain, the tree check on a cold tree of 512",
    )
    W32 = "commit record, plain, on a warm tree of 32"
    assert count(g, W32) == count(g, P32), "the warm and the cold plain record of 32 have the same targets"
    p32 = [max(a, b) for a, b in zip(pt(g, P32), pt(g, W32))]
    record = line(p32, pt(g, P512), count(g, P32), count(g, P512))
    RB = "commit record at its bounds, ML-DSA-65"
    rb, nb = pt(g, RB), count(g, RB)
    per_admin = rest(rb, pt(g, "commit record at its bounds, one admin"), 31)
    per_kib = rest(rb, pt(g, "commit record at its bounds, 2 B of info"), 5 - 1)
    base_b = at(record, nb)
    extra = [base_b[i] + 31 * per_admin[k] + 4 * per_kib[k] for i, k in enumerate(RG)]
    per_add = rest(rb, extra, 20)
    RR = "reachability: the record, 20 forced Removes"
    per_remove = rest(pt(g, RR), at(record, count(g, RR)), 20)
    # the completion with the held ciphertext, that ciphertext's own row taken out: its tree term per target (plain
    # commits at 31 and 511 targets; their node keys, 5 and 9, move with it), per Add (the bound's rest), per Remove (the
    # reachability's rest)
    C32, C512 = "completion of a plain commit, cold tree of 32", "completion of a plain commit, cold tree of 512"
    completion = line(sub(pt(g, C32), one_ct), sub(pt(g, C512), one_ct), count(g, P32), count(g, P512))
    CB = "completion at its bounds with the held ciphertext"
    c_add = rest(sub(pt(g, CB), one_ct), at(completion, nb), 20)
    CR = "reachability: the held ciphertext with the completion"
    c_remove = rest(sub(pt(g, CR), one_ct), at(completion, count(g, RR)), 20)
    # a commit with no piece (the last live leaf's Removes, with its completion), 4,124 B of info: at 20 Removes the larger
    # of A-8's (the admins 1 -> 32, new slots) and A-17's (the worst head, 32 admins replaced) each way; at 1 Remove the
    # worst head's row with A-8's new admin slots over A-17's (their state's rest at 20) added
    a8 = pt(g, "the last live leaf at the spec's bound, ML-DSA-65, one transaction")
    a17 = pt(g, "the last live leaf on the worst head, ML-DSA-65, one transaction")
    one = pt(g, "the last live leaf on the worst head, one Remove, ML-DSA-65, one transaction")
    slots = max(0, a8[1] - a17[1])
    no_piece = line([one[0], one[1] + slots], [max(a8[0], a17[0]), max(a8[1], a17[1])], 1, 20)
    # a signature's bytes above the rows' 3,309: the ML-DSA-87 rows' rest over the ML-DSA-65 ones (the larger of the
    # record's and the no-piece commit's)
    d = [
        sub(pt(g, a + "87" + b), pt(g, a + "65" + b))
        for a, b in (
            ("commit record at its bounds, ML-DSA-", ""),
            ("the last live leaf on the worst head, ML-DSA-", ", one transaction"),
        )
    ]
    per_sig = rest([max(x[0] for x in d), max(x[1] for x in d)], [0, 0], SIG87 - SIG65)
    # an Add on a large tree costs less than on a small one (the tree term already reads its paths): the Add's rest at the
    # 20 Adds on the reached tree of 491 (ML-DSA-87, its signature's bytes taken out) gives a drop per target, floored, so
    # both measured points stay at or under the rows
    RH = "commit record, 20 Adds on the reached tree of 491, ML-DSA-87"
    nh = count(g, RH)
    hi = rest(pt(g, RH), [at(record, nh)[i] + (SIG87 - SIG65) * per_sig[k] for i, k in enumerate(RG)], 20)
    drop = {k: max(0, (per_add[k] - hi[k]) // (nh - nb)) for k in RG}
    per_add = {k: per_add[k] + drop[k] * nb for k in RG}
    C4, C11 = "creation in one transaction, 4 member keys", "creation in one transaction, 11 member keys"
    creation = line(pt(g, C4), pt(g, C11), count(g, C4), count(g, C11))
    creation_admin = rest(pt(g, "creation in one transaction, 4 member keys, 32 admins"), pt(g, C4), 31)
    W15 = pt(g, "15 genesis wraps in one transaction")
    assert count(g, "reachability: a chunk of ciphertexts") == 16, "the chunk row holds 16 ciphertexts"
    L20, L511 = pt(g, "the list at the bound, 20 targets"), pt(g, "the list of a cold commit, 511 targets")
    K6, K9 = pt(g, "the node keys at the bound, six"), pt(g, "the node keys, depth 9")
    return {
        "format": "scaas.pqchat-tree-gas",
        "name": "reference",
        "family": "evm",
        "source": "forge, smartcontracts/evm/test/pqchat/PqChatTreeGas.t.sol (its GAS rows at 512 leaves and 20 changes; the "
        "lines in clients/scaas-sdk/gas/pqchat-tree-forge.txt), by clients/scaas-sdk/gas/pqchat_tree_rows.py: each term a "
        "line through two measured rows or a measured row's rest over the terms before it, every measured point it does "
        "not come from checked at or under the rows. The verify caps and signature sizes are docs/contracts/accounts.md's. "
        "The T8 run on the local Nethermind copy (runs/2026-11-26-pqchat-treekem-t8-nethermind.py) included one burner "
        "transaction at the figures of each of its eight earlier points; the rows of this file are forge's. Plan and "
        "quote only: every transaction's limit is its estimate at send time.",
        "kinds": {k: {"verify": v, "sigBytes": b} for k, (v, b) in KINDS.items()},
        "sigRef": SIG65,
        "perSigByte": per_sig,
        "creation": creation,
        "creationPerAdmin": creation_admin,
        "wrap": gas(up(W15[0], 15), up(W15[1], 15)),
        "record": record,
        "recordPerAdd": per_add,
        "recordPerAddDrop": drop,
        "recordPerRemove": per_remove,
        "recordPerAdmin": per_admin,
        "recordPerKibInfo": per_kib,
        "list": line(L20, L511, 20, 511),
        "keys": line(K6, K9, 6, 9),
        "cts": line(one_ct, pt(g, "reachability: a chunk of ciphertexts"), 1, 16),
        "completion": completion,
        "completionPerAdd": c_add,
        "completionPerRemove": c_remove,
        "noPiece": no_piece,
    }


def checks(j, g):
    """The measured points the rows do not come from: the rows' figure at each is at least the measured one."""

    def sig(k):
        return [max(0, KINDS[k][1] - SIG65) * j["perSigByte"][x] for x in RG]

    fails = []

    def ge(what, model, measured):
        if model[0] < measured[0] or model[1] < measured[1]:
            fails.append(f"{what}: rows {model} under measured {list(measured)}")

    def rec(cts, adds, removes, admins, kib, k):
        return [
            at(j["record"], cts)[i]
            + adds * max(0, j["recordPerAdd"][x] - cts * j["recordPerAddDrop"][x])
            + removes * j["recordPerRemove"][x]
            + (admins - 1) * j["recordPerAdmin"][x]
            + (kib - 1) * j["recordPerKibInfo"][x]
            + sig(k)[i]
            for i, x in enumerate(RG)
        ]

    def no(n, k):
        return [at(j["noPiece"], n)[i] + sig(k)[i] for i in (0, 1)]

    ge("the bound record, ML-DSA-87", rec(20, 20, 0, 32, 5, "mldsa87"), pt(g, "commit record at its bounds, ML-DSA-87"))
    rh = "commit record, 20 Adds on the reached tree of 491, ML-DSA-87"
    ge(rh, rec(count(g, rh), 20, 0, 1, 1, "mldsa87"), pt(g, rh))
    if rec(count(g, rh), 20, 0, 1, 1, "mldsa87")[0] + KINDS["mldsa87"][0] > CAP:
        fails.append(rh + ": over 2^24 by the rows")
    warm = "commit record, plain, on a warm tree of 32"
    ge(warm, rec(count(g, warm), 0, 0, 1, 1, "mldsa65"), pt(g, warm))
    for k, row in (
        ("mldsa65", "the last live leaf at the spec's bound, ML-DSA-65, one transaction"),
        ("mldsa87", "the last live leaf at the spec's bound, ML-DSA-87, one transaction"),
        ("mldsa87", "the last live leaf on the worst head, ML-DSA-87, one transaction"),
        ("mldsa65", "the commit of the last live leaf at its bounds, ML-DSA-65, one transaction"),
        ("mldsa87", "the commit of the last live leaf at its bounds, ML-DSA-87, one transaction"),
    ):
        ge(row, no(20, k), pt(g, row))
    if no(20, "mldsa87")[0] + KINDS["mldsa87"][0] >= CAP:
        fails.append("the no-piece commit at 20 Removes, ML-DSA-87: at or over 2^24")
    one_ct = pt(g, "one ciphertext in addPath")
    fx = "completion with the held ciphertext, 32 -> 52 keys (codex-r3-6)"
    comp = [at(j["completion"], 20)[i] + 20 * j["completionPerAdd"][x] + one_ct[i] for i, x in enumerate(RG)]
    ge(fx, comp, pt(g, fx))
    return fails


def main():
    g = rows(Path(sys.argv[1]).read_text())
    j = build(g)
    bad = checks(j, g)
    if bad:
        print("pqchat_tree_rows: the rows fall under measured points:\n  " + "\n  ".join(bad))
        return 1
    out = json.dumps(j, indent=1) + "\n"
    evidence = "".join(f"GAS {k} {x}: {v}\n" for k, r in g.items() for x, v in r.items())
    if "--check" in sys.argv:
        ok = DEST.read_text() == out and EVIDENCE.read_text() == evidence
        print("pqchat_tree_rows: " + ("equal" if ok else "differs: regenerate"))
        return 0 if ok else 1
    DEST.write_text(out)
    EVIDENCE.write_text(evidence)
    print(f"pqchat_tree_rows: wrote {DEST.name} and {EVIDENCE.name} ({len(g)} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
