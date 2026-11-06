# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Fuzz inputs of ua-rs (ua-rs-sign T11) from the vector files (smartcontracts/vectors/ua/):

    python3 -I clients/ua-rs/fuzz/seeds.py <out dir>     the seed corpus, <out>/<target>/, rebuilt by run.sh before each run
    python3 -I clients/ua-rs/fuzz/seeds.py --regress     rewrites regress/<target>/over-*: one input past each cap (committed;
                                                          tests/fuzz_caps.rs reads them, run.sh feeds them to every run)

Seeds: typed_data (sign.json typed generic / canon / refusals, policy td), expect (policy expect), tx (tx rows, published,
refusals), vault (vault.json, rs_vault.json), manifest (a manifest of kem.json's UA rows; the backup / link payloads of
seal.json's containers), container (seal.json containers, acceptance), sealed (seal.json wire), kem_pk (kem.json keys and
encapsRefusals), mnemonic (keys.json mnemonics, normalization).
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
V = os.path.join(HERE, "../../../smartcontracts/vectors/ua")


def load(name):
    with open(os.path.join(V, name), encoding="utf-8") as f:
        return json.load(f)


def js(v):
    return json.dumps(v, separators=(",", ":"), ensure_ascii=False).encode()


def unhex(s):
    return bytes.fromhex(s[2:] if s.startswith("0x") else s)


sign, seal, kem, keys = load("sign.json"), load("seal.json"), load("kem.json"), load("keys.json")
manifest = {"v": 1, "entries": [{"kind": r["kind"], "account": r["account"], "index": r["index"], "ua": r["ua"]} for r in kem["keys"]],
            "natives": [], "kem": [], "imports": [], "backupGeneration": 0, "backupSenders": []}
payloads = [unhex(c["pt"]) for c in seal["containers"] if c["container"]["purpose"] in ("scaas/backup/v1", "scaas/link/v1")]


def seeds():
    t = sign["typed"]
    yield "typed_data", [js(r["td"]) for k in ("generic", "canon", "refusals") for r in t[k]] + [js(r["td"]) for r in sign["policy"]]
    yield "expect", [js(r["expect"]) for r in sign["policy"] if "expect" in r]
    yield "tx", [js(r["tx"]) for k in ("rows", "published", "refusals") for r in sign["tx"][k]]
    yield "vault", [js(r["vault"]) for f in ("vault.json", "rs_vault.json") for r in load(f)["vaults"]]
    yield "manifest", [js(manifest)] + payloads
    yield "container", [js(r["container"]) for k in ("containers", "acceptance") for r in seal[k]]
    yield "sealed", [unhex(r["wire"]) for r in seal["seal"]]
    yield "kem_pk", [unhex(r["kemPk"]) for k in ("keys", "encapsRefusals") for r in kem[k]]
    yield "mnemonic", [r["words"].encode() for k in ("mnemonics", "normalization") for r in keys[k]]


def nest(n):
    """`n` nested arrays around 0: depth n."""
    return json.loads("[" * n + "0" + "]" * n)


def over(v, cap):
    """`v` (an object, depth 1 or more) with a key `x` of depth cap: the whole is depth cap + 1."""
    return js({**v, "x": nest(cap)})


def regress():
    """name -> bytes: one input past each cap (depth for the JSON decoders), else what the target's bound refuses."""
    words = keys["mnemonics"][0]["words"]
    wire = unhex(seal["seal"][0]["wire"])
    pk = unhex(kem["keys"][0]["kemPk"])
    return {
        "typed_data/over-depth-9.json": over(sign["typed"]["generic"][0]["td"], 8),
        "expect/over-depth-5.json": over(sign["policy"][0]["expect"], 4),
        "tx/over-depth-5.json": over(sign["tx"]["rows"][0]["tx"], 4),
        "vault/over-depth-3.json": over(load("vault.json")["vaults"][0]["vault"], 2),
        "manifest/over-depth-4.json": over(manifest, 3),
        "manifest/payload-over-depth-5.json": over(json.loads(payloads[0]), 4),
        "container/over-depth-8.json": over(seal["containers"][0]["container"], 7),
        # no depth: the wire form one byte short of its fixed fields and tag (a 15-byte tag)
        "sealed/short-tag.bin": wire[: 2 + 1568 + 32 + 15],
        # no depth: a scheme-2 key of the right length, and a scheme-1 key one byte long
        "kem_pk/scheme-2.bin": b"\x02" + pk[1:],
        "kem_pk/len-1602.bin": pk + b"\x00",
        # no depth: 24 valid words padded with spaces to 1,025 bytes, and 25 words
        "mnemonic/over-1025-bytes.txt": (words + " " * (1025 - len(words.encode()))).encode(),
        "mnemonic/over-25-words.txt": (words + " " + words.split()[0]).encode(),
    }


if sys.argv[1:] == ["--regress"]:
    for name, b in regress().items():
        p = os.path.join(HERE, "regress", name)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(b)
    print(f"regress/: {len(regress())} inputs")
elif len(sys.argv) == 2:
    n = 0
    for t, items in seeds():
        d = os.path.join(sys.argv[1], t)
        os.makedirs(d, exist_ok=True)
        for i, b in enumerate(items):
            with open(os.path.join(d, f"{i:03}"), "wb") as f:
                f.write(b)
        n += len(items)
        print(f"seeds/{t}: {len(items)}")
    print(f"seeds: {n}")
else:
    sys.exit(__doc__)
