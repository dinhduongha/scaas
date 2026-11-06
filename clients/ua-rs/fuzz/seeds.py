# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Fuzz inputs of ua-rs (ua-rs-sign T11) from the vector files (smartcontracts/vectors/ua/):

    python3 -I clients/ua-rs/fuzz/seeds.py <out dir>     the seed corpus, <out>/<target>/, rebuilt by run.sh before each run
    python3 -I clients/ua-rs/fuzz/seeds.py --regress     rewrites regress/<target>/over-*: one input past each cap (committed;
                                                          tests/fuzz_caps.rs reads them, run.sh feeds them to every run)

Seeds: typed_data (sign.json typed generic / canon / refusals, policy td), expect (policy expect), tx (tx rows, published,
refusals), vault (vault.json, rs_vault.json), manifest (a manifest of kem.json's UA rows; the backup / link payloads of
seal.json's containers), container (seal.json containers, acceptance), sealed (seal.json wire), kem_pk (kem.json keys and
encapsRefusals), mnemonic (keys.json mnemonics, normalization); T12: container_expect, members, accepted (seal.json's expect,
members and accepted inputs of an open), uasig (sign.json's msig rows and ua rows as UaSigRequest JSON); T14: zether_cmd (one
byte, the command's index in facade::zether::COMMANDS, then its JSON: clients/zether-prover/vectors/ requests without their key and
witness flag, the disclosure cases, the envelope; the index after the last, zether.json's cache boxes).
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
V = os.path.join(HERE, "../../../smartcontracts/vectors/ua")
ZV = os.path.join(HERE, "../../zether-prover/vectors")
# the order of scaas_ua::facade::zether::COMMANDS (tests/fuzz_caps.rs checks the indices used here); BOX: the box reader
ZCMDS = ["encrypt", "decrypt", "decryptPending", "checkBalance", "proveTransfer", "proveTransferMulti", "proveBurn", "openMemo",
         "recoverTransfer", "openDisclosure", "pop", "ownerAuth", "uaSig", "shieldCalldata", "envelope", "typedDigest", "namedCall"]
BOX = len(ZCMDS)


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
opens = [r for k in ("containers", "acceptance", "replay") for r in seal[k]]
nested = next(r for r in sign["msig"] if r["case"].startswith("nested minimal"))


def uasig(r):
    """A sign.json msig row as a UaSigRequest: its keys numbered in slot order."""
    n = iter(range(64))
    slot = lambda s: ({"index": s["index"], "members": [{"index": x["index"], "key": next(n)} for x in s["members"]]}
                      if "members" in s else {"index": s["index"], "key": next(n)})
    m = {"keyData": r["keyData"], "slots": [slot(s) for s in r["slots"]], **({"inner": r["inner"]} if "inner" in r else {})}
    return {"purpose": r["purposeTag"], "digest": r["digest"], "msig": m}


def zload(name):
    with open(os.path.join(ZV, name), encoding="utf-8") as f:
        return json.load(f)


def zreq(name):
    """A zether-prover vector request as a facade caller sends it: no key, no witness flag."""
    return {k: v for k, v in zload(name)["request"].items() if k not in ("key", "includeWitness")}


def zc(cmd, v):
    return bytes([ZCMDS.index(cmd)]) + js(v)


def zether_seeds():
    t = zreq("transfer_bls12381.json")
    out = [zc("proveTransfer", zreq(f)) for f in ("transfer_bls12381.json", "transfer_noaud_bls12381.json")]
    out += [zc("proveTransferMulti", zreq(f)) for f in ("transfer_multi_bls12381.json", "transfer_multi_noaud_bls12381.json")]
    out += [zc("proveBurn", zreq("burn_bls12381.json")), zc("checkBalance", {"acc": t["acc"], "balance": t["balance"]}),
            zc("decrypt", {"ct": t["acc"], "tableBits": 18, "boundBits": 36}), zc("encrypt", {"Y": t["yTo"], "amount": 5}),
            zc("pop", {"curve": "bls12381"}), zc("ownerAuth", {"digest": "0x" + "11" * 32}),
            zc("uaSig", {"purpose": "metatx", "digest": "0x" + "22" * 32}), zc("shieldCalldata", {"Y": t["yTo"], "amount": 1})]
    out += [zc("openDisclosure", {**{k: v for k, v in c.items() if k not in ("opening", "expect")},
                                  "kind": {1: "receiver", 2: "auditor"}.get(c["kind"], "sender")})
            for c in zload("disclosure_bls12381.json")["cases"]]
    e = zload("envelope.json")
    out += [zc("envelope", {k: e[k] for k in ("chainId", "chainUid", "token", "meta")})]
    out += [bytes([BOX]) + js(r["box"]) for k in ("cacheBox", "cacheRefusals") for r in load("zether.json")[k]]
    return out


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
    yield "container_expect", [js(r["expect"]) for r in opens]
    yield "members", [js(r["members"]) for r in opens if "members" in r]
    yield "accepted", [js(r["accepted"]) for r in opens if r.get("accepted") is not None]
    yield "uasig", [js(uasig(r)) for r in sign["msig"]] + [js({"purpose": r["purposeTag"], "digest": r["digest"], "key": 0}) for r in sign["ua"][:4]]
    yield "zether_cmd", zether_seeds()


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
        # T12: the container open's JSON inputs (16 KiB, depth 4) and the UASig request (64 KiB, depth 6)
        "container_expect/over-depth-5.json": over(seal["acceptance"][0]["expect"], 4),
        "members/over-depth-5.json": over(next(r["members"] for r in opens if "members" in r), 4),
        "accepted/over-depth-5.json": over(next(r["accepted"] for r in opens if r.get("accepted")), 4),
        "uasig/over-depth-7.json": over(uasig(nested), 6),
        # T14: a Zether command (1 MiB, depth 8) and a cache box (2 MiB, depth 1), each behind its index byte
        "zether_cmd/cmd-over-depth-9.bin": bytes([ZCMDS.index("proveTransfer")]) + over(zreq("transfer_bls12381.json"), 8),
        "zether_cmd/box-over-depth-2.bin": bytes([BOX]) + over(load("zether.json")["cacheBox"][0]["box"], 1),
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
