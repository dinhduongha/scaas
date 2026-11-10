# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T66b task 4.3 (spec 2026-11-09-t66b-library-organisation.md §10): the pre-split releases for the differential tests.

    python3 script/modules/legacy_artifacts.py build    # export d142b57c's src, build it (scripts/capped), write the json
    python3 script/modules/legacy_artifacts.py json <pre-split out dir>
    python3 script/modules/legacy_artifacts.py abi <pre-split out dir> <current out dir>
    python3 script/modules/legacy_artifacts.py faceabi <pre-split out dir> <current out dir>   # before I<Kind>Abi exists

`json` writes out/t66b-legacy/ (git-ignored, read by test/modules/: libs.json, k<kind>.json, dex.json): for each token kind and the DEX, the pre-split
implementation's init code with its libraries linked, the libraries' linked init code in deploy order (each by CREATE2
through the deterministic deployer with salt `keccak256("scaas.t66b.legacy")`, so every address is known here), and one
call row per external function (selector, signature, mutability, ABI-encoded sample arguments). `abi` compares each face's
external functions, events and errors with the pre-split ABI (rc 1 unless functions = pre-split + `modules()` (+ `pqzSet()`
on 4, 5, 12, 13), events = pre-split, errors = pre-split + the three module errors). Nothing here is committed output: the build is local. UNAUDITED tooling."""
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EVM = os.path.abspath(os.path.join(HERE, "../.."))
ROOT = os.path.abspath(os.path.join(EVM, "../.."))
sys.path.insert(0, os.path.join(ROOT, "pqz-core/nethermind/chain"))
from eth import keccak256  # noqa: E402

PRE = "d142b57c"
DEPLOYER = bytes.fromhex("4e59b44847b379578588920ca78fbf26c0b4956c")
SALT = keccak256(b"scaas.t66b.legacy")
KINDS = {0: "NormalToken", 1: "WrappedToken", 2: "NormalZetherToken", 3: "WrappedZetherToken", 4: "NormalPqzToken",
         5: "WrappedPqzToken", 8: "NormalRegulatedToken", 9: "WrappedRegulatedToken", 10: "NormalZetherRegulatedToken",
         11: "WrappedZetherRegulatedToken", 12: "NormalPqzRegulatedToken", 13: "WrappedPqzRegulatedToken"}
SAMPLE_ADDR = 0xB0B


def art(out, name, src=None):
    return json.load(open(os.path.join(out, (src or name) + ".sol", name + ".json")))


def create2(init):
    return keccak256(b"\xff" + DEPLOYER + SALT + keccak256(init))[12:]


class Linker:
    def __init__(self, out):
        self.out, self.addr, self.order = out, {}, []

    def link(self, j):
        code = j["bytecode"]["object"].removeprefix("0x")
        for ls in j["bytecode"]["linkReferences"].values():
            for ln, pos in ls.items():
                a = self.lib(ln)
                for p in pos:
                    code = code[:2 * p["start"]] + a.hex() + code[2 * (p["start"] + p["length"]):]
        return bytes.fromhex(code)

    def lib(self, name):
        if name not in self.addr:
            init = self.link(art(self.out, name))  # its own libraries first
            self.addr[name] = create2(init)
            self.order.append({"name": name, "init": "0x" + init.hex(), "addr": "0x" + self.addr[name].hex()})
        return self.addr[name]


# ------------------------------------------------------------------ sample arguments (head / tail ABI encoding)

def _static(t):
    if t["type"].endswith("[]") or t["type"] in ("bytes", "string"):
        return False
    if t["type"].startswith("tuple"):
        if t["type"].endswith("]"):
            return _static({"type": "tuple", "components": t["components"]})
        return all(_static(c) for c in t["components"])
    return True


def _enc(t):
    ty = t["type"]
    if ty.endswith("[]"):
        return (0).to_bytes(32, "big")  # an empty array
    m = re.fullmatch(r"(.*)\[(\d+)\]", ty)
    if m:
        inner = dict(t, type=m.group(1))
        return _encs([inner] * int(m.group(2)))
    if ty.startswith("tuple"):
        return _encs(t["components"])
    if ty in ("bytes", "string"):
        return (0).to_bytes(32, "big")
    if ty == "address":
        return SAMPLE_ADDR.to_bytes(32, "big")
    if ty == "bool" or ty.startswith("uint") or ty.startswith("int"):
        return (1).to_bytes(32, "big")
    return bytes(32)  # bytesN


def _encs(ts):
    head, tail = [], b""
    hl = sum(32 if not _static(t) else len(_enc(t)) for t in ts)
    for t in ts:
        e = _enc(t)
        if _static(t):
            head.append(e)
        else:
            head.append((hl + len(tail)).to_bytes(32, "big"))
            tail += e
    return b"".join(head) + tail


def _sig(f):
    def ty(t):
        if t["type"].startswith("tuple"):
            return "(" + ",".join(ty(c) for c in t["components"]) + ")" + t["type"][5:]
        return t["type"]
    return f["name"] + "(" + ",".join(ty(i) for i in f["inputs"]) + ")"


def rows(j):
    r = []
    for f in j["abi"]:
        if f["type"] != "function":
            continue
        s = _sig(f)
        sel = keccak256(s.encode())[:4]
        assert "0x" + sel.hex() == "0x" + j["methodIdentifiers"][s], s
        r.append({"sig": s, "mutability": f["stateMutability"], "data": "0x" + (sel + _encs(f["inputs"])).hex()})
    return r


def write_json(out):
    L = Linker(out)
    res = {"commit": PRE, "salt": "0x" + SALT.hex(), "kinds": {}, "dex": None}
    for k, n in KINDS.items():
        j = art(out, n)
        res["kinds"][str(k)] = {"name": n, "init": "0x" + L.link(j).hex(), "rows": rows(j)}
    j = art(out, "SCaaSDex")
    res["dex"] = {"name": "SCaaSDex", "init": "0x" + L.link(j).hex(), "rows": rows(j)}
    d = os.path.join(EVM, "out/t66b-legacy")
    os.makedirs(d, exist_ok=True)
    # one file each (a test parses only the kind it needs): libs.json, k<kind>.json, dex.json
    json.dump({"commit": PRE, "salt": res["salt"], "libs": L.order}, open(os.path.join(d, "libs.json"), "w"))
    for k, v in res["kinds"].items():
        json.dump(v, open(os.path.join(d, f"k{k}.json"), "w"))
    json.dump(res["dex"], open(os.path.join(d, "dex.json"), "w"))
    print(f"{d}: {len(L.order)} libraries, {len(KINDS)} kinds + the DEX, "
          f"{sum(len(v['rows']) for v in res['kinds'].values()) + len(res['dex']['rows'])} rows")


def _kind_modules(k):
    src = open(os.path.join(EVM, "script/KindModules.sol")).read()
    m = re.search(r"if \(kind == %d\) \{(.*?)return n;" % k, src, re.S)
    return re.findall(r'"(\w+)\.sol:(\w+)"', m.group(1))


def _named(j, t):
    def ty(x):
        if x["type"].startswith("tuple"):
            return "(" + ",".join(ty(c) for c in x["components"]) + ")" + x["type"][5:]
        return x["type"]
    return {x["name"] + "(" + ",".join(ty(i) for i in x["inputs"]) + ")" for x in j["abi"] if x["type"] == t}


MODULE_ERRORS = {"ModuleMissing(uint256)", "ModuleMismatch(uint256)", "NotDelegated()"}  # T66b §4.5, M2


def abi(old, new):
    """Each face against the pre-split face (d142b57c): its external functions are the pre-split ones and `modules()` (and
    `pqzSet()` on 4, 5, 12, 13); its events are the pre-split ones; its errors the pre-split ones and the three module
    errors (controller 2026-11-09, option B). The number of faces that differ (0 passes)."""
    bad = 0
    for k, n in KINDS.items():
        o, w = art(old, n), art(new, n)
        so, sw = set(o["methodIdentifiers"]), set(w["methodIdentifiers"])
        want = {"modules()"} | ({"pqzSet()"} if k in (4, 5, 12, 13) else set())
        eo, ew = _named(o, "event"), _named(w, "event")
        ro, rw = _named(o, "error"), _named(w, "error")
        ok = sw == so | want and ew == eo and rw == ro | MODULE_ERRORS
        bad += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {k:2} {n}: functions {len(so)} -> {len(sw)} (added {sorted(sw - so)}, missing "
              f"{sorted(so - sw)}); events {len(eo)} -> {len(ew)} (added {sorted(ew - eo)}, missing {sorted(eo - ew)}); "
              f"errors {len(ro)} -> {len(rw)} (added {sorted(rw - ro)}, missing {sorted(ro - rw)})")
    return bad


def _decls(j, t):
    return {_named({"abi": [x]}, t).pop(): x for x in j["abi"] if x["type"] == t}


def face_abi(old, new):
    """script/modules/face_abi.json, gen_faces.py's input for each face's `I<Kind>Abi` (controller 2026-11-09, option B): the
    events and errors of the pre-split face (d142b57c) that the face does not declare without it, as ABI entries."""
    out = {}
    for k, n in KINDS.items():
        o, w = art(old, n), art(new, n)
        out[n] = {t: [v for s, v in sorted(_decls(o, t).items()) if s not in _decls(w, t)] for t in ("event", "error")}
    p = os.path.join(EVM, "script/modules/face_abi.json")
    json.dump({"_comment": "GENERATED by script/modules/legacy_artifacts.py faceabi from the pre-split faces (d142b57c): per kind, "
               "the events and errors its face declares through I<Kind>Abi (gen_faces.py)", "commit": PRE, "kinds": out},
              open(p, "w"), indent=1, sort_keys=True)
    print(p, {n: (len(v["event"]), len(v["error"])) for n, v in out.items()})


def build():
    pre = os.path.join(ROOT, "scratchpad/t66b-pre")
    if not os.path.isdir(os.path.join(pre, "smartcontracts/evm/out")):
        subprocess.run(["rm", "-rf", pre], check=True)
        os.makedirs(pre)
        a = subprocess.run(["git", "-C", ROOT, "archive", "--format=tar", PRE, "smartcontracts/evm/src",
                            "smartcontracts/evm/foundry.toml"], check=True, capture_output=True).stdout
        subprocess.run(["tar", "-x", "-C", pre], input=a, check=True)
        subprocess.run(["cp", "-al", os.path.join(EVM, "lib"), os.path.join(pre, "smartcontracts/evm/lib")], check=True)
        subprocess.run([os.path.join(ROOT, "scripts/capped"), os.path.expanduser("~/.foundry/bin/forge"), "build", "src"],
                       cwd=os.path.join(pre, "smartcontracts/evm"), check=True, stdout=subprocess.DEVNULL)
    write_json(os.path.join(pre, "smartcontracts/evm/out"))


if __name__ == "__main__":
    if sys.argv[1] == "build":
        build()
    elif sys.argv[1] == "json":
        write_json(sys.argv[2])
    elif sys.argv[1] == "faceabi":
        face_abi(sys.argv[2], sys.argv[3])
    else:
        sys.exit(1 if abi(sys.argv[2], sys.argv[3]) else 0)
