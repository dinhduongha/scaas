# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""T66b task 4.3 (spec 2026-11-09-t66b-library-organisation.md §10): the pre-split releases for the differential tests.

    python3 script/t66b/legacy_artifacts.py build    # export d142b57c's src, build it (scripts/capped), write the json
    python3 script/t66b/legacy_artifacts.py json <pre-split out dir>
    python3 script/t66b/legacy_artifacts.py abi <pre-split out dir> <current out dir>

`json` writes out/t66b-legacy/ (git-ignored, read by test/t66b/: libs.json, k<kind>.json, dex.json): for each token kind and the DEX, the pre-split
implementation's init code with its libraries linked, the libraries' linked init code in deploy order (each by CREATE2
through the deterministic deployer with salt `keccak256("scaas.t66b.legacy")`, so every address is known here), and one
call row per external function (selector, signature, mutability, ABI-encoded sample arguments). `abi` compares each face's
external functions, events and errors with the pre-split ABI (prints; rc 1 when a selector differs beyond `modules()` and,
on 4, 5, 12, 13, `pqzSet()`). Nothing here is committed output: the build is local. UNAUDITED tooling."""
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


def abi(old, new):
    bad = 0
    for k, n in KINDS.items():
        o, w = art(old, n), art(new, n)
        so, sw = set(o["methodIdentifiers"]), set(w["methodIdentifiers"])
        want = {"modules()"} | ({"pqzSet()"} if k in (4, 5, 12, 13) else set())
        ok = so <= sw and sw - so == want
        bad += not ok
        # every event / error of the pre-split face is declared by an artifact of the release's closure
        arts, seen, stack = [w], set(), []
        for src, m in _kind_modules(k):
            arts.append(art(new, m, src))
        stack = [ln for a in arts for ls in a["bytecode"]["linkReferences"].values() for ln in ls]
        while stack:
            ln = stack.pop()
            if ln not in seen:
                seen.add(ln)
                a = art(new, ln)
                arts.append(a)
                stack += [x for ls in a["bytecode"]["linkReferences"].values() for x in ls]
        ev, er = set().union(*(_named(a, "event") for a in arts)), set().union(*(_named(a, "error") for a in arts))
        print(f"{'ok  ' if ok else 'FAIL'} {k:2} {n}: {len(so)} -> {len(sw)} functions, added {sorted(sw - so)}, missing "
              f"{sorted(so - sw)}; events {len(_named(o, 'event'))} -> {len(_named(w, 'event'))} on the face, not declared in "
              f"the closure {sorted(_named(o, 'event') - ev)}; errors {len(_named(o, 'error'))} -> {len(_named(w, 'error'))} "
              f"on the face, {len(_named(o, 'error') - er)} not declared in the closure")
    return bad


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
    else:
        sys.exit(1 if abi(sys.argv[2], sys.argv[3]) else 0)
