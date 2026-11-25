# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""CTR-UA-74 (owner 2026-11-25): every mutant of the `msig` version tag and of `msigAt` alone on a clean tree, `forge test` of
test/ua/UARegistryMsigUpdate.t.sol through `scripts/capped`, the file restored byte-equal (sha256 checked) after each. One line per
mutant: `mutant | red tests | rc` (rc 1 = killed). Resumes: a mutant already in `<runs>/mutants.txt` is skipped. Full output in
git-ignored `.log` files under `<runs>/mutants/`. The runner is script/wraplimit/mutants.py's.

usage (from smartcontracts/evm): python3 script/ua/msig-history-mutants.py <runs dir> [name ...]   UNAUDITED tooling."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "wraplimit"))
import mutants as runner  # noqa: E402  (the shared runner: run, others_waiting)

REG = "src/ua/UARegistry.sol"
CORE = "src/ua/UARegistryCoreLib.sol"
AUX = "src/ua/UARegistryAuxLib.sol"
STORE = "src/ua/UAStore.sol"
T = "test/ua/UARegistryMsigUpdate.t.sol"
D = "test/ua"

VER = "return v == 0 ? tag.length == 0 : tag.length == 8 && word(tag, 0) >> 192 == v;"

# (name, file, old, new)
M = [
    (
        "chain-path-any-tag",
        REG,
        "return auth.keyData.length == 0 && UAStore.verOk(auth.signature, d)",
        "return auth.keyData.length == 0",
    ),
    (
        "portable-path-any-tag",
        CORE,
        "ok = auth.keyData.length == 0 && UAStore.verOk(auth.signature, d)",
        "ok = auth.keyData.length == 0",
    ),
    ("stored-path-any-tag", CORE, "if (!UAStore.verOk(sig, d)) return false;", ""),
    ("chain-inner-any-tag", REG, "return UAStore.verOk(s.sig, di) && _msig(", "return _msig("),
    ("portable-inner-any-tag", CORE, "return UAStore.verOk(s.sig, di) //", "return true //"),
    ("held-elsewhere-inner-tag-dropped", REG, 'UASig("", s.sig, inner)', 'UASig("", "", inner)'),
    ("tag-any-eight-bytes", STORE, VER, "return v == 0 ? tag.length == 0 : tag.length == 8;"),
    ("tag-any-at-version-0", STORE, VER, "return v == 0 || (tag.length == 8 && word(tag, 0) >> 192 == v);"),
    # the forgery's door: the form of before the first update accepted for ever
    (
        "tag-empty-at-any-version",
        STORE,
        VER,
        "return tag.length == 0 || (tag.length == 8 && word(tag, 0) >> 192 == v);",
    ),
    (
        "tag-at-least-eight-bytes",
        STORE,
        VER,
        "return v == 0 ? tag.length == 0 : tag.length >= 8 && word(tag, 0) >> 192 == v;",
    ),
    ("tag-not-greater", STORE, VER, "return v == 0 ? tag.length == 0 : tag.length == 8 && word(tag, 0) >> 192 <= v;"),
    ("msigAt-serves-the-current", AUX, "            ptr = UAStore.prevOf(ptr);\n", ""),
    ("msigAt-answers-a-later-version", AUX, "        if (version > v) return (s, 0);\n", ""),
    ("msigAt-one-version-off", AUX, "for (; v > version; --v) {", "for (; v > version + 1; --v) {"),
    (
        "blob-forgets-the-one-before",
        AUX,
        "version, UAStore.layout().records[ua].keyPtr); // CTR-UA-74",
        "version, address(0)); // CTR-UA-74",
    ),
    ("prev-read-off-by-one", STORE, "ptr.code.length - 21, 20", "ptr.code.length - 22, 20"),
    ("trailer-read-at-the-old-place", STORE, "ptr.code.length - 61, 40", "ptr.code.length - 41, 40"),
    (
        "stored-signature-drops-the-tag",
        AUX,
        "bytes.concat(abi.encode(sig.members), sig.signature)",
        "abi.encode(sig.members)",
    ),
    ("gen2-msigAt-not-forwarded", AUX, "        if (h != address(0)) return IUARegistry(h).msigAt(ua, version);\n", ""),
    ("bound-without-the-tag-word", "src/ua/UARegistryRegLib.sol", "? 32 + _authBytes(", "? _authBytes("),
    (
        "accept-object-drops-the-tag",
        CORE,
        "bytes.concat(abi.encode(memberSig.members), memberSig.sig)",
        "abi.encode(memberSig.members)",
    ),
    (
        "pop-object-drops-the-tag",
        "src/ua/UARegistryRegLib.sol",
        "bytes.concat(abi.encode(m.members), m.sig)",
        "abi.encode(m.members)",
    ),
]


def main():
    runs = sys.argv[1]
    os.makedirs(os.path.join(runs, "mutants"), exist_ok=True)
    only = set(sys.argv[2:])
    out = os.path.join(runs, "mutants.txt")
    done = set()
    if os.path.exists(out):
        done = {line.split(" | ")[0] for line in open(out) if " | " in line and not line.startswith("mutant")}
    with open(out, "a") as o:
        if not done:
            o.write("mutant | red tests | rc\n")
        for i, (name, f, old, new) in enumerate(M):
            if (only and name not in only) or name in done:
                continue
            if runner.others_waiting():
                print("yield: another work tree waits for a capped slot; rerun to resume", flush=True)
                return
            print(f"start {i + 1}/{len(M)} {name}", flush=True)
            rc, red = runner.run(runs, name, f, old, new, D, T)
            line = f"{name} | {', '.join(red) or '-'} | {rc}\n"
            o.write(line)
            o.flush()
            print(line, end="", flush=True)


if __name__ == "__main__":
    main()
