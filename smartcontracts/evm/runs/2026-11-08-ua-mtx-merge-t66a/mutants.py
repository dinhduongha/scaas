# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Mutant harness of plan T66a (the registry block: requirePortable, no KEM key for an msig, the pop slot bitmap). The shape of
runs/2026-11-08-ua-mtx-merge-pqz-verifier/mutants.py: one mutant per run on a clean tree, the source edit applied, the named tests
run through `scripts/capped` (test/ua compiled alone into out/mutants), the file restored in the same process (finally), then
`git diff --quiet --exit-code -- <file>` must hold. Killed = the run fails (rc != 0) with a test red.

Usage (from smartcontracts/evm): python3 runs/2026-11-08-ua-mtx-merge-t66a/mutants.py list | run <id> [<id> ...]
Full output: runs/2026-11-08-ua-mtx-merge-t66a-mut-<id>.log (git-ignored); `mutant | tests that went red | rc` appended to
runs/2026-11-08-ua-mtx-merge-t66a-mutants.txt.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EVM = os.path.dirname(os.path.dirname(HERE))
CAPPED = os.path.join(EVM, "..", "..", "scripts", "capped")
FORGE = os.path.expanduser("~/.foundry/bin/forge")
LIB = "src/ua/UARegistryLib.sol"
REG = "src/ua/UARegistry.sol"
PORT = ("test/ua/UARegistryPortable.t.sol", None)
KEM = ("test/ua/UARegistryUA8.t.sol", "test_ua8_kemMsigRefused|test_ua8_nonHolderAttrsRefused|test_msigKemSigNotMinimalRefused")
POP = ("test/ua/UARegistryUA8.t.sol", "test_popSlotsOf")

# id: (file, old, new, (match-path, match-test))
MUTANTS = {
    # ---- item 1: requirePortable
    "p1-pqchat-not-portable": (LIB, "\n                && purpose != UAKinds.PURPOSE_PQCHAT\n", "\n", PORT),
    "p2-pop-v2-allowed": (LIB, "if (r.kind == 0 || purposeTag == UAKinds.PURPOSE_POP_V2) revert", "if (r.kind == 0) revert", PORT),
    "p3-msig-pop-exempts-slots": (LIB, "_msig(ua, md, typedDigest, false, d, auth.members)", "_msig(ua, md, typedDigest, true, d, auth.members)", PORT),
    "p4-msig-purpose-fixed": (LIB, "UAKinds.uaMessage(UAKinds.MSIG, purposeTag, typedDigest));\n            ok =",
                              "UAKinds.uaMessage(UAKinds.MSIG, UAKinds.PURPOSE_KEM, typedDigest));\n            ok =", PORT),
    "p5-msig-signature-ignored": (LIB, "ok = auth.keyData.length == 0 && auth.signature.length == 0 && _msig(",
                                  "ok = auth.keyData.length == 0 && _msig(", PORT),
    "p6-native-member-md": (LIB, "UAStore.byCode(address(uint160(uint256(id))), typed, s.sig,",
                            "UAStore.byCode(address(uint160(uint256(id))), md, s.sig,", PORT),
    "p7-minimal-off": (LIB, "return acc >= threshold && acc - wMin < threshold;", "return acc >= threshold;", PORT),
    "p8-gen2-not-forwarded": (REG, "        if (_elsewhere(ua)) IUARegistry(predecessor).requirePortable(ua, purposeTag, typedDigest, auth);\n        else _libView(",
                              "        _libView(", PORT),
    "p9-kind-unchecked": (LIB, "if (r.kind == 0 || purposeTag == UAKinds.PURPOSE_POP_V2) revert", "if (purposeTag == UAKinds.PURPOSE_POP_V2) revert", PORT),
    # ---- item 2: no KEM key for an msig
    "k1-register-msig-kem": (LIB, "if ((commit || kemPk.length != 0) && !_kemHolder(kind)) revert", "if ((commit || kemPk.length != 0) && !_holder(kind, d)) revert", KEM),
    "k2-setkemkey-msig": (LIB, "        if (!_kemHolder(r.kind)) revert IUARegistry.UAKemHolder(ua);",
                          "        if (r.kind != UAKinds.MSIG && !_kemHolder(r.kind)) revert IUARegistry.UAKemHolder(ua);", KEM),
    "k3-kemholder-msig": (LIB, "            || kind == UAKinds.FNDSA1024;\n    }", "            || kind == UAKinds.FNDSA1024 || kind == UAKinds.MSIG;\n    }", KEM),
    # ---- item 5: the pop slot bitmap
    "s1-popslots-not-written": (LIB, "            s.popSlots[ua] = bits;", "            bits;", POP),
    "s2-acceptance-sets-pop-bit": (LIB, "        s.accepted[ua] = bits | 1 << index;\n", "        s.accepted[ua] = bits | 1 << index;\n        s.popSlots[ua] |= 1 << index;\n", POP),
    "s3-popslots-read-accepted": (REG, "uint256 bits = _s.popSlots[ua];", "uint256 bits = _s.accepted[ua];", POP),
    "s4-hash-wrong-index": (REG, "(uint16(i), _s.memberSigHash[ua][i])", "(uint16(i), _s.memberSigHash[ua][n])", POP),
    "s5-gen2-not-forwarded": (REG, "        if (_elsewhere(ua)) return IUARegistry(predecessor).popSlotsOf(ua);\n", "", POP),
}


def red_tests(log):
    return sorted(set(re.findall(r"\[FAIL[^\]]*\] (\w+)\(", log)))


def run(mid):
    path, old, new, (match, test) = MUTANTS[mid]
    full = os.path.join(EVM, path)
    src = open(full).read()
    if src.count(old) != 1:
        raise SystemExit(f"{mid}: the mutated text occurs {src.count(old)} times in {path}")
    logp = os.path.join(EVM, "runs", f"2026-11-08-ua-mtx-merge-t66a-mut-{mid}.log")
    try:
        open(full, "w").write(src.replace(old, new))
        env = {**os.environ, "FOUNDRY_TEST": "test/ua", "FOUNDRY_OUT": "out/mutants", "FOUNDRY_CACHE_PATH": "cache/mutants"}
        cmd = [CAPPED, FORGE, "test", "-j", "2", "--match-path", match] + (["--match-test", test] if test else [])
        with open(logp, "w") as log:
            rc = subprocess.call(cmd, cwd=EVM, env=env, stdout=log, stderr=subprocess.STDOUT)
    finally:
        open(full, "w").write(src)
    if subprocess.call(["git", "diff", "--quiet", "--exit-code", "--", path], cwd=EVM) != 0:
        raise SystemExit(f"{mid}: {path} not restored")
    out = open(logp).read()
    red = red_tests(out)
    note = ", ".join(red) if red else ("compile error" if "Compiler run failed" in out else "none")
    line = f"{mid} | {note} | {rc}"
    print(line)
    with open(os.path.join(EVM, "runs", "2026-11-08-ua-mtx-merge-t66a-mutants.txt"), "a") as f:
        f.write(line + "\n")


if __name__ == "__main__":
    if sys.argv[1:2] == ["list"]:
        print("\n".join(MUTANTS))
    elif sys.argv[1:2] == ["run"]:
        for m in sys.argv[2:]:
            run(m)
    else:
        raise SystemExit(__doc__)
