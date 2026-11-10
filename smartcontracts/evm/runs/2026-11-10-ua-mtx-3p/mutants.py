# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-mtx-3p mutants (owner rulings 2026-11-10): one at a time, each edit applied to its file (a generated face, the generator
`script/t66b/gen_faces.py` then regenerated, or `PqChatTopics.sol`), forge through `scripts/capped` on its suite, every touched
or regenerated file restored in the same process and checked byte-equal (sha256) to its content before the run. Each must
turn a test red while the original stays green.

Usage (from smartcontracts/evm): python3 runs/2026-11-10-ua-mtx-3p/mutants.py list | run [<id> ...]
Full output: runs/2026-11-10-ua-mtx-3p/mut-<id>.log (git-ignored); `mutant | tests that went red | rc` appended to
runs/2026-11-10-ua-mtx-3p/mutants.txt. UNAUDITED tooling.
"""
import glob
import hashlib
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EVM = os.path.dirname(os.path.dirname(HERE))
CAPPED = os.path.join(EVM, "..", "..", "scripts", "capped")
FORGE = os.path.expanduser("~/.foundry/bin/forge")
GEN = "script/t66b/gen_faces.py"
TOPICS = "src/pqchat/PqChatTopics.sol"
GENERATED = sorted(glob.glob(os.path.join(EVM, "src/*/*Token.sol")) + glob.glob(os.path.join(EVM, "src/*/*TokenModules.sol"))
                   + [os.path.join(EVM, "script/KindModules.sol")] + glob.glob(os.path.join(EVM, "test/helpers/*Whole.sol")))
T66B = ("test/t66b", "^(GroupsTest|ModulesTest)$")
CHAT = ("test/pqchat", "^PqTopicsTest$")


def stub(face, entry, frm, to):
    """The stub of `entry` in the generated face `face` forwarding to `to` instead of `frm`."""
    return ("re", f"src/regulated/{face}.sol" if "Regulated" in face else f"src/pqz/{face}.sol",
            r"(function " + entry + r"\([^)]*\) external[^{]*\{\n        _forward\w*\()" + frm + r"(\);)", r"\g<1>" + to + r"\g<2>")


MUTANTS = {
    # item 3: the topic name bound
    "M-T1": ([("s", TOPICS, "uint256 internal constant NAME_MAX = 512;", "uint256 internal constant NAME_MAX = 513;")], False, CHAT),
    "M-T2": ([("s", TOPICS, "if (nl == 0 || nl > NAME_MAX || t.homeChain == 0", "if (nl == 0 || nl > 128 || t.homeChain == 0")],
             False, CHAT),
    "M-T3": ([("s", TOPICS, "        if (nl == 0 || nl > NAME_MAX) revert IPqChat.PqTopicShape();",
               "        if (nl == 0) revert IPqChat.PqTopicShape();")], False, CHAT),
    # item 2: the modules by function
    "M-R0": ([("head", GEN)], True, T66B),  # the generator before group 3p (394dd9cc): W keeps the regulated entries, Q2
    "M-R1": ([stub("WrappedRegulatedToken", "freeze", "_MR", "_MW")], False, T66B),  # a regulated selector routed to W
    "M-R2": ([("s", GEN, "R_ENTRIES = {_e['name'] for _e in E['kinds']['NormalRegulatedToken'] if _e['group'] == 'W'}",
               "R_ENTRIES = {_e['name'] for _e in E['kinds']['NormalRegulatedToken'] if _e['group'] == 'W'} - {'freeze'}")],
             True, T66B),  # the generator leaves `freeze` in W
    "M-R3": ([("s", "src/regulated/WrappedPqzRegulatedToken.sol", "_MR = _module(a.modules, 6, 12);",
               "_MR = _module(a.modules, 6, 4);")], False, T66B),  # R's slot expects W's group
    "M-R4": ([stub("NormalRegulatedToken", "pause", "_MR", "_MA")], False, T66B),  # 8's R entry routed to A
    "M-W1": ([("s", GEN, "R_ENTRIES = {_e['name'] for _e in E['kinds']['NormalRegulatedToken'] if _e['group'] == 'W'}",
               "R_ENTRIES = {_e['name'] for _e in E['kinds']['NormalRegulatedToken'] if _e['group'] == 'W'} | {'rescue'}")],
             True, T66B),  # a wrap body (the restated `rescue`) moved to R
    "M-S1": ([stub("WrappedPqzToken", "proofStore", "_MS", "_MQ")], False, T66B),  # a state view routed to Q
    "M-S2": ([("s", GEN, "S_SETTERS = {'pqzSetVerifier', 'pqzCancelVerifier', 'pqzRevokeVerifier', 'setProofStore'}",
               "S_SETTERS = {'pqzSetVerifier', 'pqzCancelVerifier', 'pqzRevokeVerifier'}")], True, T66B),  # a setter left in Q
}


def sha(p):
    return hashlib.sha256(open(p, "rb").read()).hexdigest()


def run(mid):
    edits, regen, (tdir, match) = MUTANTS[mid]
    files = {os.path.join(EVM, e[1]) for e in edits} | (set(GENERATED) if regen else set())
    keep = {f: open(f, "rb").read() for f in files}
    before = {f: sha(f) for f in files}
    try:
        for e in edits:
            p = os.path.join(EVM, e[1])
            s = open(p).read()
            if e[0] == "head":
                t = subprocess.run(["git", "show", "394dd9cc:smartcontracts/evm/" + e[1]], cwd=EVM, check=True,
                                   capture_output=True, text=True).stdout
            elif e[0] == "re":
                t, n = re.subn(e[2], e[3], s)
                assert n == 1, (mid, e[1], n)
            else:
                assert s.count(e[2]) == 1, (mid, e[1], e[2])
                t = s.replace(e[2], e[3])
            assert t != s, (mid, "no change")
            open(p, "w").write(t)
        if regen:
            subprocess.run(["python3", GEN], cwd=EVM, check=True, stdout=subprocess.DEVNULL)
        env = dict(os.environ, FOUNDRY_TEST=tdir, FOUNDRY_SCRIPT=tdir, FOUNDRY_OUT=f"out/m3p-mut-{tdir.split('/')[1]}",
                   FOUNDRY_CACHE_PATH=f"cache/m3p-mut-{tdir.split('/')[1]}")
        log = os.path.join(HERE, f"mut-{mid}.log")
        with open(log, "w") as f:
            rc = subprocess.run([CAPPED, FORGE, "test", "-j", "2", "--match-contract", match], cwd=EVM, env=env, stdout=f,
                                stderr=subprocess.STDOUT).returncode
        red = sorted(set(re.findall(r"\[FAIL[^\]]*\] (\w+)\(", open(log).read())))
    finally:
        for f, b in keep.items():
            open(f, "wb").write(b)
    for f in files:
        assert sha(f) == before[f], f"{f}: not restored"
    killed = rc != 0 and red
    line = f"{mid} | {', '.join(red) or 'none'} | {rc}{'' if killed else ' SURVIVED'}"
    print(line)
    with open(os.path.join(HERE, "mutants.txt"), "a") as f:
        f.write(line + "\n")
    return killed


if __name__ == "__main__":
    if sys.argv[1:2] == ["list"]:
        print("\n".join(MUTANTS))
    else:
        ids = sys.argv[2:] or list(MUTANTS)
        sys.exit(0 if all([run(m) for m in ids]) else 1)
