# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Mutant harness of round 3r (admin, not owner; spec docs/superpowers/specs/2026-11-10-admin-not-owner.md §8, §13.9), in the
shape of runs/2026-11-10-ua-mtx-merge-3c/mutants.py: one mutant per run on a clean tree (the mutated file committed), the
source edit applied, the named suite run alone through `scripts/capped`, the file restored in the same process (finally), then
`git diff --quiet --exit-code -- <file>` must hold (byte-equal). Killed = the run fails (rc != 0) with a test red.

A row: id -> (file from the repository root, old text (must occur once), new text, kind, where, match)
  kind "forge": FOUNDRY_TEST=smartcontracts/evm/<where>, `forge test --match-path <where>/<match>` (match a glob of files)
  kind "cargo": in <where> (e.g. scaas-node), `cargo test --lib <match>` (a test-name filter)
  kind "npm":   in <where> (e.g. clients/clientkeys), `npm test`

Usage (from the repository root): python3 smartcontracts/evm/runs/2026-11-10-ua-mtx-3r/mutants.py list | run <id> [<id> ...] | all
Full output: runs/2026-11-10-ua-mtx-3r/mut-<id>.log (git-ignored); `mutant | tests that went red | rc` appended to
runs/2026-11-10-ua-mtx-3r/mutants.txt (committed). `all` skips ids already in mutants.txt.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
CAPPED = os.path.join(ROOT, "scripts", "capped")
FORGE = os.path.expanduser("~/.foundry/bin/forge")

# Rows are added by the task that builds the code they mutate (T2 ... T15); T13 runs the rest and checks the count.
MUTANTS = {
    # T2 (§4.1): a token face keeps an ownership alias beside the admin entries: `owner()` answering the admin (a view, caught
    # by AdminNames) and a `transferOwnership(bytes32)` stub (a write, caught by SelectorAudit as unclassified). The face is
    # generated from entries.json by gen_faces.py, which the harness does not run, so the generated face is mutated.
    "M5": ("smartcontracts/evm/src/metatx/NormalToken.sol",
           "    function admin() external view returns (bytes32 _p0) {\n        _forwardView(_MA);\n    }\n",
           "    function admin() external view returns (bytes32 _p0) {\n        _forwardView(_MA);\n    }\n\n"
           "    function owner() external view returns (bytes32) {\n        return IGovernance(address(this)).admin();\n    }\n\n"
           "    function transferOwnership(bytes32) external {\n        _forward(_MA);\n    }\n",
           "forge", "test/governance", "{AdminNames,SelectorAudit}.t.sol"),
    # T7a (§4.3): UATransferAdmin keeps the word `newOwner` (the typehash pin)
    "M7": ("smartcontracts/evm/src/governance/GovernanceRouterBase.sol",
           "\"UATransferAdmin(bytes32 from,address target,bytes32 newAdmin,",
           "\"UATransferAdmin(bytes32 from,address target,bytes32 newOwner,",
           "forge", "test/governance", "GovRouterTypehash.t.sol"),
    # T3 (§4.3): TOPIC_TYPEHASH keeps `owner` (the typehash pins and the topics.json digests)
    "M8": ("smartcontracts/evm/src/pqchat/PqChatTypes.sol",
           "\"PqTopic(bytes32 admin,uint64 nonce,",
           "\"PqTopic(bytes32 owner,uint64 nonce,",
           "forge", "test/pqchat", "PqChatTypes.t.sol"),
    # T4 (§3): `_create` still reads the token's `admin()` (the reverting-`admin()` creation)
    "M6": ("smartcontracts/evm/src/factory/OpenFactory.sol",
           "        IGovernance t = IGovernance(token);\n        _index(token, creatorId, CLASS_TOKEN, uint16(kind), version);\n",
           "        IGovernance t = IGovernance(token);\n        t.admin();\n        _index(token, creatorId, CLASS_TOKEN, uint16(kind), version);\n",
           "forge", "test/v2", "FactoryIndex.t.sol"),
    # T9a (§7): a node row keeps the old entry `mtxTransferOwnership` (the allow-list against selector_audit.json)
    "M12": ("scaas-node/src/typed.rs",
            "(\"UATransferAdmin\", \"mtxTransferAdmin\", GR,",
            "(\"UATransferAdmin\", \"mtxTransferOwnership\", GR,",
            "cargo", "scaas-node", "allow_lists_equal_the_selector_audit_both_directions"),
}


def red_tests(log):
    forge = re.findall(r"\[FAIL[^\]]*\] (\w+)\(", log)
    cargo = re.findall(r"^test (\S+) \.\.\. FAILED", log, re.M)
    node = re.findall(r"^not ok \d+ - (.+)$", log, re.M) + re.findall(r"^\s*✖ (.+?)(?: \(\d|$)", log, re.M)
    return sorted(set(forge + cargo + node))


def command(kind, where, match):
    if kind == "forge":
        n = "mutants-3r-" + where.replace("/", "-")
        env = {"FOUNDRY_TEST": where, "FOUNDRY_SCRIPT": where, "FOUNDRY_OUT": f"out/{n}", "FOUNDRY_CACHE_PATH": f"cache/{n}"}
        return os.path.join(ROOT, "smartcontracts", "evm"), env, [FORGE, "test", "-j", "2", "--match-path", f"{where}/{match}"]
    if kind == "cargo":
        return os.path.join(ROOT, where), {"CAPPED_MEM": "6G"}, ["cargo", "test", "-j", "2", "--lib", match]
    if kind == "npm":
        return os.path.join(ROOT, where), {}, ["npm", "test"]
    raise SystemExit(f"unknown kind {kind}")


def run(mid):
    path, old, new, kind, where, match = MUTANTS[mid]
    full = os.path.join(ROOT, path)
    src = open(full).read()
    if src.count(old) != 1:
        raise SystemExit(f"{mid}: the mutated text occurs {src.count(old)} times in {path}")
    if subprocess.call(["git", "diff", "--quiet", "--exit-code", "--", path], cwd=ROOT) != 0:
        raise SystemExit(f"{mid}: {path} has uncommitted changes; commit first")
    logp = os.path.join(HERE, f"mut-{mid}.log")
    cwd, extra, cmd = command(kind, where, match)
    # MUT_IN_CAPPED=1: the batch already runs inside one `scripts/capped` scope (each mutant still alone and in order)
    cap = [] if os.environ.get("MUT_IN_CAPPED") == "1" else [CAPPED]
    try:
        open(full, "w").write(src.replace(old, new))
        with open(logp, "w") as log:
            rc = subprocess.call(cap + cmd, cwd=cwd, env={**os.environ, **extra}, stdout=log, stderr=subprocess.STDOUT)
    finally:
        open(full, "w").write(src)
    if subprocess.call(["git", "diff", "--quiet", "--exit-code", "--", path], cwd=ROOT) != 0:
        raise SystemExit(f"{mid}: {path} not restored")
    out = open(logp).read()
    red = red_tests(out)
    compile_err = "Compiler run failed" in out or "error[E" in out or "could not compile" in out
    note = ", ".join(red) if red else ("compile error" if compile_err else "none")
    line = f"{mid} | {note} | {rc}"
    print(line, flush=True)
    with open(os.path.join(HERE, "mutants.txt"), "a") as f:
        f.write(line + "\n")


if __name__ == "__main__":
    if sys.argv[1:2] == ["list"]:
        print("\n".join(MUTANTS))
    elif sys.argv[1:2] == ["run"]:
        for m in sys.argv[2:]:
            run(m)
    elif sys.argv[1:2] == ["all"]:
        done = set()
        txt = os.path.join(HERE, "mutants.txt")
        if os.path.exists(txt):
            done = {l.split(" | ")[0] for l in open(txt) if " | " in l}
        for m in MUTANTS:
            if m not in done:
                run(m)
    else:
        raise SystemExit(__doc__)
