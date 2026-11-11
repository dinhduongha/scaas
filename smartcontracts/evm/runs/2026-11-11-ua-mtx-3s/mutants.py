# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Mutant harness of round 3s (KYC bit 28, the allow and deny lists; spec docs/superpowers/specs/2026-11-10-token-lists.md §13), in the
shape of runs/2026-11-10-ua-mtx-3r/mutants.py: one mutant per run on a clean tree (the mutated file committed), the
source edit applied, the named suite run alone through `scripts/capped`, the file restored in the same process (finally), then
`git diff --quiet --exit-code -- <file>` must hold (byte-equal). Killed = the run fails (rc != 0) with a test red.

A row: id -> (file from the repository root, old text (must occur once), new text, kind, where, match)
  kind "forge": FOUNDRY_TEST=smartcontracts/evm/<where>, `forge test --match-path <where>/<match>` (match a glob of files)
  kind "cargo": in <where> (e.g. scaas-node), `cargo test --lib <match>` (a test-name filter)
  kind "npm":   in <where> (e.g. clients/clientkeys), `npm test`

Usage (from the repository root): python3 smartcontracts/evm/runs/2026-11-11-ua-mtx-3s/mutants.py list | run <id> [<id> ...] | all
Full output: runs/2026-11-11-ua-mtx-3s/mut-<id>.log (git-ignored); `mutant | tests that went red | rc` appended to
runs/2026-11-11-ua-mtx-3s/mutants.txt (committed). `all` skips ids already in mutants.txt.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
CAPPED = os.path.join(ROOT, "scripts", "capped")
FORGE = os.path.expanduser("~/.foundry/bin/forge")

# Rows are added by the task that builds the code they mutate (T2 ... T7); T10 runs the rest and checks the count.
GL = "smartcontracts/evm/src/governance/GovernanceLib.sol"
GB = "smartcontracts/evm/src/governance/GovernanceBits.sol"
RB = "smartcontracts/evm/src/regulated/RegulatedBase.sol"
RL = "smartcontracts/evm/src/regulated/RegulatedLib.sol"
MUTANTS = {
}


def red_tests(log):
    forge = re.findall(r"\[FAIL[^\]]*\] (\w+)\(", log)
    cargo = re.findall(r"^test (\S+) \.\.\. FAILED", log, re.M)
    node = re.findall(r"^not ok \d+ - (.+)$", log, re.M) + re.findall(r"^\s*✖ (.+?)(?: \(\d|$)", log, re.M)
    return sorted(set(forge + cargo + node))


def command(kind, where, match):
    if kind == "forge":
        n = "mutants-3s-" + where.replace("/", "-")
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
