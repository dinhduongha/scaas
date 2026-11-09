# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Plan T66b build (spec 2026-11-09-t66b-library-organisation.md §10) mutants: one at a time, each edit applied to its src/ file,
forge through `scripts/capped` (sparse, out/mutants-t66b) on the mutant's tests, the file restored in the same process and checked
byte-equal to its content before the run (then `git diff --exit-code` when the tree is committed). Each must turn a named negative
red while the original stays green (the gate's own runs).

Usage (from smartcontracts/evm): python3 runs/2026-11-09-ua-mtx-merge-t66b-build/mutants.py list | run [<id> ...]
Full output: runs/2026-11-09-ua-mtx-merge-t66b-mut-<id>.log (git-ignored); `mutant | tests that went red | rc` appended to
runs/2026-11-09-ua-mtx-merge-t66b-build/mutants.txt.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EVM = os.path.dirname(os.path.dirname(HERE))
CAPPED = os.path.join(EVM, "..", "..", "scripts", "capped")
FORGE = os.path.expanduser("~/.foundry/bin/forge")
REG = "src/ua/UARegistry.sol"
PAIR = "test/ua/UARegistryPair.t.sol"

# id: (tests, [(file, old, new, occurrences)])
MUTANTS = {
    # §10: R-1's forward to the wrong library entry
    "R1-wrong-library-entry": (PAIR, [(REG, "_libPure(UARegistryLib.keyHashOf.selector);",
                                       "_libPure(UARegistryLib.uaOf.selector);", 1)]),
}


def run(mid):
    tests, edits = MUTANTS[mid]
    files = sorted({f for f, *_ in edits})
    orig = {f: open(os.path.join(EVM, f)).read() for f in files}
    mut = dict(orig)
    for f, old, new, n in edits:
        if mut[f].count(old) != n:
            raise SystemExit(f"{mid}: the mutated text occurs {mut[f].count(old)} times in {f}, not {n}")
        mut[f] = mut[f].replace(old, new)
    logp = os.path.join(EVM, "runs", f"2026-11-09-ua-mtx-merge-t66b-mut-{mid}.log")
    try:
        for f in files:
            open(os.path.join(EVM, f), "w").write(mut[f])
        env = {**os.environ, "FOUNDRY_SPARSE_MODE": "true", "FOUNDRY_OUT": "out/mutants-t66b",
               "FOUNDRY_CACHE_PATH": "cache/mutants-t66b"}
        with open(logp, "w") as log:
            rc = subprocess.call([CAPPED, FORGE, "test", "-j", "2", "--match-path", tests], cwd=EVM, env=env, stdout=log,
                                 stderr=subprocess.STDOUT)
    finally:
        for f in files:
            open(os.path.join(EVM, f), "w").write(orig[f])
    for f in files:
        if open(os.path.join(EVM, f)).read() != orig[f]:
            raise SystemExit(f"{mid}: {f} not restored")
    out = open(logp).read()
    red = sorted(set(re.findall(r"\[FAIL[^\]]*\] (\w+)", out)))
    note = ", ".join(red) if red else ("compile error" if "Compiler run failed" in out
                                       else "red, unnamed (see the log)" if rc else "none (survived)")
    line = f"{mid} | {note} | {rc}"
    print(line, flush=True)
    with open(os.path.join(HERE, "mutants.txt"), "a") as f:
        f.write(line + "\n")


if __name__ == "__main__":
    if sys.argv[1:2] == ["list"]:
        print("\n".join(MUTANTS))
    elif sys.argv[1:2] == ["run"]:
        for m in sys.argv[2:] or list(MUTANTS):
            run(m)
    else:
        raise SystemExit(__doc__)
