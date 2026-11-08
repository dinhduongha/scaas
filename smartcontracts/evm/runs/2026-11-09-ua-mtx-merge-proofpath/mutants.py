# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Group 3h T64 (spec 2026-11-06-pqz-proof-path §11.3): every mutant of the spec, M1-M22 without M12 and M19 (which went with
SSTORE2), re-run against the proof-path invariants (test/pqz/invariant/ProofPath*.t.sol), one at a time on a clean tree: the
source edit applied, forge through `scripts/capped` (sparse, out/mutants), the file restored in the same process, then
`git diff --quiet --exit-code -- <file>`. The mutants are T58-T61's (runs/2026-11-08-ua-mtx-merge-3h/mutants.py, where each was
killed by its task's unit tests) plus M16, new here. A survivor here is not a kill lost: the column `unit` names the task file
that killed it; a survivor of both is a finding for its owning task.

Usage (from smartcontracts/evm): python3 runs/2026-11-09-ua-mtx-merge-proofpath/mutants.py list | run [<id> ...]
Full output: runs/2026-11-09-ua-mtx-merge-proofpath-mut-<id>.log (git-ignored); `mutant | tests that went red | rc` appended to
runs/2026-11-09-ua-mtx-merge-proofpath/summary.txt.
"""
import importlib.util
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EVM = os.path.dirname(os.path.dirname(HERE))
CAPPED = os.path.join(EVM, "..", "..", "scripts", "capped")
FORGE = os.path.expanduser("~/.foundry/bin/forge")
INV = "test/pqz/invariant/ProofPath*.t.sol"

_spec = importlib.util.spec_from_file_location("m3h", os.path.join(EVM, "runs", "2026-11-08-ua-mtx-merge-3h", "mutants.py"))
_m3h = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_m3h)
MUTANTS = {k: v[:3] for k, v in _m3h.MUTANTS.items()}
UNIT = {k: v[3] for k, v in _m3h.MUTANTS.items()}
MUTANTS["M16-trivial-merge-lo-rolled"] = ("src/pqz/PqzCore.sol", "uint64 lo = b.floor > b.rolled ? b.floor : b.rolled;",
                                          "uint64 lo = b.rolled;")
UNIT["M16-trivial-merge-lo-rolled"] = "(none: equivalent if floor <= rolled holds, P1 asserts it)"


def run(mid):
    path, old, new = MUTANTS[mid]
    full = os.path.join(EVM, path)
    src = open(full).read()
    if src.count(old) != 1:
        raise SystemExit(f"{mid}: the mutated text occurs {src.count(old)} times in {path}")
    logp = os.path.join(EVM, "runs", f"2026-11-09-ua-mtx-merge-proofpath-mut-{mid}.log")
    try:
        open(full, "w").write(src.replace(old, new))
        env = {**os.environ, "FOUNDRY_SPARSE_MODE": "true", "FOUNDRY_OUT": "out/mutants", "FOUNDRY_CACHE_PATH": "cache/mutants"}
        with open(logp, "w") as log:
            rc = subprocess.call([CAPPED, FORGE, "test", "-j", "2", "--match-path", INV], cwd=EVM, env=env, stdout=log,
                                 stderr=subprocess.STDOUT)
    finally:
        open(full, "w").write(src)
    if subprocess.call(["git", "diff", "--quiet", "--exit-code", "--", path], cwd=EVM) != 0:
        raise SystemExit(f"{mid}: {path} not restored")
    out = open(logp).read()
    # a unit test fails as `[FAIL: …] name(…)`, an invariant as `[FAIL: …]`, its sequence, then ` name() (runs: …)` on its own line
    red = sorted(set(re.findall(r"\[FAIL[^\]]*\] (\w+)\(", out)) | set(re.findall(r"^\s+(invariant_\w+)\(\) \(runs:", out, re.M)))
    note = ", ".join(red) if red else ("compile error" if "Compiler run failed" in out else "none (survived)")
    line = f"{mid} | {note} | {rc} | unit: {UNIT[mid]}"
    print(line, flush=True)
    with open(os.path.join(HERE, "summary.txt"), "a") as f:
        f.write(line + "\n")


if __name__ == "__main__":
    if sys.argv[1:2] == ["list"]:
        print("\n".join(MUTANTS))
    elif sys.argv[1:2] == ["run"]:
        for m in sys.argv[2:] or list(MUTANTS):
            run(m)
    else:
        raise SystemExit(__doc__)
