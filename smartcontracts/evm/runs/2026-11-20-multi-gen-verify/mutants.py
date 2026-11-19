# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Round multi-gen-verify (plan 2026-11-19-registry-verify-only-kinds): every mutant of a task alone on a clean tree, `forge test`
of its killing test through `scripts/capped` (`FOUNDRY_TEST` the test directory), the file restored byte-equal (sha256 checked)
after each; the runner is script/wraplimit/mutants.py's `run`. One line per mutant in `task<N>-mutants.txt`:
`mutant | red tests | rc | killed by` (killed = the named test is among the red ones). Resumes: a mutant already listed is skipped.
Full output in git-ignored `.log` files under `mutants/`. The mutants themselves: `task<N>.py` beside this file (a list `M` of
`(name, file, old, new, test file, killing test)`).

usage (from smartcontracts/evm): python3 runs/2026-11-20-multi-gen-verify/mutants.py <N> [name ...]   UNAUDITED tooling."""

import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "script", "wraplimit"))
import mutants as runner  # noqa: E402


def main():
    task = sys.argv[1]
    spec = importlib.util.spec_from_file_location("t", os.path.join(HERE, f"task{task}.py"))
    t = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(t)
    os.makedirs(os.path.join(HERE, "mutants"), exist_ok=True)
    only = set(sys.argv[2:])
    out = os.path.join(HERE, f"task{task}-mutants.txt")
    done = set()
    if os.path.exists(out):
        done = {line.split(" | ")[0] for line in open(out) if " | " in line and not line.startswith("mutant")}
    with open(out, "a") as o:
        if not done:
            o.write("mutant | red tests | rc | killed by\n")
        for i, (name, f, old, new, tfile, killer) in enumerate(t.M):
            if (only and name not in only) or name in done:
                continue
            print(f"start {i + 1}/{len(t.M)} {name}", flush=True)
            rc, red = runner.run(HERE, name, f, old, new, os.path.dirname(tfile), tfile)
            killed = killer in red
            o.write(f"{name} | {', '.join(red) or '-'} | {rc} | {killer if killed else 'SURVIVED'}\n")
            o.flush()
            print(f"{'killed' if killed else 'SURVIVED'} {name}: {', '.join(red) or '-'}", flush=True)


if __name__ == "__main__":
    main()
