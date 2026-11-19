# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""bls-multi round (from 2026-11-17-ua-rs-native-mutants-run.py): the mutant runner every task's harness (t<n>-mutants.py) loads.
A harness defines M = [(name, file, old, new, cmd, cwd, expect), ...] and calls main(M); `expect` is the test that must turn red:
a mutant killed only by other tests is reported "other", not "killed". One change per run on a clean tree, `cmd` run in `cwd` (from the
worktree root), the file restored byte for byte after it. A mutant that needs two edits in one file (an import beside its
use) gives `old` as a list of (old, new) pairs and `new` None. A mutant whose suite passes is a finding; one that does not load (a
syntax or compile error, a missing export) kills nothing and is counted as not loaded.
  python3 -I <harness> [first last]     run (slices for long lists)
  python3 -I <harness> check            every replacement found exactly once at this commit, no run
The last line of a full run: "N mutants, K killed, S survived, L not loaded"."""
import subprocess
import sys

NO_LOAD = ("SyntaxError", "ERR_MODULE_NOT_FOUND", "does not provide an export", "error[E", "error: could not compile")


def edits(a, b):
    return a if b is None else [(a, b)]


def main(M):
    assert len({m[0] for m in M}) == len(M), "mutant names must be unique"
    if sys.argv[1:] == ["check"]:
        for name, f, a, b, *_ in M:
            src = open(f, encoding="utf-8").read()
            for x, _y in edits(a, b):
                assert src.count(x) == 1, (name, f, x, src.count(x))
        print(f"{len(M)} mutants, every replacement found once")
        return 0
    lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) == 3 else (1, len(M))
    killed = survived = noload = 0
    for n, (name, f, a, b, cmd, cwd, expect) in enumerate(M[lo - 1:hi], lo):
        src = mut = open(f, encoding="utf-8").read()
        for x, y in edits(a, b):
            assert mut.count(x) == 1, (name, x, mut.count(x))
            mut = mut.replace(x, y)
        open(f, "w", encoding="utf-8").write(mut)
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
        finally:
            open(f, "w", encoding="utf-8").write(src)
        assert open(f, encoding="utf-8").read() == src
        out = r.stdout + r.stderr
        loaded = not any(x in out for x in NO_LOAD)
        failed = sorted({x[2:].split(" (")[0] for x in out.splitlines() if x.startswith("✖ ") and "failing tests" not in x} |
                        {x.split()[1] for x in out.splitlines() if x.startswith("test ") and x.endswith("FAILED")} |
                        {x.split()[1] for x in out.splitlines() if x.startswith(("FAIL: ", "ERROR: "))} |
                        {x.split()[2] for x in out.splitlines() if x.startswith("--- FAIL: ")} |
                        {x.split()[1] for x in out.splitlines() if x.lstrip().startswith("Failed Scaas")} |
                        {x.split("] ", 1)[1].split("(")[0] for x in out.splitlines() if x.startswith("[FAIL") and "] " in x} |
                        {x.split(": ", 1)[1].rsplit(" [E]", 1)[0] for x in out.splitlines() if x.rstrip().endswith("[E]") and ": " in x})
        if not failed:  # no test names (a generator, a compile): the first error line
            failed = [x.strip() for x in out.splitlines() if x.lstrip().startswith(("Error", "error", "UAError", "thread "))][:1]
        if r.returncode == 0:
            verdict, survived = "SURVIVED", survived + 1
        elif not loaded:
            verdict, noload = "NO-LOAD ", noload + 1
        elif any(expect in x for x in failed):
            verdict, killed = "killed  ", killed + 1
        else:
            verdict, survived = "other   ", survived + 1
        print(f"{verdict} | M{n} {name} | {f} | rc={r.returncode} | expect {expect} | {len(failed)} failed: {', '.join(failed)[:300]}",
              flush=True)
    print(f"{hi - lo + 1} mutants, {killed} killed, {survived} survived, {noload} not loaded")
    return 1 if survived or noload else 0
