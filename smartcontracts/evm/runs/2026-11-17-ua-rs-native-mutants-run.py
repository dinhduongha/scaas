# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-native: the mutant runner every task's harness (2026-11-17-ua-rs-native-t<n>-mutants.py) loads. A harness defines
M = [(name, file, old, new, cmd, cwd), ...] and calls main(M). One change per run on a clean tree, `cmd` run in `cwd` (from the
worktree root), the file restored byte for byte after it. A mutant whose suite passes is a finding; one that does not load (a
syntax or compile error, a missing export) kills nothing and is counted as not loaded.
  python3 -I <harness> [first last]     run (slices for long lists)
  python3 -I <harness> check            every replacement found exactly once at this commit, no run
The last line of a full run: "N mutants, K killed, S survived, L not loaded"."""
import subprocess
import sys

NO_LOAD = ("SyntaxError", "ERR_MODULE_NOT_FOUND", "does not provide an export", "error[E", "error: could not compile")


def main(M):
    assert len({m[0] for m in M}) == len(M), "mutant names must be unique"
    if sys.argv[1:] == ["check"]:
        for name, f, a, _b, _cmd, _cwd in M:
            n = open(f, encoding="utf-8").read().count(a)
            assert n == 1, (name, f, n)
        print(f"{len(M)} mutants, every replacement found once")
        return 0
    lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) == 3 else (1, len(M))
    killed = survived = noload = 0
    for n, (name, f, a, b, cmd, cwd) in enumerate(M[lo - 1:hi], lo):
        src = open(f, encoding="utf-8").read()
        assert src.count(a) == 1, (name, src.count(a))
        open(f, "w", encoding="utf-8").write(src.replace(a, b))
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
        finally:
            open(f, "w", encoding="utf-8").write(src)
        assert open(f, encoding="utf-8").read() == src
        out = r.stdout + r.stderr
        loaded = not any(x in out for x in NO_LOAD)
        failed = sorted({x[2:].split(" (")[0] for x in out.splitlines() if x.startswith("✖ ") and "failing tests" not in x} |
                        {x.split()[1] for x in out.splitlines() if x.startswith("test ") and x.endswith("FAILED")})
        if r.returncode == 0:
            verdict, survived = "SURVIVED", survived + 1
        elif not loaded:
            verdict, noload = "NO-LOAD ", noload + 1
        else:
            verdict, killed = "killed  ", killed + 1
        print(f"{verdict} | M{n} {name} | {f} | rc={r.returncode} | {len(failed)} failed: {failed[0][:90] if failed else ''}",
              flush=True)
    print(f"{hi - lo + 1} mutants, {killed} killed, {survived} survived, {noload} not loaded")
    return 1 if survived or noload else 0
