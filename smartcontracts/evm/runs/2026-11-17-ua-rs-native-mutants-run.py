# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-native: the mutant runner every task's harness (2026-11-17-ua-rs-native-t<n>-mutants.py) loads. A harness defines
M = [(name, file, old, new, cmd, cwd), ...] and calls main(M). One change per run on a clean tree, `cmd` run in `cwd` (from the
worktree root), the file restored byte for byte after it. A mutant that needs two edits in one file (an import beside its
use) gives `old` as a list of (old, new) pairs and `new` None. A mutant whose suite passes is a finding; one that does not load (a
syntax or compile error, a missing export) kills nothing and is counted as not loaded.
  python3 -I <harness> [first last]     run (slices for long lists)
  python3 -I <harness> check            every replacement found exactly once at this commit, no run
A hung run is `killed (timeout N s)` (counted as killed): each (cmd, cwd) first runs once unmutated, and a mutant's run past
3 x that baseline (at least 10 min, or `--timeout N`) has its whole process group killed. A target file that differs from
HEAD refuses the run (rc 2: a leftover mutation); the file is restored and checked in a `finally`, on SIGINT / SIGTERM too
(scripts/mutant_guard.py, owner 2026-11-24).
The last line of a full run: "N mutants, K killed, S survived, L not loaded"."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "scripts"))
import mutant_guard as G  # noqa: E402

NO_LOAD = ("SyntaxError", "ERR_MODULE_NOT_FOUND", "does not provide an export", "error[E", "error: could not compile")


def edits(a, b):
    return a if b is None else [(a, b)]


def main(M):
    assert len({m[0] for m in M}) == len(M), "mutant names must be unique"
    if sys.argv[1:] == ["check"]:
        for name, f, a, b, _cmd, _cwd in M:
            src = open(f, encoding="utf-8").read()
            for x, _y in edits(a, b):
                assert src.count(x) == 1, (name, f, x, src.count(x))
        print(f"{len(M)} mutants, every replacement found once")
        return 0
    lo, hi = (int(sys.argv[1]), int(sys.argv[2])) if len(sys.argv) == 3 else (1, len(M))
    killed = survived = noload = 0
    G.refuse_dirty([m[1] for m in M[lo - 1:hi]], ".")
    base = {}
    for m in M[lo - 1:hi]:
        key = (tuple(m[4]), m[5])
        if key not in base:
            b = G.run(m[4], G.TIMEOUT, capture_output=True, text=True, cwd=m[5])
            assert b.returncode == 0, f"baseline red (rc={b.returncode}): {m[4]} in {m[5]}"
            base[key] = b.seconds
    for n, (name, f, a, b, cmd, cwd) in enumerate(M[lo - 1:hi], lo):
        src = mut = open(f, encoding="utf-8").read()
        for x, y in edits(a, b):
            assert mut.count(x) == 1, (name, x, mut.count(x))
            mut = mut.replace(x, y)
        saved = {f: open(f, "rb").read()}
        try:
            open(f, "w", encoding="utf-8").write(mut)
            r = G.run(cmd, G.deadline(base[(tuple(cmd), cwd)]), capture_output=True, text=True, cwd=cwd)
        finally:
            G.restore(saved)
        out = r.stdout + r.stderr
        loaded = not any(x in out for x in NO_LOAD)
        failed = sorted({x[2:].split(" (")[0] for x in out.splitlines() if x.startswith("✖ ") and "failing tests" not in x} |
                        {x.split()[1] for x in out.splitlines() if x.startswith("test ") and x.endswith("FAILED")} |
                        {x.split()[1] for x in out.splitlines() if x.startswith(("FAIL: ", "ERROR: "))} |
                        {x.split()[2] for x in out.splitlines() if x.startswith("--- FAIL: ")} |
                        {x.split()[1] for x in out.splitlines() if x.lstrip().startswith("Failed Scaas")})
        if not failed:  # no test names (a generator, a compile): the first error line
            failed = [x.strip() for x in out.splitlines() if x.lstrip().startswith(("Error", "error", "UAError", "thread "))][:1]
        if r.timeout:
            verdict, killed = G.outcome(r, ""), killed + 1
        elif r.returncode == 0:
            verdict, survived = "SURVIVED", survived + 1
        elif not loaded:
            verdict, noload = "NO-LOAD ", noload + 1
        else:
            verdict, killed = "killed  ", killed + 1
        print(f"{verdict} | M{n} {name} | {f} | rc={r.returncode} | {len(failed)} failed: {failed[0][:90] if failed else ''}",
              flush=True)
    print(f"{hi - lo + 1} mutants, {killed} killed, {survived} survived, {noload} not loaded")
    return 1 if survived or noload else 0
