# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The scaas-sdk plan's mutant runner (Global constraints): each task's file lists mutants as
(name, [(file, old, new), ...], test command).

`check` verifies every `old` occurs exactly once (the mutant loads) and prints the record's rows that are stale (their commit
is older than the last commit touching a file the row's mutant edits, or the row names no commit).

`run [name…]` first refuses (rc 2, nothing written) when a selected mutant does not load. It then runs each distinct test
command once on the unmutated tree and requires rc 0 (the green baseline; a red baseline is rc 2, nothing written). Then it
applies one mutant at a time, runs its test command from the worktree root (the command goes through scripts/capped,
foreground), restores the files byte for byte, and records the outcome in the task's `-mutants.txt`: `killed` (the intended
test failed: the mutant's optional fourth element `expect`, else the test its command names; a failure line is required),
`survived` (it passed), `not loaded` (the mutant does not compile, in any toolchain), `other failure` (red, but not by the
intended assertion: no kill; merged-tree review M12), `killed (timeout N s)` (the run passed its deadline: 3 x the
command's baseline, at least 10 min, or `--timeout N`; its whole process group is killed, and it counts as killed; owner
2026-11-24). A target file that differs from HEAD refuses the run (rc 2: a leftover mutation); every mutated file is
restored and checked in a `finally`, on SIGINT / SIGTERM too (scripts/mutant_guard.py). Each row is
`name | outcome | commit[ dirty] | test | first failure line`, `dirty` when tracked files other than the runs records differed
from HEAD. A run of named mutants keeps the record's other rows (each with its own commit). Last line:
`N mutants, K killed, S survived, L not loaded, O other failure`. Full output in a git-ignored `.log` beside it."""
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))
import mutant_guard as G  # noqa: E402
# the test commands see foundry's tools as the gate runner's steps do (`anvil`, `cast`, `forge` of the e2e tests)
os.environ["PATH"] = f"{Path.home() / '.foundry' / 'bin'}{os.pathsep}{os.environ.get('PATH', '')}"
RUNS = "clients/scaas-sdk/runs"
# the record files' directory and name prefix; another plan's runner sets both (and RUNS, NOT_CODE) before `main`
OUT = Path(__file__).parent
PREFIX = "2026-11-17-scaas-sdk-"
# the records and the summary are written by the runners themselves; they do not make the tree dirty
NOT_CODE = [f":!{RUNS}/*-mutants.txt", f":!{RUNS}/2026-11-17-scaas-sdk-summary.txt"]


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True)


def check(mutants):
    bad = []
    for m in mutants:
        name, edits = m[0], m[1]
        for f, old, _new in edits:
            n = (ROOT / f).read_text().count(old)
            if n != 1:
                bad.append(f"{name}: {f}: the text occurs {n} times")
    return bad


def stale(task, mutants):
    out = OUT / (f"{PREFIX}{task}-mutants.txt")
    if not out.exists():
        return [f"{task}: no record"]
    files = {m[0]: sorted({f for f, _, _ in m[1]}) for m in mutants}
    rows = {}
    for line in out.read_text().splitlines()[1:-1]:
        cols = line.split(" | ")
        rows[cols[0]] = cols
    res = []
    for name in files:
        cols = rows.get(name)
        if cols is None:
            res.append(f"{name}: no row")
            continue
        sha = cols[2].split()[0] if len(cols) >= 5 else ""
        if not re.fullmatch(r"[0-9a-f]{7,40}", sha):
            res.append(f"{name}: the row names no commit")
            continue
        for f in files[name]:
            if git("diff", "--quiet", sha, "HEAD", "--", f).returncode != 0:
                res.append(f"{name}: {f} changed since {sha}")
                break
    return res


# a compile error of any toolchain: the mutant does not load (never a kill)
COMPILE_ERRORS = ("error[E", "could not compile", "Compiler run failed", "Compilation failed", "SyntaxError:",
                  "TypeError: Cannot", "ReferenceError:", "Error: Cannot find module", "Error compiling", "compilation error")


def intended(cmd, expect=None):
    """The assertion a mutant must fail (M12): the mutant's own `expect` text, else the test its command names (its last
    word, quotes and a trailing `$` dropped); `None` when the command names no single test (a whole binary after
    `--test`, a script), where any failing test counts."""
    if expect:
        return expect
    words = cmd.split()
    # a forge filter is a regex over the signature: `^name\(` names `name` (as `name$` would, which forge never matches)
    last = re.sub(r"^\^|\\\($|\$$", "", words[-1].strip("'\"")) if words else ""
    if (len(words) >= 2 and words[-2] == "--test") or not re.search(r"[A-Za-z]", last) \
            or last.startswith("-") or last.endswith((".sh", ".py", ".js", ".mjs")):
        return None
    return last


def killed_by(text, want):
    """Whether `text` shows a failing test, `want`'s when it is named: a Rust `test … FAILED` / `panicked`, a forge
    `[FAIL…]`, a node `not ok` (TAP) or `✖` (spec reporter), a Python `FAIL:` / `ERROR:` / `AssertionError` line, a Go
    `--- FAIL:` line, an xUnit `<test> [FAIL]` line, a `dart test` `<file>: <test> [E]` line, the bindings generator's drift
    check `[gen] FAIL`."""
    fails = [ln for ln in text.splitlines()
             if re.search(r"\.\.\. FAILED|^\[FAIL|panicked at|^not ok|^FAIL:|^ERROR: |^\s*--- FAIL: |\S \[FAIL\]$|^\s*✖ |AssertionError|^failures:|---- .* stdout ----|^\[gen\] FAIL |: .* \[E\]$", ln)]
    if not fails:
        return False
    return want is None or any(want in ln for ln in fails)


def ran_nothing(text):
    """Whether a green run ran no test (a filter that matches none): forge's warning, or cargo's result lines all 0 / 0."""
    if "no tests match the provided pattern" in text:
        return True
    res = re.findall(r"^test result: \w+\. (\d+) passed; (\d+) failed", text, re.M)
    return bool(res) and all(p == "0" and f == "0" for p, f in res)


def failure_line(text):
    """The first line that says why the test failed (a panic, a failed test, an error), shortened."""
    for pat in (r"panicked at [^\n]*", r"assertion[^\n]*failed[^\n]*", r"^test \S+ \.\.\. FAILED", r"^\[FAIL[^\n]*", r"^not ok [^\n]*",
                r"^\s*✖ [^\n]*", r"AssertionError[^\n]*", r"^FAIL: [^\n]*", r"^ERROR: [^\n]*", r"^\s*--- FAIL: [^\n]*", r"\S+ \[FAIL\]$",
                r"^\[gen\] FAIL [^\n]*", r"^[^\n]*: [^\n]* \[E\]$", r"(?i)^\S*error[^\n]*"):
        m = re.search(pat, text, re.M)
        if m:
            # no machine path in a committed record: the worktree relative, the home `~`, a temp dir `<tmp>`
            line = m.group(0).strip().replace(f"{ROOT}/", "").replace(str(Path.home()), "~")
            return re.sub(r"/[t]mp/\S*", "<tmp>", line).replace("|", "/")[:160]
    return "-"


def run(task, mutants, only=None):
    out = OUT / (f"{PREFIX}{task}-mutants.txt")
    log = OUT / (f"{PREFIX}{task}-mutants.log")
    sel = [m for m in mutants if not only or m[0] in only]
    if only and len(sel) != len(only):
        print(f"[mutants] {task}: no such mutant: {sorted(set(only) - {m[0] for m in sel})}")
        return 2
    bad = check(sel)
    if bad:
        print(f"[mutants] {task}: refused, mutants that do not load:\n" + "\n".join(bad))
        return 2
    G.refuse_dirty([f for m in sel for f, _, _ in m[1]], ROOT)
    sha = git("rev-parse", "--short=9", "HEAD").stdout.strip()
    dirty = git("diff", "--quiet", "HEAD", "--", ".", *NOT_CODE).returncode != 0
    at = sha + (" dirty" if dirty else "")
    with log.open("a" if only else "w") as lg:
        lg.write(f"# {task} mutants at commit {at}\n")
        cmds = list(dict.fromkeys(m[2] for m in sel))
        base = {}
        for k, cmd in enumerate(cmds, 1):
            print(f"[mutants] {task} baseline {k}/{len(cmds)}: running", flush=True)
            p = G.run(cmd, G.TIMEOUT, shell=True, cwd=ROOT, capture_output=True, text=True)
            base[cmd] = p.seconds
            text = p.stdout + p.stderr
            lg.write(f"\n## baseline\n$ {cmd}\nrc={p.returncode} in {p.seconds:.0f} s\n{text[-6000:]}\n")
            if p.returncode != 0:
                print(f"[mutants] {task}: FAIL baseline red (rc={p.returncode}): {cmd}\n  {failure_line(text)}")
                return 2
            if ran_nothing(text):
                # a green baseline that ran no test would make every mutant of it survive for nothing (plan T39)
                print(f"[mutants] {task}: FAIL baseline ran no test: {cmd}")
                return 2
        kept = {}
        if only and out.exists():
            for line in out.read_text().splitlines()[1:-1]:
                kept[line.split(" | ")[0]] = line
        rows, counts = [], {"killed": 0, "survived": 0, "not loaded": 0, "other failure": 0}
        for k, m in enumerate(mutants, 1):
            name, edits, cmd = m[:3]
            expect = m[3] if len(m) > 3 else None
            if only and name not in only:
                if name in kept:
                    rows.append(kept[name])
                    counts[G.counted(kept[name].split(" | ")[1])] += 1
                continue
            files = {ROOT / f: (ROOT / f).read_bytes() for f, _, _ in edits}
            by = "-"
            try:
                for f, old, new in edits:
                    text = (ROOT / f).read_text()
                    (ROOT / f).write_text(text.replace(old, new, 1))
                limit = G.deadline(base[cmd])
                print(f"[mutants] {task} {k}/{len(mutants)} {name}: running (deadline {limit} s)", flush=True)
                p = G.run(cmd, limit, shell=True, cwd=ROOT, capture_output=True, text=True)
                text = p.stdout + p.stderr
                lg.write(f"\n## {name}\n$ {cmd}\nrc={p.returncode} in {p.seconds:.0f} s"
                         f"{f' (timeout {p.timeout} s)' if p.timeout else ''}\n{text[-6000:]}\n")
                by = failure_line(text)
                if p.timeout:
                    outcome = G.outcome(p, "killed")
                elif p.returncode == 0:
                    outcome, by = "survived", "-"
                elif any(e in text for e in COMPILE_ERRORS):
                    outcome = "not loaded"
                elif by != "-" and killed_by(text, intended(cmd, expect)):
                    outcome = "killed"
                else:
                    # red, but not by the assertion the mutant names (or no failure line at all): no kill (M12)
                    outcome = "other failure"
            finally:
                G.restore(files)
            counts[G.counted(outcome)] += 1
            rows.append(f"{name} | {outcome} | {at} | {cmd.split('&&')[-1].strip()} | {by}")
            print(f"[mutants] {task} {name}: {outcome}", flush=True)
    total = sum(counts.values())
    summary = (f"{total} mutants, {counts['killed']} killed, {counts['survived']} survived, {counts['not loaded']} not loaded, "
               f"{counts['other failure']} other failure")
    out.write_text(f"# {task} mutants (name | outcome | commit | test | first failure line)\n" + "\n".join(rows)
                   + f"\n{summary}\n")
    print(summary)
    return 0 if counts["killed"] == total else 1


def main(task, mutants):
    mode = sys.argv[1] if len(sys.argv) > 1 else "check"
    if mode == "check":
        bad = check(mutants)
        print("\n".join(bad) or f"{len(mutants)} mutants load")
        for s in stale(task, mutants):
            print(f"stale: {s}")
        sys.exit(1 if bad else 0)
    if mode == "run":
        sys.exit(run(task, mutants, set(sys.argv[2:]) or None))
    print("modes: check | run [name…]")
    sys.exit(2)
