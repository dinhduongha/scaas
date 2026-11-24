# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The scaas-rpc plan's mutant runner (Global constraints): each task's file lists mutants as
(name, [(file, old, new), ...], test command); `check` verifies every `old` occurs exactly once (the mutant loads); `run` applies
one mutant at a time, runs its test command from the worktree root (through scripts/capped, foreground), restores the files
byte for byte, and records the outcome in the task's `-mutants.txt`: `killed` (the test failed), `survived` (it passed),
`not loaded` (the text is missing or the mutant does not compile). Last line: `N mutants, K killed, S survived, L not loaded`.
A hung run is `killed (timeout N s)`: each command first runs once unmutated (it must pass), and a mutant's run past 3 x
that baseline (at least 10 min, or `--timeout N`) has its whole process group killed; it counts as killed. A target file that
differs from HEAD refuses the run (rc 2: a leftover mutation); every mutated file is restored and checked in a `finally`, on
SIGINT / SIGTERM too (scripts/mutant_guard.py, owner 2026-11-24). Full output in a git-ignored `.log` beside it."""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "scripts"))
import mutant_guard as G  # noqa: E402


def check(mutants):
    bad = []
    for name, edits, _ in mutants:
        for f, old, _new in edits:
            n = (ROOT / f).read_text().count(old)
            if n != 1:
                bad.append(f"{name}: {f}: the text occurs {n} times")
    return bad


def run(task, mutants, only=None):
    out = Path(__file__).with_name(f"2026-11-17-scaas-rpc-{task}-mutants.txt")
    log = Path(__file__).with_name(f"2026-11-17-scaas-rpc-{task}-mutants.log")
    sha = subprocess.run(["git", "rev-parse", "--short=9", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    rows, counts = [], {"killed": 0, "survived": 0, "not loaded": 0}
    with log.open("w") as lg:
        lg.write(f"# {task} mutants at commit {sha}\n")
        sel = [m for m in mutants if not only or m[0] in only]
        G.refuse_dirty([f for m in sel for f, _, _ in m[1]], ROOT)
        base = {}
        for cmd in dict.fromkeys(m[2] for m in sel):
            print(f"[mutants] {task} baseline {len(base) + 1}: running", flush=True)
            p = G.run(cmd, G.TIMEOUT, shell=True, cwd=ROOT, capture_output=True, text=True)
            lg.write(f"\n## baseline\n$ {cmd}\nrc={p.returncode} in {p.seconds:.0f} s\n{(p.stdout + p.stderr)[-6000:]}\n")
            if p.returncode != 0:
                print(f"[mutants] {task}: FAIL baseline red (rc={p.returncode}), nothing written: {cmd}")
                return 2
            base[cmd] = p.seconds
        for k, (name, edits, cmd) in enumerate(mutants, 1):
            if only and name not in only:
                continue
            files = {ROOT / f: (ROOT / f).read_bytes() for f, _, _ in edits}
            outcome = None
            try:
                for f, old, new in edits:
                    text = (ROOT / f).read_text()
                    if text.count(old) != 1:
                        outcome = "not loaded"
                        break
                    (ROOT / f).write_text(text.replace(old, new, 1))
                if outcome is None:
                    limit = G.deadline(base[cmd])
                    print(f"[mutants] {task} {k}/{len(mutants)} {name}: running (deadline {limit} s)", flush=True)
                    p = G.run(cmd, limit, shell=True, cwd=ROOT, capture_output=True, text=True)
                    text = p.stdout + p.stderr
                    lg.write(f"\n## {name}\n$ {cmd}\nrc={p.returncode} in {p.seconds:.0f} s\n{text[-6000:]}\n")
                    if p.timeout:
                        outcome = G.outcome(p, "killed")
                    elif p.returncode == 0:
                        outcome = "survived"
                    elif "error[E" in text or "could not compile" in text:
                        outcome = "not loaded"
                    else:
                        outcome = "killed"
            finally:
                G.restore(files)
            counts[G.counted(outcome)] += 1
            rows.append(f"{name} | {outcome} | {cmd.split('&&')[-1].strip()}")
            print(f"[mutants] {task} {name}: {outcome}", flush=True)
    total = sum(counts.values())
    summary = f"{total} mutants, {counts['killed']} killed, {counts['survived']} survived, {counts['not loaded']} not loaded"
    out.write_text(f"# {task} mutants at commit {sha} (name | outcome | test)\n" + "\n".join(rows) + f"\n{summary}\n")
    print(summary)
    return 0 if counts["killed"] == total else 1


def main(task, mutants):
    mode = sys.argv[1] if len(sys.argv) > 1 else "check"
    if mode == "check":
        bad = check(mutants)
        print("\n".join(bad) or f"{len(mutants)} mutants load")
        sys.exit(1 if bad else 0)
    if mode == "run":
        sys.exit(run(task, mutants, set(sys.argv[2:]) or None))
    print("modes: check | run [name…]")
    sys.exit(2)
