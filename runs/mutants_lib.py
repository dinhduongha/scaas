# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The Avalanche / Polkadot / Arweave plan's mutant runner (Global constraints; from the scaas-rpc plan's): each task's file
lists mutants as (name, [(file, old, new), ...], test command[, expect]); `expect`, when given, is a text the failing output must
hold (the named test's own failure reason), else the outcome is `killed elsewhere` and counts as a survivor; `check` verifies every `old` occurs exactly once (the mutant loads); `run` applies
one mutant at a time, runs its test command from the worktree root (through scripts/capped, foreground), restores the files
byte for byte, and records the outcome in the task's `-mutants.txt`: `killed` (the test failed), `survived` (it passed),
`not loaded` (the text is missing or the mutant does not compile). Last line: `N mutants, K killed, S survived, L not loaded`.
Full output in a git-ignored `.log` beside it."""
import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def check(mutants):
    bad = []
    for name, edits, *_ in mutants:
        for f, old, _new in edits:
            n = (ROOT / f).read_text().count(old)
            if n != 1:
                bad.append(f"{name}: {f}: the text occurs {n} times")
    return bad


def run(task, mutants, only=None, prefix="2026-11-21-avax-dot-arweave"):
    out = Path(__file__).with_name(f"{prefix}-{task}-mutants.txt")
    log = Path(__file__).with_name(f"{prefix}-{task}-mutants.log")
    sha = subprocess.run(["git", "rev-parse", "--short=9", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    rows, counts = [], {"killed": 0, "survived": 0, "killed elsewhere": 0, "not loaded": 0}
    with log.open("w") as lg:
        lg.write(f"# {task} mutants at commit {sha}\n")
        for k, (name, edits, cmd, *ex) in enumerate(mutants, 1):
            if only and name not in only:
                continue
            files = {f: (ROOT / f).read_bytes() for f, _, _ in edits}
            digest = {f: hashlib.sha256(b).hexdigest() for f, b in files.items()}
            outcome = None
            try:
                for f, old, new in edits:
                    text = (ROOT / f).read_text()
                    if text.count(old) != 1:
                        outcome = "not loaded"
                        break
                    (ROOT / f).write_text(text.replace(old, new, 1))
                if outcome is None:
                    print(f"[mutants] {task} {k}/{len(mutants)} {name}: running", flush=True)
                    p = subprocess.run(cmd, shell=True, cwd=ROOT, capture_output=True, text=True)
                    text = p.stdout + p.stderr
                    lg.write(f"\n## {name}\n$ {cmd}\nrc={p.returncode}\n{text[-6000:]}\n")
                    if p.returncode == 0:
                        outcome = "survived"
                    elif any(m in text for m in ("error[E", "could not compile", "Compiler run failed", "SyntaxError")):
                        outcome = "not loaded"
                    elif ex and ex[0] not in text:
                        outcome = "killed elsewhere"
                    else:
                        outcome = "killed"
            finally:
                for f, b in files.items():
                    (ROOT / f).write_bytes(b)
                for f in files:
                    assert hashlib.sha256((ROOT / f).read_bytes()).hexdigest() == digest[f], f"{f} not restored"
            counts[outcome] += 1
            rows.append(f"{name} | {outcome} | {cmd.split('&&')[-1].strip()}")
            print(f"[mutants] {task} {name}: {outcome}", flush=True)
    total = sum(counts.values())
    summary = (f"{total} mutants, {counts['killed']} killed, {counts['survived'] + counts['killed elsewhere']} survived"
               f" ({counts['killed elsewhere']} killed elsewhere), {counts['not loaded']} not loaded")
    out.write_text(f"# {task} mutants at commit {sha} (name | outcome | test)\n" + "\n".join(rows) + f"\n{summary}\n")
    print(summary)
    return 0 if counts["killed"] == total else 1


def main(task, mutants, prefix="2026-11-21-avax-dot-arweave"):
    mode = sys.argv[1] if len(sys.argv) > 1 else "check"
    if mode == "check":
        bad = check(mutants)
        print("\n".join(bad) or f"{len(mutants)} mutants load")
        sys.exit(1 if bad else 0)
    if mode == "run":
        sys.exit(run(task, mutants, set(sys.argv[2:]) or None, prefix))
    print("modes: check | run [name…]")
    sys.exit(2)
