# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""One `task | step | commit | rc | counts` line per gate log of runs/2026-11-17-pqvault/<tag>/ (the last run of each step; a red
earlier run is <step>.red.log and not listed). Usage (from smartcontracts/evm):
  python3 runs/2026-11-17-pqvault/summary.py <task> <tag> <commit> [step ...]   (no step: every <step>.log of <tag>)"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def counts(t):
    m = re.findall(r"Ran \d+ test suites? in .*?: (\d+) tests passed, (\d+) failed, (\d+) skipped", t)
    if m:
        p, f, s = m[-1]
        return f"{p} passed {f} failed {s} skipped (forge)"
    c = re.findall(r"test result: \w+\. (\d+) passed; (\d+) failed; (\d+) ignored", t)
    if c:
        return f"{sum(int(x[0]) for x in c)} passed {sum(int(x[1]) for x in c)} failed {sum(int(x[2]) for x in c)} ignored (cargo)"
    n = re.search(r"ℹ pass (\d+)\s+ℹ fail (\d+)", t)
    if n:
        return f"{n.group(1)} passed {n.group(2)} failed (node)"
    py = re.findall(r"Ran (\d+) tests? in", t)
    ct = re.findall(r"(\d+)% tests passed, (\d+) tests failed out of (\d+)", t)
    go = len(re.findall(r"^ok\s", t, re.M))
    dart = re.findall(r"\+(\d+)(?: ~\d+)?(?: -(\d+))?: All tests passed", t)
    out = []
    if py:
        out.append(f"{sum(map(int, py))} passed (python)")
    if ct:
        out.append(f"{sum(int(x[2]) - int(x[1]) for x in ct)} passed {sum(int(x[1]) for x in ct)} failed (ctest)")
    if go:
        out.append(f"{go} packages ok (go)")
    if dart:
        out.append(f"{sum(int(x[0]) for x in dart)} passed (dart)")
    if "Passed!" in t or "Failed!" in t:
        d = re.findall(r"(Passed|Failed)!\s+-\s+Failed:\s+(\d+), Passed:\s+(\d+)", t)
        if d:
            out.append(f"{sum(int(x[2]) for x in d)} passed {sum(int(x[1]) for x in d)} failed (dotnet)")
    if "size gate:" in t:
        out.append(re.findall(r"size gate: .*", t)[-1])
    return "; ".join(out) or "-"


def main(task, tag, commit, steps):
    d = os.path.join(HERE, tag)
    if not steps:
        steps = sorted(f[:-4] for f in os.listdir(d) if f.endswith(".log") and not f.endswith(".red.log") and f != "progress.log"
                       and not f.startswith(("mut-", "band-", "setkem-", "pvx-", "portableapp")))
    for s in steps:
        t = open(os.path.join(d, s + ".log"), errors="replace").read()
        rc = re.findall(r"^rc=(\d+)$", t, re.M)
        print(f"{task} | {s} | {commit} | {rc[-1] if rc else '?'} | {counts(t)}")


if __name__ == "__main__":
    if len(sys.argv) < 4:
        raise SystemExit(__doc__)
    main(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4:])
