# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The setAuditor plan's committed record: `task | step | tree | rc | counts` from the gate runner's progress logs (the last
result per step) and `task mutant | mutant | tests that went red | rc` from the mutant runner's files; no paths, no logs.

Usage (from smartcontracts/evm): python3 runs/2026-11-17-set-auditor/summary.py <task> <tree> <progress.log|mutants.txt> ...
prints the lines; the caller appends them to runs/2026-11-17-set-auditor-summary.txt.
"""
import re
import sys


def counts(line):
    m = re.search(r"(\d+) tests passed, (\d+) failed, (\d+) skipped", line)
    if m:
        return f"{m.group(1)} passed {m.group(2)} failed {m.group(3)} skipped (forge)"
    c = re.findall(r"test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored", line)
    if c:
        p, f, i = (sum(int(x[k]) for x in c) for k in range(3))
        return f"{p} passed {f} failed {i} ignored (cargo, the cells' last two lines)"
    m = re.search(r"size gate: (\d+) error\(s\), (\d+) contracts", line)
    if m:
        return f"size gate: {m.group(1)} error(s), {m.group(2)} contracts"
    for pat in (r"Ran \d+ tests", r"\d+% tests passed, \d+ tests failed out of \d+", r"wasm smoke: \d+ checks passed",
                r"pass \d+", r"\d+ passing"):
        m = re.findall(pat, line)
        if m:
            return ", ".join(m)
    return ""


def main():
    task, tree, files = sys.argv[1], sys.argv[2], sys.argv[3:]
    out = {}
    for f in files:
        for line in open(f, encoding="utf-8", errors="replace"):
            line = line.rstrip("\n")
            if f.endswith("mutants.txt"):
                if " | " in line:
                    out["mut:" + line.split(" | ")[0]] = f"{task} mutant | {line}"
                continue
            m = re.match(r"\d\d:\d\d:\d\d (\S+): rc=(\d+)(.*)$", line)
            if m:
                out[m.group(1)] = f"{task} | {m.group(1)} | {tree} | {m.group(2)} | {counts(m.group(3))}"
    steps = sorted(k for k in out if not k.startswith("mut:"))
    muts = [k for k in out if k.startswith("mut:")]
    for k in steps + muts:
        print(out[k])


if __name__ == "__main__":
    main()
