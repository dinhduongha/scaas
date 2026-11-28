#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Fail once a dated exit of an accepted advisory has passed (node-deps review E-3, 2026-11-28).

An ignore that still matches is silent in cargo deny and cargo audit, and neither knows dates. Every committed deny.toml and
.cargo/audit.toml outside legacy/ is read for "remove from YYYY-MM-DD" and "review by YYYY-MM-DD"; a date before today is red.
Run by .github/workflows/deps-weekly.yml. Usage: python3 -I scripts/check_advisory_exits.py [--today YYYY-MM-DD]
"""

import datetime
import pathlib
import re
import subprocess
import sys

DATED = re.compile(r"(remove from|review by)\s+(\d{4}-\d{2}-\d{2})")


def main() -> int:
    args = sys.argv[1:]
    today = datetime.date.fromisoformat(args[1]) if args[:1] == ["--today"] else datetime.date.today()
    root = pathlib.Path(__file__).resolve().parent.parent
    files = subprocess.run(
        ["git", "ls-files", "*deny.toml", "*.cargo/audit.toml"], cwd=root, capture_output=True, text=True, check=True
    ).stdout.split()
    files = [f for f in files if "legacy/" not in f]
    passed = seen = 0
    for f in files:
        for n, line in enumerate((root / f).read_text().splitlines(), 1):
            for m in DATED.finditer(line):
                seen += 1
                if datetime.date.fromisoformat(m[2]) < today:
                    passed += 1
                    print(f"EXIT PASSED {f}:{n}: {m[1]} {m[2]} (today {today}): {line.strip()}")
    print(f"advisory exits: {seen} dated in {len(files)} policy files, {passed} passed (today {today})")
    return 1 if passed else 0


if __name__ == "__main__":
    sys.exit(main())
