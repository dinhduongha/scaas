#!/usr/bin/env python3
"""Rust PQZL roll-out (2026-10-19): the timing columns of several calibration logs side by side, per row.
  python3 -I runs/2026-10-19-calib-timing.py <baseline log>[,<baseline log>...] <run log> [<run log> ...]
The baseline logs are merged (the C core: 2026-10-15-calib.txt,2026-10-17-calib-ops7.txt). Prints p50 valid /
p99 valid / p99 adversarial (ms) per (op, id, stmtLen [M, auditorOn]) row, PQZL rows first."""
import sys


def rows(path):
    out = {}
    for line in open(path):
        c = [x.strip() for x in line.split("|")[1:-1]]
        if len(c) == 12 and c[0].isdigit():
            out[(int(c[0]), c[1], c[2].replace(" ", ""))] = (float(c[5]), float(c[6]), float(c[7]))
    return out


base = {}
for p in sys.argv[1].split(","):
    base |= rows(p)
runs = [rows(p) for p in sys.argv[2:]]
fmt = lambda t: f"{t[0]:.2f} / {t[1]:.2f} / {t[2]:.2f}" if t else "—"
print("| op | id | stmtLen [M, auditorOn] | baseline | " + " | ".join(f"run {i + 1}" for i in range(len(runs))) + " |")
print("|---|---|---|---|" + "---|" * len(runs))
for k in sorted(runs[-1], key=lambda k: (k[1] != "pqzl", k[0], -int(k[2].split("[")[0]), k[2])):
    print(f"| {k[0]} | {k[1]} | {k[2]} | {fmt(base.get(k))} | " + " | ".join(fmt(r.get(k)) for r in runs) + " |")
