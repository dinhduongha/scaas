#!/usr/bin/env python3
"""typed-signing R2: the PQZ gas table at each set against C6's: rows that moved, by column; the debit row.
  python3 -I runs/2026-11-01-typed-signing-r2-gas-compare.py"""
import re

SETS = ["n2048-kmax1024", "n2304-kmax4096", "n2560-kmax16384", "n2816-kmax65536"]
PIN = {"n2048-kmax1024": 6826921, "n2304-kmax4096": 6998368, "n2560-kmax16384": 7168690, "n2816-kmax65536": 7358343}


def rows(f):
    r, head = {}, None
    for l in open(f, errors="replace"):
        m = re.match(r"\s*GAS \S+ (\S+) \| (.*?) \| calldata (\d+)", l)
        if m:
            head = (m[1], m[2], int(m[3]))
            continue
        m = re.match(r"\s*\| pqz (\d+) \| exec (\d+) \| regular (\d+) .*state (\d+) \| fits 2\^24 (\w+)", l)
        if m and head:
            r[head[:2]] = dict(calldata=head[2], pqz=int(m[1]), exec=int(m[2]), regular=int(m[3]), state=int(m[4]), fits=m[5])
    return r


for s in SETS:
    a = rows(f"runs/2026-11-01-typed-signing-c6-gas-{s}.txt")
    b = rows(f"runs/2026-11-01-typed-signing-r2-gas-{s}.txt")
    assert a.keys() == b.keys(), s
    moved = {k: sum(a[r][k] != b[r][k] for r in a) for k in ("calldata", "pqz", "exec", "regular", "state", "fits")}
    d = sorted(b[r]["regular"] - a[r]["regular"] for r in a)
    k = ("pqzl-ua", "burn 1 to an address, fresh ref")
    print(f"{s}: {len(a)} rows; moved by column {moved}; regular delta {d[0]:+d} .. {d[-1]:+d}; "
          f"debit row {a[k]['regular']} -> {b[k]['regular']} ({b[k]['regular'] - a[k]['regular']:+d}), pin {PIN[s]}, over the pin {b[k]['regular'] - PIN[s]:+d}; "
          f"all fit 2^24: {all(v['fits'] == 'yes' for v in b.values())}")
    reg = [(r, a[r]["regular"], b[r]["regular"]) for r in a if abs(b[r]["regular"] - a[r]["regular"]) > 500]
    for r, x, y in reg:
        print(f"  {r[0]} | {r[1]}: {x} -> {y} ({y - x:+d})")
