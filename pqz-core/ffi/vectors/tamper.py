#!/usr/bin/env python3
"""Tamper test of pqz_kat.py's vector checkers (P6e Task 11): in a copy of the vector directory, leaves of each file
(spread evenly over it) are changed one at a time (int + 1, bool negated, hex: last bit flipped, text: a character
appended); each change must make that file's checker fail. Skipped by design: free text (description, generator, note,
name, what, alignment) and rnd32 (any rnd32 gives a valid proof; pqz-vectors --check pins it, and selftest.json the
REGISTER rows').
  python3 -I tamper.py [vector dir] [leaves per file, default 12]
The parameter set: PQZ_SET (pqz_kat.py's; default the v3 set and its directory smartcontracts/vectors/pqz, another set
smartcontracts/vectors/pqz/<set>)."""
import importlib.util
import json
import os
import shutil
import sys
import tempfile

V = os.path.join(os.path.dirname(os.path.abspath(__file__)), "../../../smartcontracts/vectors/pqz")
SET = os.environ.get("PQZ_SET", "n2304-kmax4096")  # pqz_kat.py's and the builds' default (plan 5h Task 8d)
D = sys.argv[1] if len(sys.argv) > 1 else (V if SET == "n2048-kmax1024" else os.path.join(V, SET))
N = int(sys.argv[2]) if len(sys.argv) > 2 else 12
spec = importlib.util.spec_from_file_location("pqz_kat", os.path.join(V, "pqz_kat.py"))
kat = importlib.util.module_from_spec(spec)
spec.loader.exec_module(kat)
SKIP = {"description", "generator", "name", "what", "alignment", "note", "rnd32"}


def leaves(j, path=()):
    if isinstance(j, dict):
        for k, v in j.items():
            if k not in SKIP:
                yield from leaves(v, path + (k,))
    elif isinstance(j, list):
        for i, v in enumerate(j):
            yield from leaves(v, path + (i,))
    else:
        yield path


def mutate(x):
    if isinstance(x, bool):
        return not x
    if isinstance(x, int):
        return x + 1
    if x and len(x) % 2 == 0 and all(c in "0123456789abcdef" for c in x):
        return x[:-1] + format(int(x[-1], 16) ^ 1, "x")
    return x + "x"


fails = total = 0
for name in sorted(f for f in os.listdir(D) if f.endswith(".json")):
    j = json.load(open(os.path.join(D, name)))
    ls = list(leaves(j))
    picks = sorted({ls[i * len(ls) // N] for i in range(N)})
    caught = 0
    for path in picks:
        t = tempfile.mkdtemp()
        try:
            for f in os.listdir(D):
                if f.endswith(".json"):
                    shutil.copy(os.path.join(D, f), t)
            jj = json.load(open(os.path.join(t, name)))
            node = jj
            for k in path[:-1]:
                node = node[k]
            node[path[-1]] = mutate(node[path[-1]])
            json.dump(jj, open(os.path.join(t, name), "w"))
            bad = kat.check_files([os.path.join(t, name)], lambda _: None)
        finally:
            shutil.rmtree(t)
        total += 1
        caught += bool(bad)
        if not bad:
            fails += 1
            print(f"NOT CAUGHT {name} {'/'.join(map(str, path))}")
    print(f"{name}: {caught} / {len(picks)} changes caught")
print(f"tamper: {total - fails} / {total} caught:", "ok" if fails == 0 else "FAIL")
sys.exit(1 if fails else 0)
