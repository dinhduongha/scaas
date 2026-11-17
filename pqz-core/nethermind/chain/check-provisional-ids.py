#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Review 3zh Fable F-9 (CI, plain text, no Docker): every row id of each chain/engine-pqz-provisional-<n>.json is one of
its set's compiled-in ids (Nethermind.Pqz/PqzSetIds.cs, written by gen_set.py), i.e. the node built for that set starts
on that schedule (PqzChainSpecEngineParameters.CheckIds at a fresh chain). chain/engine-pqz.json (the calibration's
output, the default set's) is reported: ok, or refused with the ids it carries. Exit 1 on any provisional mismatch."""
import json, pathlib, re, sys

here = pathlib.Path(__file__).resolve().parent
src = (here.parent / "Nethermind.Pqz" / "PqzSetIds.cs").read_text()
ids = {}
for m in re.finditer(r'PQZ_SET_(N\d+)_KMAX\d+\s+public const string PqzlId = "([0-9a-f]{64})", PqzhId = "([0-9a-f]*)";', src):
    ids[m.group(1).lower()] = {m.group(2)} | ({m.group(3)} if m.group(3) else set())
if len(ids) != 4:
    sys.exit(f"PqzSetIds.cs: {len(ids)} sets parsed, expected 4")


def rows(path):
    return [r["id"].lower().removeprefix("0x") for s in json.loads(path.read_text())["schedules"] for r in s["pqz"]]


bad = 0
for n, want in sorted(ids.items()):
    f = here / f"engine-pqz-provisional-{n}.json"
    got = rows(f)
    other = sorted({i[:8] for i in got if i not in want})
    print(f"{f.name}: {len(got)} rows, {'ok' if got and not other else 'FAIL: not the set ids ' + str(other)}")
    bad += not got or bool(other)
got = rows(here / "engine-pqz.json")
other = sorted({i[:8] for i in got if i not in ids["n2304"]})
print(f"engine-pqz.json (n2304-kmax4096): {'ok' if not other else 'refused at start-up, retired ids ' + str(other) + ' (a calibration rewrites it)'}")
sys.exit(1 if bad else 0)
