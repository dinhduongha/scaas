# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The setAuditor plan's ratchet moves (plan A5; size-baseline.json is a ratchet, every move old -> new with its reason): reads a
size_gate.py output, raises each row it reports over its baseline to the measured size, adds a row (and its `_forms` entry, the
form the gate printed for it) for each contract it reports over 24,576 B without a row, and appends one sentence to `_comment`
with every move. Prints the moves. Usage (from smartcontracts/evm):
  python3 runs/2026-11-17-set-auditor/baseline.py <size.log> "<reason prefix>"
"""
import json
import re
import sys

log, reason = sys.argv[1], sys.argv[2]
text = open(log, encoding="utf-8", errors="replace").read()
path = "size-baseline.json"
raw = open(path).read()
d = json.loads(raw)
moves = []
for name, new, old in re.findall(r"^error: (\w+): runtime (\d+) > baseline (\d+)", text, re.M):
    if d[name] == int(new):
        continue  # an earlier task's move already raised it to this size
    prev = d[name]  # the log's baseline, or an earlier task's smaller move of this round
    assert prev == int(old) or int(old) < prev < int(new), (name, prev, old)
    d[name] = int(new)
    moves.append(f"`{name}` {prev:,} -> {int(new):,}")
forms = {"Z": "module", "S": "module", "Q": "module", "P": "module", "A": "module", "T": "module", "W": "module", "R": "module"}
for name, new in re.findall(r"^error: (\w+): runtime (\d+) > 24576", text, re.M):
    if d.get(name) == int(new):
        continue
    assert name not in d, name
    d[name] = int(new)
    form = "library" if name.endswith("Lib") else forms.get(name[-1], "release") if name[-1].isupper() and name[-2].islower() else "release"
    d["_forms"][name] = form
    moves.append(f"`{name}` new row {int(new):,} ({form}, first past 24,576 B)")
if not moves:
    sys.exit("no move")
d["_comment"] += f" {reason}: " + "; ".join(moves) + "."
out = json.dumps(d, indent=2)  # the file's own form: insertion order, ASCII escapes
open(path, "w").write(out + ("\n" if raw.endswith("\n") else ""))
print("\n".join(moves))
