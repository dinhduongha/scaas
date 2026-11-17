# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The UA-8 gas rows (`GAS|name|regular|state` of test/ua/UARegistryUA8.t.sol, GAS_REPIN=1 runs at the four sets) against the
pins of `_pin`: prints every row above its pin, `name | old regular / state | new regular / state`; with --write, raises those
pins to the measured figure (a row at or below its pin keeps it: the pins are upper bounds).
usage (from smartcontracts/evm): python3 runs/2026-11-09-ua-mtx-merge-t66b-build/ua8_pins.py <log> [<log> ...] [--write]"""
import re
import sys

TEST = "test/ua/UARegistryUA8.t.sol"
args = [a for a in sys.argv[1:] if a != "--write"]
src = open(TEST).read()
pins = {m[0]: (int(m[1]), int(m[2])) for m in
        re.findall(r'if \(h == keccak256\("([^"]+)"\)\) return \((\d+), (\d+)\);', src)}
rows = {}
for p in args:
    for name, reg, st in re.findall(r"GAS\|([^|]+)\|(\d+)\|(\d+)", open(p).read()):
        rows[name] = (int(reg), int(st))
up = []
for name, (reg, st) in sorted(rows.items()):
    if name not in pins:
        sys.exit(f"no pin for {name}")
    old = pins[name]
    if reg > old[0] or st > old[1]:
        new = (max(reg, old[0]), max(st, old[1]))
        up.append((name, old, new))
        print(f"{name} | {old[0]} / {old[1]} | {new[0]} / {new[1]}")
print(f"{len(rows)} rows, {len(up)} above their pin")
if "--write" in sys.argv:
    for name, old, new in up:
        a = f'if (h == keccak256("{name}")) return ({old[0]}, {old[1]});'
        assert src.count(a) == 1, a
        src = src.replace(a, f'if (h == keccak256("{name}")) return ({new[0]}, {new[1]});')
    open(TEST, "w").write(src)
