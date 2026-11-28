# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Gate `pqc-reads` (plan T4, CLI-PQC-13): every read the crate makes, with its mark, held to the spec's §5 R2.
  python3 -I clients/pqchat-core/runs/check_reads.py
Lists each read item and its mark from src/net.rs's READS; refuses an item a call site names outside READS or WRITES, a
trusted item the spec's R2 row does not name, and an R2 name read without the trusted mark."""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
SRC = ROOT / "clients/pqchat-core/src"
SPEC = ROOT / "docs/superpowers/specs/2026-11-17-pqchat-core.md"
ITEM = r"(?:I(?:PqChatTreeViews|PqChat|UARegistry|OpenFactory)|PqChatStore)\.\w+"


def main():
    net = (SRC / "net.rs").read_text()
    reads = dict(re.findall(rf'\("({ITEM})", (Trusted|Plain)\)', net))
    writes = set(re.findall(rf'^\s+"({ITEM})",$', net.split("pub const WRITES")[1].split("];")[0], re.M))
    bad = []
    for f in sorted(SRC.glob("*.rs")):
        if f.name == "net.rs":
            continue
        for item in re.findall(rf'"({ITEM})"', f.read_text()):
            if item not in reads and item not in writes:
                bad.append(f"{f.name}: {item} has no mark")
    row = next(ln for ln in SPEC.read_text().splitlines() if ln.startswith("| R2 |"))
    # the R2 names that are views of the ABI (the row's other code spans name fields and the table)
    funcs = {k.split(".")[1] for k in json.loads((SRC / "abi.json").read_text())}
    r2 = set(re.findall(r"`(\w+)`", row)) & funcs
    trusted = {i.split(".")[1] for i, m in reads.items() if m == "Trusted"}
    for n in sorted(trusted - r2):
        bad.append(f"{n}: trusted in READS, not named in spec §5 R2")
    for n in sorted(r2 - trusted):
        bad.append(f"{n}: named in spec §5 R2, not a trusted read in READS")
    for i, m in sorted(reads.items()):
        print(f"{i} {m}")
    print(f"RESULT reads {len(reads)} ({len(trusted)} trusted), writes {len(writes)}, R2 {len(r2)}; {len(bad)} refused")
    for b in bad:
        print(f"FAIL {b}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
