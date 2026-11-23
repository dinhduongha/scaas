# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The C++ drift check's comparison (runs/2026-11-17-scaas-sdk-gen.sh): uniffi-bindgen-cpp writes its type definitions in a
hash map's order, so a regenerated file may hold the committed file's blocks in another order. Run:
python3 -I same_blocks.py <regenerated> <committed>: exit 0 when both hold the same blocks (runs of non-blank lines), each block's
lines in the same order."""

import re
import sys


def blocks(t):
    """The runs of non-blank lines of `t`, each kept whole in its own order, sorted."""
    return sorted(b.strip("\n") for b in re.split(r"\n[ \t]*\n", t) if b.strip())


def same(a, b):
    """The same blocks in any order (review T26 C-4: a sort of single lines hid a change that only moves lines inside a block,
    a record's fields swapped)."""
    return blocks(a) == blocks(b)


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8") as x, open(sys.argv[2], encoding="utf-8") as y:
        sys.exit(0 if same(x.read(), y.read()) else 1)
