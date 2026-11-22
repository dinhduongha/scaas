# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The bindings enabled per language (owner 2026-11-22, decisions CLI-SDK-33 (102)): `clients/scaas-sdk/bindings/langs`, one
name per line (`#` starts a comment), the one list the generator (runs/2026-11-17-scaas-sdk-gen.sh), the gate runner's
`bind-*` steps and CI read. A language left out is neither generated, tested nor run in CI; its committed generated files
stay as they are. A name outside KNOWN, or one named twice, is refused (exit 2).

Usage: python3 -I clients/scaas-sdk/bindings/langs.py   prints the enabled names, space-separated, in the file's order."""

import sys
from pathlib import Path

KNOWN = ("cpp", "cs", "python", "kotlin", "swift", "java", "go", "dart", "js")
FILE = Path(__file__).with_name("langs")


def enabled(text):
    """The names of a list's text, in its order; ValueError for an unknown name or a repeated one."""
    names = [w for line in text.splitlines() for w in line.split("#", 1)[0].split()]
    for n in names:
        if n not in KNOWN:
            raise ValueError(f"unknown binding language {n!r} (known: {' '.join(KNOWN)})")
    if len(set(names)) != len(names):
        raise ValueError("a binding language named twice")
    return names


if __name__ == "__main__":
    try:
        print(" ".join(enabled(FILE.read_text())))
    except (OSError, ValueError) as e:
        print(f"[langs] FAIL {e}", file=sys.stderr)
        sys.exit(2)
