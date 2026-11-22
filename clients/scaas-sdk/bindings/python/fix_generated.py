# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""A defect of UniFFI 0.31.0's Python output, fixed after each generation by runs/2026-11-17-scaas-sdk-gen.sh (plan T20d;
review B16; decisions CLI-SDK-30): an abandoned foreign future is cancelled by `eventloop.call_soon` from a foreign thread,
which asyncio refuses under debug and which is not thread-safe otherwise; `call_soon_threadsafe` is the call for it.

Usage: python3 -I fix_generated.py <generated dir>. Prints the files it changed.
"""

import pathlib
import sys

OLD = "eventloop.call_soon(_uniffi_cancel_task, task)"
NEW = "eventloop.call_soon_threadsafe(_uniffi_cancel_task, task)"


def fix(text):
    return text.replace(OLD, NEW)


def main(root):
    for f in sorted(pathlib.Path(root).rglob("*.py")):
        s = f.read_text()
        t = fix(s)
        if t != s:
            f.write_text(t)
            print(f.relative_to(root))


if __name__ == "__main__":
    main(sys.argv[1])
