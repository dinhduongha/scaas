# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""A defect of uniffi-bindgen-go v0.7.1+v0.31.0's output, fixed after each generation by runs/2026-11-17-scaas-sdk-gen.sh
(plan T20h; decisions CLI-SDK-30, T20h change): the external-type helpers of a custom type over `bool` (the SDK's
`AllowOpaqueCall`) convert a Go `bool` to `C.int8_t` and back, which Go refuses; they convert by value instead.

Usage: python3 -I fix_generated.py <generated dir>. Prints the files it changed.
"""

import pathlib
import re
import sys

LIFT = re.compile(r"(func LiftFromExternalType\w+\(value bool\) \w+ \{\n\treturn \w+)\.Lift\(C\.int8_t\(value\)\)")
LOWER = re.compile(r"(func LowerToExternalType\w+\(value \w+\) bool \{\n\treturn )bool\((\w+\.Lower\(value\))\)")


def fix(text):
    t = LIFT.sub(r"\1.Lift(func() C.int8_t {\n\t\tif value {\n\t\t\treturn 1\n\t\t}\n\t\treturn 0\n\t}())", text)
    return LOWER.sub(r"\1\2 != 0", t)


def main(root):
    for f in sorted(pathlib.Path(root).rglob("*.go")):
        s = f.read_text()
        t = fix(s)
        if t != s:
            f.write_text(t)
            print(f.relative_to(root))


if __name__ == "__main__":
    main(sys.argv[1])
