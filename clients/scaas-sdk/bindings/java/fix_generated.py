# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Three defects of uniffi-bindgen-java 0.4.2's output, fixed after each generation by runs/2026-11-17-scaas-sdk-gen.sh (plan
T20e2; decisions CLI-SDK-30, T20e2 change). Its config renames cannot reach an item outside the crate root, so a rename cannot.

1. A tuple variant's object field is closed as `this.` with no name; the record names its components `v1`, `v2`, ….
2. A variant field named `value` is bound in a converter's `case` over the method's own parameter `value`: bound as `value_`.
3. The SDK's `Class` (an endpoint's class) shadows `java.lang.Class` in `Class<?>`.

Usage: python3 -I fix_generated.py <generated dir>. Prints the files it changed.
"""

import pathlib
import re
import sys


def fix(text):
    def close(m):
        n = iter(range(1, 99))
        return re.sub(r"this\.(?=\s*[,)])", lambda _: f"this.v{next(n)}", m.group(0))

    t = re.sub(r"AutoCloseableHelper\.close\([^;]*\);", close, text)
    lines, bound = t.split("\n"), False
    for i, line in enumerate(lines):
        if re.search(r"^\s*case .*\(.*\bvar value\b.*\) ->", line):
            lines[i], bound = re.sub(r"\bvar value\b", "var value_", line), True
        elif re.match(r"^\s*case ", line):
            bound = False
        elif bound and "INSTANCE." in line:
            lines[i] = re.sub(r"\bvalue\b", "value_", line)
    t = "\n".join(lines)
    return re.sub(r"(?<![\w.])Class<\?>", "java.lang.Class<?>", t)


def main(root):
    for f in sorted(pathlib.Path(root).rglob("*.java")):
        s = f.read_text()
        t = fix(s)
        if t != s:
            f.write_text(t)
            print(f.relative_to(root))


if __name__ == "__main__":
    main(sys.argv[1])
