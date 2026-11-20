#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""bls-multi Task 14 mutants (ua-dart 0x0121 key data). From the worktree root: python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

DART = "clients/ua-dart"
F = DART + "/lib/src/keydata.dart"
T = ["dart", "test", "--no-color", "-r", "expanded", "test/vectors_test.dart"]
M = [(n, f, a, b, T, DART, e) for n, f, a, b, e in [
    ("uint16 weight sum", F, "    total += w;\n", "    total = (total + w) & 0xffff;\n", "valid rows"),
    ("order check <= instead of <", F, "    if (i > 0) _need(_cmp(d, o - 258, o, 256) < 0, 'order');",
     "    if (i > 0) _need(_cmp(d, o - 258, o, 256) <= 0, 'order');", "invalid rows"),
    ("no key check per member", F, "    _blsG2(k);\n    if (i > 0) _need(_cmp(d, o - 258", "    if (i > 0) _need(_cmp(d, o - 258",
     "invalid rows"),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
