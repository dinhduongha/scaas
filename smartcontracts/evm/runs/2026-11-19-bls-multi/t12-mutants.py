#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""bls-multi Task 12 mutants (ua-go 0x0121 key data). From the worktree root: python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

GO = "clients/ua-go"
F = GO + "/keydata.go"
T = ["go", "test", "-count=1", "-run", "TestBlsMulti|TestValidRows|TestInvalidRows", "-v", "."]
M = [(n, f, a, b, T, GO, e) for n, f, a, b, e in [
    ("uint16 weight sum", F, "		total += w\n", "		total = (total + w) & 0xffff\n", "TestBlsMulti"),
    ("order check <= instead of <", F, "		if i > 0 && bytes.Compare(d[o-258:o-2], k) >= 0 {",
     "		if i > 0 && bytes.Compare(d[o-258:o-2], k) > 0 {", "TestInvalidRows"),
    ("no identity check on apk", F, "	if sum.IsInfinity() {\n		return keyDataErr(\"identity\")\n	}\n", "", "TestInvalidRows"),
    ("a w_i <= t bound added", F, "		if w < 1 {\n			return keyDataErr(\"weight\")", "		if w < 1 || w > int(d[256])<<8|int(d[257]) {\n			return keyDataErr(\"weight\")",
     "TestValidRows"),
    ("n up to 65", F, "	if n < 2 || n > 64 {", "	if n < 2 || n > 65 {", "TestInvalidRows"),
    ("no key check per member", F, "		if err := blsG2(k); err != nil {\n			return err\n		}\n", "", "TestInvalidRows"),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
