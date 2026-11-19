#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""bls-multi Task 11 mutants (ua-py 0x0121 key data). From the worktree root: python3 -I <this> [first last | check]"""
import importlib.util
import os
import sys

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

PY = "clients/ua-py"
F = PY + "/scaas_ua/__init__.py"
T = [sys.executable, "-m", "unittest", "tests.test_vectors"]
M = [(n, f, a, b, T, PY, e) for n, f, a, b, e in [
    ("uint16 weight sum", F, "    _need(1 <= t <= sum(weights), \"threshold\")", "    _need(1 <= t <= sum(weights) & 0xFFFF, \"threshold\")",
     "test_key_data_rows"),
    ("order check <= instead of <", F, "            _need(d[o - 258 : o - 2] < k, \"order\")", "            _need(d[o - 258 : o - 2] <= k, \"order\")",
     "test_invalid_rows"),
    ("no identity check on apk", F, "    _need(not _bls.is_inf(acc), \"identity\")\n", "", "test_invalid_rows"),
    ("a w_i <= t bound added", F, "    _need(all(w >= 1 for w in weights), \"weight\")",
     "    _need(all(1 <= w <= _u16(d, 256) for w in weights), \"weight\")", "test_valid_rows"),
    ("n up to 65", F, "    _need(2 <= n <= 64, \"n\")", "    _need(2 <= n <= 65, \"n\")", "test_invalid_rows"),
    ("no key check per member", F, "        _bls_g2(k)\n", "", "test_invalid_rows"),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
