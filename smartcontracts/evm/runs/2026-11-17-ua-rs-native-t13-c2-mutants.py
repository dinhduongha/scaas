#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-native T13 C2 mutants (clientkeys signDigest takes exactly 32 bytes); runner and modes:
2026-11-17-ua-rs-native-mutants-run.py. From the worktree root: python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "2026-11-17-ua-rs-native-mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

CK = "clients/clientkeys"
SEED = CK + "/src/seed.js"
NODE = [os.path.abspath("scripts/capped"), "node", "--test", "test/native.test.js"]
CHECK = "  if (!(digest instanceof Uint8Array) || digest.length !== 32) fail('Argument', 'digest: 32 bytes');\n"
M = [
    ("the 32-byte check removed", SEED, CHECK, "", NODE, CK),
    ("any length up to 32", SEED, CHECK, CHECK.replace("digest.length !== 32", "digest.length > 32"), NODE, CK),
]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
