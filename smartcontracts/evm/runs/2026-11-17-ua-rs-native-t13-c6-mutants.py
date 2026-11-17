#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-native T13 C6 mutants (sign_near_transaction refuses the NEP-413 and NEP-366 tags); runner and modes:
2026-11-17-ua-rs-native-mutants-run.py. From the worktree root: python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "2026-11-17-ua-rs-native-mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

CK, RS = "clients/clientkeys", "clients/ua-rs"
SEED, SIGN = CK + "/src/seed.js", RS + "/src/wallet/sign.rs"
NODE = [os.path.abspath("scripts/capped"), "node", "--test", "test/native.test.js"]
CARGO = [os.path.abspath("scripts/capped"), "cargo", "test", "--locked", "--offline", "-j2", "--test", "wallet_native"]
M = [
    ("clientkeys: the tag check removed", SEED, "  if (t.length >= 4 && NEP461_TAGS.includes(", "  if (false && NEP461_TAGS.includes(", NODE, CK),
    ("clientkeys: NEP-366 dropped", SEED, "const NEP461_TAGS = [2 ** 31 + 413, 2 ** 30 + 366];", "const NEP461_TAGS = [2 ** 31 + 413];", NODE, CK),
    ("clientkeys: big-endian read", SEED, ".getUint32(0, true))) fail(", ".getUint32(0, false))) fail(", NODE, CK),
    ("ua-rs: the tag check removed", SIGN, ".is_some_and(|b| NEP461_TAGS.contains(&u32::from_le_bytes(b))) {", ".is_some_and(|b| NEP461_TAGS.contains(&u32::from_le_bytes(b)) && false) {", CARGO, RS),
    ("ua-rs: NEP-413 dropped", SIGN, "const NEP461_TAGS: [u32; 2] = [(1 << 31) + 413, (1 << 30) + 366];", "const NEP461_TAGS: [u32; 2] = [(1 << 30) + 366, (1 << 30) + 366];", CARGO, RS),
    ("ua-rs: big-endian read", SIGN, "NEP461_TAGS.contains(&u32::from_le_bytes(b))", "NEP461_TAGS.contains(&u32::from_be_bytes(b))", CARGO, RS),
]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
