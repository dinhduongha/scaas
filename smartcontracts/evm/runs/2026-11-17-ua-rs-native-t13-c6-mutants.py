#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-native T13 C6 mutants (sign_near_transaction refuses a payload whose first u32, little-endian, is at or above 2^30:
NEP-461's reserved ranges); runner and modes: 2026-11-17-ua-rs-native-mutants-run.py. From the worktree root:
python3 -I <this> [first last | check]"""
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
    ("clientkeys: >= 2^30 becomes >= 2^31", SEED, "const NEP461_MIN = 2 ** 30;", "const NEP461_MIN = 2 ** 31;", NODE, CK),
    ("clientkeys: the range check removed", SEED, ".getUint32(0, true) >= NEP461_MIN) fail(", ".getUint32(0, true) >= 2 ** 32) fail(", NODE, CK),
    ("clientkeys: big-endian read", SEED, ".getUint32(0, true) >= NEP461_MIN", ".getUint32(0, false) >= NEP461_MIN", NODE, CK),
    ("ua-rs: >= 2^30 becomes >= 2^31", SIGN, "const NEP461_MIN: u32 = 1 << 30;", "const NEP461_MIN: u32 = 1 << 31;", CARGO, RS),
    ("ua-rs: the range check removed", SIGN, "u32::from_le_bytes(b) >= NEP461_MIN) {", "u32::from_le_bytes(b) >= NEP461_MIN && false) {", CARGO, RS),
    ("ua-rs: big-endian read", SIGN, "u32::from_le_bytes(b) >= NEP461_MIN", "u32::from_be_bytes(b) >= NEP461_MIN", CARGO, RS),
]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
