#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-native T13 C7 mutants (the manifest parser takes only entries the wallet writes); runner and modes:
2026-11-17-ua-rs-native-mutants-run.py. From the worktree root: python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "2026-11-17-ua-rs-native-mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

RS = "clients/ua-rs"
MAN = RS + "/src/wallet/manifest.rs"
CARGO = [os.path.abspath("scripts/capped"), "cargo", "test", "--locked", "--offline", "-j2", "--test", "wallet_native"]
CHECK = "if (change == 1 && !network.bitcoin()) || network.coin_ok(coin_type).is_err() {"
M = [
    ("change 1 off Bitcoin accepted", MAN, CHECK, "if network.coin_ok(coin_type).is_err() {", CARGO, RS),
    ("coin type unchecked", MAN, CHECK, "if change == 1 && !network.bitcoin() {", CARGO, RS),
]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
