#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-native T6 mutants (ua-rs NEAR); runner and modes: 2026-11-17-ua-rs-native-mutants-run.py.
From the worktree root: python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "2026-11-17-ua-rs-native-mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

RS = "clients/ua-rs"
MOD, DERIVE = RS + "/src/wallet/mod.rs", RS + "/src/wallet/derive.rs"
T = [os.path.abspath("scripts/capped"), "cargo", "test", "--locked", "--offline", "-j2", "--test", "wallet_native"]
M = [(n, f, a, b, T, RS) for n, f, a, b in [
    ("index at the coin level", MOD, "Network::Near => vec![44 | H, 397 | H, i | H],", "Network::Near => vec![44 | H, (397 + i) | H, H],"),
    ("upper-case hex address", DERIVE, "Network::Near => Some(hex(public_key)),", "Network::Near => Some(hex(public_key).to_uppercase()),"),
    ("coin override accepted", MOD, "            (Network::Near, Some(_)) => Err(Error::Argument),\n", ""),
    ("key proof accepted on near", MOD, "        self.scheme_kind().is_some()\n", "        self.scheme_kind().is_some() || self == Network::Near\n"),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
