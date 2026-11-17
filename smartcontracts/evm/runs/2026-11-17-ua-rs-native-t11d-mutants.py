#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-native T11d mutants (ua-py: the network list, the load check of bit native-networks). The UA-key refusal of the raw calls
is the library's (ua-c, T10 M1): the binding passes the status through. Runner and modes: 2026-11-17-ua-rs-native-mutants-run.py.
From the worktree root, after `cargo build --release` in clients/ua-c: python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "2026-11-17-ua-rs-native-mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

PY = "clients/ua-py"
WAL = PY + "/scaas_ua/wallet.py"
T = ["python3", "-m", "unittest", "tests.test_wallet.Native", "tests.test_wallet.Load"]
M = [(n, f, a, b, T, PY) for n, f, a, b in [
    ("network order swapped (near / polkadot)", WAL, "'bitcoin_p2wpkh', 'bitcoin_p2tr', 'near', 'polkadot')", "'bitcoin_p2wpkh', 'bitcoin_p2tr', 'polkadot', 'near')"),
    ("the load check of bit native-networks removed", WAL, "need = FEATURE['wallet'] | FEATURE['pq'] | FEATURE['native-networks']", "need = FEATURE['wallet'] | FEATURE['pq']"),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
