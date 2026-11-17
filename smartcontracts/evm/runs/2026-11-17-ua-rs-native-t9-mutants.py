#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-native T9 mutant: one byte of an sr25519 signature in rs_native.json flipped; clientkeys' reader of the ua-rs rows must go
red (both ways, CLI-UAL-47). Runner and modes: 2026-11-17-ua-rs-native-mutants-run.py. From the worktree root:
python3 -I <this> [first last | check]. A regenerate that re-signs the row moves the string: refresh it from the file then."""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "2026-11-17-ua-rs-native-mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

CK = "clients/clientkeys"
RSN = "smartcontracts/vectors/native/rs_native.json"
T = [os.path.abspath("scripts/capped"), "node", "--test", "test/native.test.js"]
M = [("a flipped signature byte in rs_native.json (row sr25519-)", RSN, '"b4068603665f72e4210151dfd2f8f1cacc968b0d88e0016a845e4ce188ae7c1b1e5714a3eff9368a7b6266d999f1956a4a277eb0e5c027c5cc59f2ca34a2ee82"', '"b4068603660f72e4210151dfd2f8f1cacc968b0d88e0016a845e4ce188ae7c1b1e5714a3eff9368a7b6266d999f1956a4a277eb0e5c027c5cc59f2ca34a2ee82"', T, CK)]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
