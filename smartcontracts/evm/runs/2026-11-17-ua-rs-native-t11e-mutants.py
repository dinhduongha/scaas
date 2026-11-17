#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-native T11e mutants (ua-go: the network list, the load check of FeatureNativeNetworks). The UA-key refusal of the raw
calls is the library's (ua-c, T10 M1). Runner and modes: 2026-11-17-ua-rs-native-mutants-run.py. From the worktree root, after
`cargo build --release` in clients/ua-c: python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "2026-11-17-ua-rs-native-mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

GO = "clients/ua-go"
WAL = GO + "/wallet/wallet.go"
T = [os.path.abspath("scripts/capped"), "bash", "-c",
     "set -o pipefail; LD_LIBRARY_PATH=$PWD/../ua-c/target/release go test -count=1 -v -run 'TestNative|TestLoadRefuses' ./wallet/ 2>&1 | grep -E '^(--- FAIL|FAIL|ok|--- PASS)'"]
M = [(n, f, a, b, T, GO) for n, f, a, b in [
    ("network order swapped (near / polkadot)", WAL, '"bitcoin_p2wpkh", "bitcoin_p2tr", "near", "polkadot"}', '"bitcoin_p2wpkh", "bitcoin_p2tr", "polkadot", "near"}'),
    ("the load check of FeatureNativeNetworks removed", WAL, "need, sets := FeatureWallet|FeaturePq|FeatureNativeNetworks, features&featureSets",
     "need, sets := FeatureWallet|FeaturePq, features&featureSets"),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
