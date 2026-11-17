#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-native T11f mutants (ua-cs: the network list, the load check of FeatureNativeNetworks). The UA-key refusal of the raw
calls is the library's (ua-c, T10 M1). Runner and modes: 2026-11-17-ua-rs-native-mutants-run.py. From the worktree root, after
`cargo build --release` in clients/ua-c: python3 -I <this> [first last | check]. Each run ends `dotnet build-server shutdown`."""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "2026-11-17-ua-rs-native-mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

CS = "clients/ua-cs"
WAL = CS + "/Scaas.Ua/Wallet.cs"
T = [os.path.abspath("scripts/capped"), "bash", "-c",
     "dotnet test Scaas.Ua.Tests --filter 'FullyQualifiedName~Native|FullyQualifiedName~LoadRefuses' --logger 'console;verbosity=normal' "
     "2>&1 | grep -E '^ *(Failed|Passed) Scaas|error CS'; r=${PIPESTATUS[0]}; dotnet build-server shutdown > /dev/null 2>&1; exit $r"]
M = [(n, f, a, b, T, CS) for n, f, a, b in [
    ("network order swapped (near / polkadot)", WAL, '"bitcoin_p2wpkh", "bitcoin_p2tr", "near", "polkadot"];', '"bitcoin_p2wpkh", "bitcoin_p2tr", "polkadot", "near"];'),
    ("the load check of FeatureNativeNetworks removed", WAL, "const ulong need = FeatureWallet | FeaturePq | FeatureNativeNetworks;",
     "const ulong need = FeatureWallet | FeaturePq;"),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
