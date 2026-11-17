#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-native T11a mutants (ua-cxx: the UA-key refusal of the raw calls, the network list). Rust-linked: no feature-bit check
of its own (it builds against this crate). Runner and modes: 2026-11-17-ua-rs-native-mutants-run.py. From the worktree root,
after a ua-cxx gate run (build/ configured): python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "2026-11-17-ua-rs-native-mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

CX = "clients/ua-cxx"
RS = CX + "/src/wallet.rs"
T = [os.path.abspath("scripts/capped"), "sh", "-c", "cmake --build build -j2 > /dev/null && ./build/wallet_test native_json"]
M = [(n, f, a, b, T, CX) for n, f, a, b in [
    ("the UA-key refusal of the raw calls removed", RS,
     'fn raw(k: &Key) -> R<&uw::NativeKey> {\n    match &*k.0 {\n        KeyInner::Ua(_) => Err(UaErr("UARawDigestRefused".into())),',
     'fn raw(k: &Key) -> R<&uw::NativeKey> {\n    match &*k.0 {\n        KeyInner::Ua(_) => Err(argument()),'),
    ("network order swapped (the list reversed)", RS, "uw::Network::all().iter().map(|n| n.name().to_string()).collect()",
     "uw::Network::all().iter().rev().map(|n| n.name().to_string()).collect()"),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
