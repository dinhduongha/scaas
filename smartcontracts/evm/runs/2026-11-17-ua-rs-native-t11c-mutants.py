#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-native T11c mutants (ua-dart-frb: the UA-key refusal of the raw calls, the network list). Rust-linked: no feature-bit
check of its own. Runner and modes: 2026-11-17-ua-rs-native-mutants-run.py. From the worktree root: python3 -I <this> [first last |
check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "2026-11-17-ua-rs-native-mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

DF = "clients/ua-dart-frb"
RS = DF + "/rust/src/api/wallet.rs"
T = [os.path.abspath("scripts/capped"), "sh", "-c",
     "cargo build --locked --offline -j2 --manifest-path rust/Cargo.toml > /dev/null 2>&1 && dart test -r expanded test/wallet_test.dart -N native.json"]
M = [(n, f, a, b, T, DF) for n, f, a, b in [
    ("the UA-key refusal of the raw calls removed", RS,
     '    fn raw(&self) -> R<&uw::NativeKey> {\n        match &*self.0 {\n            KeyInner::Ua(_) => Err(UAError { code: "UARawDigestRefused".into(), reason: String::new() }),',
     '    fn raw(&self) -> R<&uw::NativeKey> {\n        match &*self.0 {\n            KeyInner::Ua(_) => Err(arg()),'),
    ("network order swapped (the list reversed)", RS, "uw::Network::all().iter().map(|n| n.name().to_string()).collect()",
     "uw::Network::all().iter().rev().map(|n| n.name().to_string()).collect()"),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
