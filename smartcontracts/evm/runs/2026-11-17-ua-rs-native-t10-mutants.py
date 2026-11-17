#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-native T10 mutants (ua-c: networks 9 to 12, bit 12, the raw-message and envelope calls); runner and modes:
2026-11-17-ua-rs-native-mutants-run.py. From the worktree root: python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "2026-11-17-ua-rs-native-mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

UC = "clients/ua-c"
LIB = UC + "/src/lib.rs"
T = [os.path.abspath("scripts/capped"), "sh", "-c",
     "cargo build --locked --offline -j2 2>&1 | tail -3 && python3 -m unittest tests.test_vectors.WalletNative tests.test_vectors.WalletAbi"]
M = [(n, f, a, b, T, UC) for n, f, a, b in [
    ("the UA-key refusal of sign_message_raw removed", LIB,
     "        Key::Ua(_) => Err(fail(SCAAS_UA_ERR_RAW_DIGEST_REFUSED)),\n        Key::Native(n) => write_var(sig, sig_len, &n.sign_message(",
     "        Key::Ua(_) => Err(argument(\"a native key\")),\n        Key::Native(n) => write_var(sig, sig_len, &n.sign_message("),
    ("feature bit 12 -> 11", LIB, "pub const SCAAS_UA_FEATURE_NATIVE_NETWORKS: u64 = 1 << 12;", "pub const SCAAS_UA_FEATURE_NATIVE_NETWORKS: u64 = 1 << 11;"),
    ("feature bit not set", LIB, "            | on(b::WALLET, SCAAS_UA_FEATURE_NATIVE_NETWORKS)\n", ""),
    ("network order swapped (near / polkadot)", LIB, '    "near",\n    "polkadot",\n];', '    "polkadot",\n    "near",\n];'),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
