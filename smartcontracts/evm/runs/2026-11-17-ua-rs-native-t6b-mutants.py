#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-native T6b mutants (ua-rs: the EIP-7702 / EIP-712 prefixes on sign_message, the envelope calls; spec §8.1); runner and
modes: 2026-11-17-ua-rs-native-mutants-run.py. From the worktree root: python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "2026-11-17-ua-rs-native-mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

RS = "clients/ua-rs"
SIGN = RS + "/src/wallet/sign.rs"
T = [os.path.abspath("scripts/capped"), "cargo", "test", "--locked", "--offline", "-j2", "--test", "wallet_native"]
M = [(n, f, a, b, T, RS) for n, f, a, b in [
    ("0x05 check removed", SIGN, "let evm_prefix = message.first() == Some(&0x05) || message.starts_with(&[0x19, 0x01]);",
     "let evm_prefix = message.starts_with(&[0x19, 0x01]);"),
    ("0x19 0x01 check removed", SIGN, "let evm_prefix = message.first() == Some(&0x05) || message.starts_with(&[0x19, 0x01]);",
     "let evm_prefix = message.first() == Some(&0x05);"),
    ("Sui intent dropped", SIGN, "digest([&[0u8; 3][..], t].concat())", "digest(t)"),
    ("Stellar envelope type 5", SIGN, "&[0, 0, 0, 2], t].concat()", "&[0, 0, 0, 5], t].concat()"),
    ("NEAR without the hash", SIGN, "self.envelope(Network::Near, tx_borsh, |t| Sha256::digest(t).to_vec())", "self.envelope(Network::Near, tx_borsh, <[u8]>::to_vec)"),
    ("network check removed", SIGN, "if self.network != network || tx.is_empty()", "if tx.is_empty()"),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
