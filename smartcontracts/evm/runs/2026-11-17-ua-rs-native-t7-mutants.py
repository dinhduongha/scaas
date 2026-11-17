#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-native T7 mutants (ua-rs Bitcoin P2WPKH / P2TR, the change chain, witness programs, the Taproot signer); runner and modes:
2026-11-17-ua-rs-native-mutants-run.py. From the worktree root: python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "2026-11-17-ua-rs-native-mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

RS = "clients/ua-rs"
MOD, DERIVE, SIGN, MAN = (RS + "/src/wallet/" + f for f in ("mod.rs", "derive.rs", "sign.rs", "manifest.rs"))
T = [os.path.abspath("scripts/capped"), "cargo", "test", "--locked", "--offline", "-j2", "--features", "vectors", "--test", "wallet_native", "--test", "native_fixed"]
M = [(n, f, a, b, T, RS) for n, f, a, b in [
    ("untweaked key", SIGN, "let tweaked = zeroize::Zeroizing::new(*d + t);", "let tweaked = zeroize::Zeroizing::new(*d);"),
    ("no odd-y negation", SIGN, "if p.as_bytes().first() == Some(&3) { -**d0 } else { **d0 }", "**d0"),  # T13 C3: d0 is Zeroizing
    ("Merkle root of 32 zero bytes in the tweak", DERIVE, ".chain_update(tag).chain_update(tag).chain_update(internal_x).finalize()",
     ".chain_update(tag).chain_update(tag).chain_update(internal_x).chain_update([0u8; 32]).finalize()"),
    ("bech32 on v1", DERIVE, "if version == 0 { 1 } else { 0x2bc8_30a3 }", "1"),
    ("bech32m on v0", DERIVE, "if version == 0 { 1 } else { 0x2bc8_30a3 }", "0x2bc8_30a3"),
    ("bc for coin 1", DERIVE, "if coin_type == Some(1) { \"tb\" } else { \"bc\" }", "\"bc\""),
    ("change ignored", MOD, "Network::BitcoinP2wpkh => vec![84 | H, H, H, change, i],", "Network::BitcoinP2wpkh => vec![84 | H, H, H, 0, i],"),
    ("witness program of the internal key", DERIVE,
     "Network::BitcoinP2tr => Some((1, taproot_tweak(public_key.get(1..)?.try_into().ok()?).ok()?.output_key.to_vec())),",
     "Network::BitcoinP2tr => Some((1, public_key.get(1..)?.to_vec())),"),
    ("self-check removed", SIGN, "    if !crate::verify::bip340(check.unwrap_or(&out.output_key), arr32(msg)?, &sig) {\n        return Err(Error::Argument);\n    }\n",
     "    let _ = check;\n"),
    ("change written when 0", MAN, "let change = if n.change == 1 { \",\\\"change\\\":1\" } else { \"\" };",
     "let change = if n.change == 1 { \",\\\"change\\\":1\" } else { \",\\\"change\\\":0\" };"),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
