#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-native T8a mutants (ua-rs Polkadot sr25519: the mini-secret, the bare account, SS58, the one-shot RNG, self-verify);
runner and modes: 2026-11-17-ua-rs-native-mutants-run.py. From the worktree root: python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "2026-11-17-ua-rs-native-mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

RS = "clients/ua-rs"
SUB, MOD, SIGN = RS + "/src/wallet/substrate.rs", RS + "/src/wallet/mod.rs", RS + "/src/wallet/sign.rs"
C = "cargo test --locked --offline -j2 --features vectors"
T = [os.path.abspath("scripts/capped"), "sh", "-c", f"{C} --lib wallet::substrate && {C} --test wallet_native --test native_fixed"]
M = [(n, f, a, b, T, RS) for n, f, a, b in [
    ("the BIP-39 seed in place of the entropy", MOD, "&substrate::mini_secret(entropy, bip39_passphrase))?;\n        Ok(w)",
     "&substrate::mini_secret(&seed_of(entropy, bip39_passphrase)?[..], bip39_passphrase))?;\n        Ok(w)"),
    ("NFKD the passphrase", SUB, "let salt = Zeroizing::new([&b\"mnemonic\"[..], passphrase.as_bytes()].concat());",
     "let nfkd: String = unicode_normalization::UnicodeNormalization::nfkd(passphrase).collect();\n    let salt = Zeroizing::new([&b\"mnemonic\"[..], nfkd.as_bytes()].concat());"),
    ("ExpansionMode::Uniform", SUB, "Ok(Zeroizing::new(m.expand(ExpansionMode::Ed25519).to_bytes()))", "Ok(Zeroizing::new(m.expand(ExpansionMode::Uniform).to_bytes()))"),
    ("context substrat", SUB, "const CONTEXT: &[u8] = b\"substrate\";", "const CONTEXT: &[u8] = b\"substrat\";"),
    ("SS58 checksum over pk only", SUB, "blake2::Blake2b512::digest([&b\"SS58PRE\"[..], &pre, pk].concat())", "blake2::Blake2b512::digest([&b\"SS58PRE\"[..], pk].concat())"),
    ("prefix 64 in one byte", SUB, "let pre = if prefix < 64 {", "let pre = if prefix <= 64 {"),
    ("self-verify removed", SUB, "    if !verify(check, msg, &sig.to_bytes()) {\n        return Err(Error::Argument);\n    }\n", "    let _ = check;\n"),
    ("OsRng's infallible fill_bytes in place of os_aux()", SIGN, "                let r = os_aux()?;\n                return self.secret.with(|s| super::substrate::sign(",
     "                let mut r = [0u8; 32];\n                rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut r);\n                return self.secret.with(|s| super::substrate::sign("),
    ("the one-shot RNG answering a second read", SUB, "        if self.reads == 1 && dest.len() == 32 {", "        if dest.len() == 32 {"),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
