#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-native T5 mutants (ua-rs NativeScheme, sign_message, the RawMessage request, external answers); runner and modes:
2026-11-17-ua-rs-native-mutants-run.py. From the worktree root: python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "2026-11-17-ua-rs-native-mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

RS = "clients/ua-rs"
SIGN, SIGNER = RS + "/src/wallet/sign.rs", RS + "/src/wallet/signer.rs"
T = [os.path.abspath("scripts/capped"), "cargo", "test", "--locked", "--offline", "-j2", "--features", "vectors", "--test", "wallet_native"]
M = [(n, f, a, b, T, RS) for n, f, a, b in [
    ("raw-message bound > to >=", SIGN, "message.len() > MAX_RAW_MESSAGE", "message.len() >= MAX_RAW_MESSAGE"),
    ("RawMessage accepted on secp256k1", SIGN, "SignRequest::RawMessage { message } if matches!(scheme, NativeScheme::Ed25519 | NativeScheme::Sr25519) =>",
     "SignRequest::RawMessage { message } =>"),
    ("envelope prefix check removed", SIGN, " || ENVELOPES.iter().any(|p| message.starts_with(p))", ""),
    ("RawMessage mapped to a UaMsg in UaKey::sign_request", SIGN, "    fn sign_request(&self, req: &SignRequest) -> Result<Vec<u8>> {\n        self.sign_ua_msg(req, None)\n    }",
     "    fn sign_request(&self, req: &SignRequest) -> Result<Vec<u8>> {\n        if let SignRequest::RawMessage { message } = req {\n"
     "            let r = SignRequest::UaMsg { kind: self.kind, ua_msg: keccak256(message), role: SigRole::Authorization };\n"
     "            return self.sign_ua_msg(&r, None);\n        }\n        self.sign_ua_msg(req, None)\n    }"),
    ("external_answer not verifying a message", SIGNER, "NativeScheme::Ed25519 => (crate::verify::ed25519(public_key, &bytes, &sig), sig),",
     "NativeScheme::Ed25519 => (true, sig),"),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
