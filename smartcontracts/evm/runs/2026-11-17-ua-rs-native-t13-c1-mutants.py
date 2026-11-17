#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-native T13 C1 mutants (the EVM-prefix rule withdrawn: messages starting 0x05 / 0x19 0x01 sign; the generator keeps the
withdrawn rows out); runner and modes: 2026-11-17-ua-rs-native-mutants-run.py. From the worktree root, NATIVE_DOWNLOADS set for the
generator mutant: python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "2026-11-17-ua-rs-native-mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

CK, RS = "clients/clientkeys", "clients/ua-rs"
SEED, GEN, SIGN = CK + "/src/seed.js", CK + "/scripts/native-vectors.mjs", RS + "/src/wallet/sign.rs"
NODE = [os.path.abspath("scripts/capped"), "node", "--test", "test/native.test.js"]
CARGO = [os.path.abspath("scripts/capped"), "cargo", "test", "--locked", "--offline", "-j2", "--test", "wallet_native"]
G = [os.path.abspath("scripts/capped"), "sh", "-c",
     "node scripts/native-vectors.mjs && git diff --exit-code --quiet -- ../../smartcontracts/vectors/native/native.json; r=$?; "
     "git checkout -q -- ../../smartcontracts/vectors/native/native.json 2>/dev/null; exit $r"]
ENV_CK = "  if (ENVELOPES.some((p) => message.length >= p.length && p.every((b, i) => message[i] === b))) fail('Argument', 'message: a SCaaS off-chain envelope');\n"
ENV_RS = "ENVELOPES.iter().any(|p| message.starts_with(p)) {"
M = [
    ("clientkeys: 0x05 refused again", SEED, ENV_CK, ENV_CK + "  if (message[0] === 0x05) fail('Argument', 'x');\n", NODE, CK),
    ("clientkeys: 0x19 0x01 refused again", SEED, ENV_CK, ENV_CK + "  if (message[0] === 0x19 && message[1] === 0x01) fail('Argument', 'x');\n", NODE, CK),
    ("ua-rs: 0x05 refused again", SIGN, ENV_RS, ENV_RS.replace(" {", " || message.first() == Some(&0x05) {"), CARGO, RS),
    ("ua-rs: 0x19 0x01 refused again", SIGN, ENV_RS, ENV_RS.replace(" {", " || message.starts_with(&[0x19, 0x01]) {"), CARGO, RS),
    ("generator: a withdrawn row comes back", GEN, "const STELLAR_TESTNET_ID = H(sha256(utf8ToBytes('Test SDF Network ; September 2015')));\n",
     "const STELLAR_TESTNET_ID = H(sha256(utf8ToBytes('Test SDF Network ; September 2015')));\n"
     "ref('sign_message EIP-7702 magic 0x05', 'sign_message', at('solana', { message: '0501' }), at('solana', { message: '0601' }));\n", G, CK),
]
if __name__ == "__main__":
    assert os.environ.get("NATIVE_DOWNLOADS"), "NATIVE_DOWNLOADS"
    raise SystemExit(run.main(M))
