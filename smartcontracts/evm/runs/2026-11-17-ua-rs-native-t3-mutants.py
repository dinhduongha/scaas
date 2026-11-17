#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-native T3 mutants (clientkeys Polkadot sr25519 in substrate.js, signMessage, the raw-signing guards); runner and modes:
2026-11-17-ua-rs-native-mutants-run.py. From the worktree root: python3 -I <this> [first last | check]
Not applicable here: the plan's "context substrat" mutant (the signing context is @scure/sr25519's own constant, not a string of
clientkeys); it is a T8a mutant of ua-rs, killed there by T0's polkadot.js signature."""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "2026-11-17-ua-rs-native-mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

CK = "clients/clientkeys"
SUB, SEED = CK + "/src/substrate.js", CK + "/src/seed.js"
T = [os.path.abspath("scripts/capped"), "node", "--test", "test/native.test.js"]
M = [(n, f, a, b, T, CK) for n, f, a, b in [
    ("NFKD the passphrase", SUB, "enc.encode('mnemonic'), enc.encode(passphrase)", "enc.encode('mnemonic'), enc.encode(passphrase.normalize('NFKD'))"),
    ("the BIP-39 seed in place of the entropy (the app's old code)", SUB, [
        ("import { UAError } from './ua.js';", "import { UAError } from './ua.js';\nimport { seedFromEntropy } from './seed.js';"),
        ("  const mini = miniSecretFromEntropy(entropy, passphrase);", "  const mini = seedFromEntropy(entropy, passphrase).slice(0, 32);")], None),
    ("hard and soft swapped", SUB, "const next = s.hard ? sr.HDKD.secretHard(", "const next = !s.hard ? sr.HDKD.secretHard("),
    ("SCALE length prefix dropped", SUB, "e = concatBytes(Uint8Array.of(b.length << 2), b);", "e = b;"),
    ("one-byte compact length at 64", SUB, "} else if (b.length < 64) {", "} else if (b.length <= 64) {"),
    ("hash at 32 bytes", SUB, "if (e.length <= 32) { const c = new Uint8Array(32);", "if (e.length < 32) { const c = new Uint8Array(32);"),
    ("numeric junction as a string", SUB, "  if (/^[0-9]+$/.test(junction)) {\n    e = new Uint8Array(8);", "  if (false) {\n    e = new Uint8Array(8);"),
    ("leading zero accepted", SUB, "((junction.length > 1 && junction[0] === '0') || BigInt(junction) > U64_MAX)", "(BigInt(junction) > U64_MAX)"),
    ("raw-message bound 131,071", SEED, "export const MAX_RAW_MESSAGE = 131072;", "export const MAX_RAW_MESSAGE = 131071;"),
    ("envelope prefix check removed", SEED,
     "  if (ENVELOPES.some((p) => message.length >= p.length && p.every((b, i) => message[i] === b))) fail('Argument', 'message: a SCaaS off-chain envelope');\n", ""),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
