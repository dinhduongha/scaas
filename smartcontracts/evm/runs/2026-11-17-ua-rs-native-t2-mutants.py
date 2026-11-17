#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-native T2 mutants (clientkeys NATIVE_NETWORKS, Bitcoin P2WPKH / P2TR, NEAR, the refusals); runner and modes:
2026-11-17-ua-rs-native-mutants-run.py. From the worktree root: python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "2026-11-17-ua-rs-native-mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

CK = "clients/clientkeys"
SEED, UAKEY = CK + "/src/seed.js", CK + "/src/uakey.js"
T = [os.path.abspath("scripts/capped"), "node", "--test", "test/native.test.js"]
M = [(n, f, a, b, T, CK) for n, f, a, b in [
    ("untweaked key signs", SEED, "try { sig = schnorr.sign(digest, tweaked, a); }", "try { sig = schnorr.sign(digest, b32(d), a); }"),  # T13 C3 moved the line into a try
    ("no odd-y negation of the internal key", SEED, "if (P[0] === 3) d = SECP_N - d;", ""),
    ("bech32 constant on witness v1", SEED, "(version === 0 ? bech32 : bech32m).encode(", "(bech32).encode("),
    ("bc for coin 1", SEED, "const hrp = coin === 1 ? 'tb' : 'bc';", "const hrp = 'bc';"),
    ("change chain ignored", SEED, "let path = net.path(i, change ?? 0);", "let path = net.path(i, 0);"),
    ("extraEntropy true on native digests", SEED,
     "{ prehash: false, lowS: true, extraEntropy: false, format: 'recovered' });\n    return concatBytes",
     "{ prehash: false, lowS: true, extraEntropy: true, format: 'recovered' });\n    return concatBytes"),
    ("signTyped guard removed", SEED, "  if (native(key.network)) fail('Argument', 'no EIP-712 on a native network of NATIVE_NETWORKS');\n", ""),
    ("key proof accepted on near", SEED, "  if (native(key.network)) fail('Argument', 'no key proof on a native network of NATIVE_NETWORKS');",
     "  if (native(key.network) && key.network !== 'near') fail('Argument', 'no key proof on a native network of NATIVE_NETWORKS');"),
    ("NEAR coin override accepted", SEED, "  if (coinType != null && network === 'near') fail('Argument', 'near takes no coin-type override');\n", ""),
    ("importedKind looks up NATIVE_NETWORKS too", UAKEY,
     "const net = Object.hasOwn(NETWORKS, network) ? NETWORKS[network] : fail('Argument', 'unknown network');",
     # NATIVE_NETWORKS' curves inline (uakey.js does not import it): bitcoin_* secp256k1, near ed25519
     "const net = Object.hasOwn(NETWORKS, network) ? NETWORKS[network] : ({ bitcoin_p2wpkh: { curve: 'secp256k1' }, bitcoin_p2tr: "
     "{ curve: 'secp256k1' }, near: { curve: 'ed25519' } })[network] ?? fail('Argument', 'unknown network');"),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
