#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-native T6a mutants (clientkeys: the EIP-7702 / EIP-712 prefixes on signMessage, the envelope calls, native.json append-only;
spec §8.1); runner and modes: 2026-11-17-ua-rs-native-mutants-run.py. From the worktree root, NATIVE_DOWNLOADS set for the
generator mutant: python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "2026-11-17-ua-rs-native-mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

CK = "clients/clientkeys"
SEED, GEN = CK + "/src/seed.js", CK + "/scripts/native-vectors.mjs"
T = [os.path.abspath("scripts/capped"), "node", "--test", "test/native.test.js"]
G = [os.path.abspath("scripts/capped"), "sh", "-c",
     "node scripts/native-vectors.mjs && git diff --exit-code --quiet -- ../../smartcontracts/vectors/native/native.json; r=$?; "
     "git checkout -q -- ../../smartcontracts/vectors/native/native.json 2>/dev/null; exit $r"]
M = [(n, f, a, b, T, CK) for n, f, a, b in [
    ("0x05 check removed", SEED, "if (message[0] === 0x05 || (message[0] === 0x19 && message[1] === 0x01))", "if ((message[0] === 0x19 && message[1] === 0x01))"),
    ("0x19 0x01 check removed", SEED, "if (message[0] === 0x05 || (message[0] === 0x19 && message[1] === 0x01))", "if (message[0] === 0x05)"),
    ("Sui intent dropped", SEED, "(t) => blake2b(concatBytes(new Uint8Array(3), t), { dkLen: 32 }));", "(t) => blake2b(t, { dkLen: 32 }));"),
    ("Stellar envelope type 5", SEED, "new Uint8Array([0, 0, 0, 2]), t)", "new Uint8Array([0, 0, 0, 5]), t)"),
    ("NEAR without the hash", SEED, "envelope(key, 'near', txBorsh, allowRawDigest, (t) => sha256(t));", "envelope(key, 'near', txBorsh, allowRawDigest, (t) => t);"),
    ("network check removed", SEED, "  if (key.network !== network) fail('Argument', `a ${network} key only`);\n", ""),
]] + [("a committed row changed (the append-only assertion refuses)", GEN, "const sighash = (n) => H(sha256(utf8ToBytes(`scaas ua-rs-native sighash ${n}`)));",
       "const sighash = (n) => H(sha256(utf8ToBytes(`scaas ua-rs-native sighash! ${n}`)));", G, CK)]
if __name__ == "__main__":
    assert os.environ.get("NATIVE_DOWNLOADS"), "NATIVE_DOWNLOADS"
    raise SystemExit(run.main(M))
