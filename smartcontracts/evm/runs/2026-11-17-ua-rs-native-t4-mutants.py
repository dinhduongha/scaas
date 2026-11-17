#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""ua-rs-native T4 mutants (the native.json generator's assertions and its pinned downloads): each must make the generator fail
before it writes; native.json unchanged after. Runner and modes: 2026-11-17-ua-rs-native-mutants-run.py.
From the worktree root, with NATIVE_DOWNLOADS set: python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "2026-11-17-ua-rs-native-mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

CK = "clients/clientkeys"
GEN = CK + "/scripts/native-vectors.mjs"
T = [os.path.abspath("scripts/capped"), "sh", "-c",
     "node scripts/native-vectors.mjs && git diff --exit-code --quiet -- ../../smartcontracts/vectors/native/native.json; r=$?; "
     "git checkout -q -- ../../smartcontracts/vectors/native/native.json 2>/dev/null; exit $r"]
M = [(n, f, a, b, T, CK) for n, f, a, b in [
    ("the odd-parity rows dropped from the parity assertion's input", GEN, "const tapRows = addresses.filter((r) => r.network === 'bitcoin_p2tr');",
     "const tapRows = addresses.filter((r) => r.network === 'bitcoin_p2tr' && r.publicKey.startsWith('02') && !S.taprootTweak(B(r.internalKey)).oddY);"),
    ("the byte-equal Taproot rows marked verify-only", GEN, "mode: 'fixed-randomness', scheme: 'bip340-taproot'", "mode: 'verify-only', scheme: 'bip340-taproot'"),
    ("a wrong pinned sha256", GEN, "'34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d'", "'34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2e'"),
]]
if __name__ == "__main__":
    assert os.environ.get("NATIVE_DOWNLOADS"), "NATIVE_DOWNLOADS"
    raise SystemExit(run.main(M))
