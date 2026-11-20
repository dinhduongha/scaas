#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""bls-multi Task 7 mutants (registry: registration, view, deploy). From the worktree root: python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

EVM = "smartcontracts/evm"
CORE = EVM + "/src/ua/UARegistryCoreLib.sol"
STORE = EVM + "/src/ua/UAStore.sol"
REG = EVM + "/src/ua/UARegistry.sol"
T = [os.path.abspath("scripts/capped"), "forge", "test", "--match-path", "test/ua/UARegistryBlsMulti.t.sol"]
M = [(n, f, a, b, T, EVM, e) for n, f, a, b, e in [
    ("keyHash on apk put back", CORE, "        kh = UAKinds.keyHashOf(kind, d);\n",
     "        kh = kind == UAKinds.BLS12381_MULTI ? keccak256(UAStore.cut(d, 0, 256)) : UAKinds.keyHashOf(kind, d);\n",
     "test_twoThresholdsSameSet_bothRegister"),
    ("d stored instead of s", CORE, "SSTORE2.write(multi ? bytes.concat(ua, BlsMultiKeyData.compress(d))",
     "SSTORE2.write(multi ? bytes.concat(ua, d)", "test_storedBytesPerMember"),
    ("ua omitted from p", CORE, "SSTORE2.write(multi ? bytes.concat(ua, BlsMultiKeyData.compress(d))",
     "SSTORE2.write(multi ? BlsMultiKeyData.compress(d)", "test_storedUaIsId"),
    ("vkLength(0x0121) = 0", STORE, "        if (kind == UAKinds.BLS12381_MULTI) return 228;\n", "",
     "test_requireAuthorized_keyDataDOrP_refused"),
    ("keyOf returning p", REG, "        if (r.kind == UAKinds.BLS12381_MULTI) return BlsMultiKeyData.point(SSTORE2.read(r.keyPtr, 0, 224), 0);\n",
     "", "test_keyOf_returnsApk"),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
