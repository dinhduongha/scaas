#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""bls-multi Task 7b mutant (0x0121 portable purposes fail closed). From the worktree root: python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

EVM = "smartcontracts/evm"
CORE = EVM + "/src/ua/UARegistryCoreLib.sol"
T = [os.path.abspath("scripts/capped"), "forge", "test", "--match-path", "test/ua/UARegistryBlsMulti.t.sol"]
M = [(n, f, a, b, T, EVM, e) for n, f, a, b, e in [
    ("verifyPop kept for portable and app purposes", CORE,
     "        if (kind == UAKinds.BLS12381_MULTI && purpose != UAKinds.PURPOSE_POP_V2) return false;\n", "",
     "test_portablePurposes_failClosed"),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
