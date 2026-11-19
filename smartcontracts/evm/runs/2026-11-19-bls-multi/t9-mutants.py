#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""bls-multi Task 9 mutants (the gas rows and the caps). From the worktree root: python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

EVM = "smartcontracts/evm"
V = EVM + "/src/ua/verifiers/BlsMultiBls12381Verifier.sol"
T = [os.path.abspath("scripts/capped"), "forge", "test", "--match-path", "test/ua/UAGas.t.sol", "--match-contract", "UAGasBlsMultiTest"]
M = [(n, f, a, b, T, EVM, e) for n, f, a, b, e in [
    ("CHECK_GAS below the measured worst verify", V, "    constructor() UASafeVerifier(300_000) {}", "    constructor() UASafeVerifier(250_000) {}",
     "test_T_GAS_blsMultiVerify"),
    ("POP_GAS below the measured worst PoP", V, "    uint256 public constant POP_GAS = 6_700_000;",
     "    uint256 public constant POP_GAS = 5_500_000;", "test_T_GAS_blsMultiPop"),
    ("POP_GAS whose hold exceeds the budget", V, "    uint256 public constant POP_GAS = 6_700_000;",
     "    uint256 public constant POP_GAS = 11_900_000;", "test_T_GAS_blsMultiCapsWithinBudget"),
    ("CHECK_GAS above what the deploy cap holds", V, "    constructor() UASafeVerifier(300_000) {}",
     "    constructor() UASafeVerifier(325_000) {}", "test_T_GAS_blsMultiLeastCap"),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
