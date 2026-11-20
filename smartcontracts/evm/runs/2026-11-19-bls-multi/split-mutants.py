#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""bls-multi, the registry library split (owner 2026-11-19, candidate (2): `UARegistryRegLib`). From the worktree root:
python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

EVM = "smartcontracts/evm"
REG = EVM + "/src/ua/UARegistry.sol"
RL = EVM + "/src/ua/UARegistryRegLib.sol"
AUX = EVM + "/src/ua/UARegistryAuxLib.sol"
T = [os.path.abspath("scripts/capped"), "forge", "test", "--match-path", "test/ua/UARegistryPair.t.sol"]
M = [(n, f, a, b, T, EVM, e) for n, f, a, b, e in [
    ("constructor: no code check of the registration library", REG,
     "                || address(UARegistryRegLib).code.length == 0\n", "",
     "test_b_constructorNeedsTheRegLibrary"),
    ("RegLib: no code check of the core", RL,
     "        if (core.code.length == 0) revert UAConfig(0);\n", "",
     "test_c_regNeedsItsCore"),
    ("register routed to the core library", REG,
     "_lib(address(UARegistryRegLib), UARegistryRegLib.register.selector, kind);",
     "_lib(address(UARegistryCoreLib), UARegistryRegLib.register.selector, kind);",
     "test_b_registrationRunsInTheRegLibrary"),
    ("step-6 PoP accepted without the core's verdict", RL,
     "        if (!_popOk(kind, d, ua, rd, sig, members)) {",
     "        if (false) {",
     "test_c_regNeedsItsCore"),
    ("Aux: pqzHolder sent to the core", AUX,
     "_core(address(UARegistryRegLib), abi.encodeWithSelector(UARegistryRegLib.pqzHolder.selector, kind, d, ua, host));",
     "_core(address(UARegistryCoreLib), abi.encodeWithSelector(UARegistryRegLib.pqzHolder.selector, kind, d, ua, host));",
     "test_c_pqzWritesRunTheCoreHelpers"),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
