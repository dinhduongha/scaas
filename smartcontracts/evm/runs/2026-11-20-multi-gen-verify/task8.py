# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Task 8: the PQZ home over N generations (spec §11.2, owner P7, M5). Mutants for runs/2026-11-20-multi-gen-verify/mutants.py."""

CORE = "src/ua/UARegistryCoreLib.sol"
AUX = "src/ua/UARegistryAuxLib.sol"
REGLIB = "src/ua/UARegistryRegLib.sol"
REG = "src/ua/UARegistry.sol"
STATE = "src/pqz/PqzStateLib.sol"
H = "test/ua/UARegistryPqzHome.t.sol"
A = "test/pqz/PqzAuditor.t.sol"

M = [
    ("home-newest-enabling", CORE, "        if (h != address(0) && home == address(0) && pqz) home = address(this);",
     "        if (h != address(0) && pqz) home = address(this);", H, "test_pqzHome_a_gen1With_gen2Without_gen3With"),
    ("0142-lists-concatenated", CORE, "        return UAStore.layout().uaCount[kind];\n",
     "        return UAStore.layout().uaCount[kind] + (_pred() != address(0) ? IUARegistry(_pred()).uaCount(kind) : 0);\n",
     H, "test_0142List_perGeneration_stablePositions"),
    ("auditor-kindEnabled", STATE,
     "(!proven && IUARegistry(registry).kindHome(UAKinds.PQZ_MLWE) != address(0))",
     "(!proven && IUARegistry(registry).kindEnabled(UAKinds.PQZ_MLWE))", A, "test_pqzHome_e_auditorChecks_lineWide"),
    ("a5i1-any-predecessor", REGLIB, "            !gen1 && uint160(UARegistryCoreLib._cfgPqz()) == 0 && g1 != address(0)",
     "            !gen1 && g1 != address(0)", H, "test_pqzHome_a_gen1With_gen2Without_gen3With"),
    ("writes-off-home", AUX, "        (, h) = UARegistryCoreLib._pqzWhere(ua);\n        if (h == address(0)) revert",
     "        (address t, address x) = UARegistryCoreLib._pqzWhere(ua);\n        h = x != address(0) ? x : t;\n        if (h == address(0)) revert",
     H, "test_pqzWrites_onlyAtHome"),
    ("reads-to-predecessor", REG, "        (t, h) = (home != address(0) ? home : h, address(0));",
     "        (t, h) = (predecessor, address(0));", H, "test_pqzHome_b_gen1Without_gen2With_gen3With"),
]
