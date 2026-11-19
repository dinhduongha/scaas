# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Task 6: the three-state call and the fallback (§5, P10, M7). Mutants for runs/2026-11-20-multi-gen-verify/mutants.py."""

STORE = "src/ua/UAStore.sol"
CORE = "src/ua/UARegistryCoreLib.sol"
V = "test/ua/UARegistryVerifyOnly.t.sol"

M = [
    ("return-2-read-as-accept", STORE, "                if gt(r, 1) { r := 2 }", "                if gt(r, 1) { r := 1 }", V,
     "test_threeStates_andFallback"),
    ("revert-read-as-refuse", STORE, "            r := 2\n            if and(s,", "            r := 0\n            if and(s,", V,
     "test_threeStates_andFallback"),
    ("fallback-on-word-0", CORE, "        return v == 2 ? UAStore.via(h, id, purposeTag, digest, back) : v == 1;",
     "        return v != 1 ? UAStore.via(h, id, purposeTag, digest, back) : true;", V, "test_threeStates_andFallback"),
    ("hold-dropped", STORE, "        if (gasleft() < cap + cap / 63 + SigCheck.GAS_MARGIN) revert UAKinds.UAVerifyGas();\n        assembly (\"memory-safe\") {\n            mstore(0, 2)",
     "        assembly (\"memory-safe\") {\n            mstore(0, 2)", V, "test_gasBelowCap_UAVerifyGas"),
    ("group-kinds-cap-not-budget", CORE, "            ? IUARegistry(address(this)).verifyBudget()\n            : UAStore._capOf(cfg);",
     "            ? UAStore._capOf(cfg)\n            : UAStore._capOf(cfg);", V, "test_groupKind_verifyOnly_holds"),
    ("app-fallback-via-requirePortable", CORE, "            appId == 0\n", "            true\n", V, "test_fallback_entry_perPath"),
]
