# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Task 12: OpenFactory accepts the router registry's line (spec §10, CTR-UA-67). Mutants for mutants.py (not yet run)."""

CORE = "src/ua/UARegistryCoreLib.sol"
F = "test/v2/FactoryDirectory.t.sol"

M = [
    ("no-clone-hash-check", CORE,
     "        if (root.code.length == 0 || IUARegistry(root).smartKeyCloneHash() != _cloneHash()) return false;",
     "        if (root.code.length == 0) return false;", F, "test_env_otherCloneHash_refused"),
    ("walk-not-to-root", CORE, "            if (r == root) return true;", "            if (r != address(0)) return true;", F,
     "test_env_otherChainUid_refused"),
]
