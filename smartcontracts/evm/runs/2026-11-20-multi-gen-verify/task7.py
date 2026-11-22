# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Task 7, part 1: the consumer bound counts a member's walk and its holder's cap (P3, N3). Mutants for
runs/2026-11-20-multi-gen-verify/mutants.py."""

REGLIB = "src/ua/UARegistryRegLib.sol"
B = "test/ua/UARegistryHardBound.t.sol"

M = [
    ("predecessor-cap", REGLIB, "            cap = IUARegistry(h).verifyCap(kind);",
     "            cap = IUARegistry(self.predecessor()).verifyCap(kind);", B, "test_notCarriedMember_boundUsesHoldersCap"),
    ("walk-not-counted", REGLIB, "        return (self.generation() - IUARegistry(UARegistryCoreLib._holder(id)).generation()) * LINE_HOP_GAS;",
     "        return 0;", B, "test_notCarriedMember_boundUsesHoldersCap"),
    ("vo-reads-dropped", REGLIB, "            if (cap != 0) return (cap + reads + VO_READ_GAS, cap);",
     "            if (cap != 0) return (cap + reads, cap);", B, "test_voMember_boundCountsReads"),
]
