# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Task 21: fixes of the Fable review (scratchpad report 20261120-fable-review.md). Mutants for mutants.py."""

R = "src/ua/UARegistryRegLib.sol"
V = "test/ua/UARegistryVerifyOnly.t.sol"

M = [
    ("p2-1-inner-at-vo-cap", R, "                here ? mode | INNER : mode | INNER | WRITE,", "                mode | INNER,", V,
     "test_innerMsig_heldElsewhere_boundAtHolderPath"),
]
