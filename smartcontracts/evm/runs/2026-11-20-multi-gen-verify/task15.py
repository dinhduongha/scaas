# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Task 15: the verify-only gas rows and LINE_HOP_GAS (spec §13 Gas, §11.1 N11). Mutants for mutants.py."""

R = "src/ua/UARegistryRegLib.sol"
F = "test/ua/UAVerifyOnlyGas.t.sol"

M = [
    ("hop-gas-back-to-10000", R, "uint256 internal constant LINE_HOP_GAS = 13_100;",
     "uint256 internal constant LINE_HOP_GAS = 10_000;", F, "test_T_GAS_voConsumer_perDepth"),
]
