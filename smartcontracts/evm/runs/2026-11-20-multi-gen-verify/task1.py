# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Task 1 (owner X1): the registry's txGasCap. Mutants for runs/2026-11-20-multi-gen-verify/mutants.py."""

REG = "src/ua/UARegistry.sol"
REGLIB = "src/ua/UARegistryRegLib.sol"
UPD = "test/ua/UARegistryMsigUpdate.t.sol"
BND = "test/ua/UARegistryPqzBound.t.sol"
CAP = "test/ua/UARegistryTxCap.t.sol"

M = [
    (
        "msigDebit-literal-2-24",
        REGLIB,
        "(uint256 debit, uint256 cap) = (PqzSet.PQZ_DEBIT_MIN_GAS, _txGasCap());",
        "(uint256 debit, uint256 cap) = (PqzSet.PQZ_DEBIT_MIN_GAS, 1 << 24);",
        BND,
        "test_msigDebit_readsTxGasCap",
    ),
    (
        "msigBound-literal-2-24",
        REGLIB,
        "+ MSIG_UPDATE_GAS + n * MSIG_UPDATE_SLOT_GAS > _txGasCap()) {",
        "+ MSIG_UPDATE_GAS + n * MSIG_UPDATE_SLOT_GAS > 1 << 24) {",
        UPD,
        "test_msigBound_readsTxGasCap",
    ),
    (
        "constructor-no-budget-check",
        REG,
        "if (verifyBudget_ == 0 || verifyBudget_ > txGasCap_ || (smartKeyAccountImpl_",
        "if (verifyBudget_ == 0 || (smartKeyAccountImpl_",
        CAP,
        "test_txGasCap_belowBudget_UAConfig0",
    ),
]
