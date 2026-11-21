# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Task 13: deploy's later-generation mode (spec §9, W5, M9, X1). Mutants for mutants.py."""

D = "script/DeployBase.sol"
F = "test/ua/UADeploy.t.sol"

M = [
    ("walk-addresses-only", D, "p == vm.parseJsonAddress(book, a) && p.codehash == vm.parseJsonBytes32(book, h)",
     "p == vm.parseJsonAddress(book, a)", F, "test_deploy_walkMismatch_codeHash"),
    ("pqz-omitted-silently", D, '''                require(
                    _ownerOverride(book, "GEN_PQZ_OMITTED"),''', '''                require(
                    true,''', F, "test_deploy_omits0142_GEN_PQZ_OMITTED"),
    ("tx-cap-default-2-24", D, 'uint64 cap = uint64(_bookUint(book, ".tx_gas_cap", 0));',
     'uint64 cap = uint64(_bookUint(book, ".tx_gas_cap", 1 << 24));', F, "test_deploy_txGasCap_fromProbe"),
]
