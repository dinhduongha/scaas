# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Task 14: the Draft precompile probe flag (spec §9 CTR-UA-69, owner R9, C5). Mutants for mutants.py."""

D = "script/DeployBase.sol"
F = "test/ua/UADeploy.t.sol"

M = [
    ("draft-first-again", D, """        c = new address[](draft ? 2 : 1);
        c[0] = address(uint160(0x5caa0012 + i));
        if (draft) c[1] = address(uint160(0x12 + i));""", """        c = new address[](draft ? 2 : 2);
        c[0] = address(uint160(0x12 + i));
        c[1] = address(uint160(0x5caa0012 + i));""", F, "test_candidates_default_noDraft"),
    ("no-fuller-probe", D, "            if (c[j] == address(uint160(0x12 + i))) {", "            if (c[j] == address(0)) {", F,
     "test_candidates_flag_fullerProbe"),
]
