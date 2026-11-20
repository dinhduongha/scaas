# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Task 21: fixes of the Fable review (scratchpad report 20261120-fable-review.md). Mutants for mutants.py."""

R = "src/ua/UARegistryRegLib.sol"
V = "test/ua/UARegistryVerifyOnly.t.sol"
D = "script/DeployBase.sol"
F = "test/ua/UADeploy.t.sol"

M = [
    ("p2-1-inner-at-vo-cap", R, "                here ? mode | INNER : mode | INNER | WRITE,", "                mode | INNER,", V,
     "test_innerMsig_heldElsewhere_boundAtHolderPath"),
    ("p2-2-no-newer-book-check", D, "            !_newerGenBook(_bookUint(book, \".ua_registry_generation\", 1) + 1) ||",
     "            true ||", F, "test_deploy_newerGenBook_GEN_NOT_LATEST"),
    ("p2-3-unbound-accepted", D, "            c.verifier == _voCreate2(c.kind, c.keyForm, callGas),", "            true,", F,
     "test_deploy_voUnbound_named"),
    ("p2-3-no-differential", D, "                vm.keyExistsJson(book, string.concat(e, \".differential\"))\n",
     "                true || vm.keyExistsJson(book, string.concat(e, \".differential\"))\n", F, "test_deploy_voDifferentialMissing_named"),
    ("p2-4-cap-unchecked", D, "            c.cap >= 2 * callGas + VO_VERIFIER_OVERHEAD,", "            c.cap >= 0,", F,
     "test_deploy_voCapBelowCallGas_named"),
    ("p3-5-lineReaches-unpinned", "test/ua/RegistryWalkInterface.t.sol", "            \"lineReaches(address)(bool)\"\n",
     "            \"lineReaches(address)(uint256)\"\n", "test/ua/RegistryWalkInterface.t.sol",
     "test_walkInterface_signaturesSelectorsAndHash"),
]
