# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Task 2: kind word flags, constructor rules, the line. Mutants for runs/2026-11-20-multi-gen-verify/mutants.py. The N12 sites
`_verifierCall`, `_single` and `_notCached` via `_consent` read no flagged word before Tasks 4 / 5 (a record of a verify-only kind is
never held here, and its entries append the word of the record's kind, 0): their mutants run with Tasks 4 and 5."""

REG = "src/ua/UARegistry.sol"
CORE = "src/ua/UARegistryCoreLib.sol"
REGLIB = "src/ua/UARegistryRegLib.sol"
LINE = "test/ua/UARegistryLine.t.sol"

M = [
    (
        "identify-unmasked",
        REGLIB,
        "if (!UAStore._registrable(UARegistryCoreLib._cfgKind())) revert IUARegistry.UAKindDisabled(kind); // 1",
        "if (uint160(UARegistryCoreLib._cfgKind()) == 0) revert IUARegistry.UAKindDisabled(kind); // 1",
        LINE,
        "test_n12_flaggedWord_capAndRegistrable",
    ),
    (
        "kindHome-unmasked",
        CORE,
        "        if (UAStore._registrable(_cfgKind())) return address(this);\n        address p = _pred();",
        "        if (uint160(_cfgKind()) != 0) return address(this);\n        address p = _pred();",
        LINE,
        "test_n12_flaggedWord_capAndRegistrable",
    ),
    (
        "iff-rule-on-0142",
        REG,
        "        if (c.kind == UAKinds.PQZ_MLWE) return !c.verifyOnly && c.keyForm == 0;\n",
        "",
        LINE,
        "test_msigAnd0142_reenabled_notRefused",
    ),
    (
        "keyForm1-checks-predecessor",
        REG,
        "UAStore.noPrecompile(IUARegistry(home).verifierOf(c.kind))",
        "UAStore.noPrecompile(IUARegistry(pred).verifierOf(c.kind))",
        LINE,
        "test_keyForm1_throughMiddleVerifyOnly_readsHome",
    ),
    (
        "group-on-kindEnabled",
        REG,
        "&& keccak256(bytes(UAKinds.groupName(j))) == g && IUARegistry(pred).kindHome(j) != address(0)",
        "&& keccak256(bytes(UAKinds.groupName(j))) == g && IUARegistry(pred).kindEnabled(j)",
        LINE,
        "test_groupAcrossLine_UAConfig",
    ),
    (
        "no-precompile-check",
        REG,
        "if (!ok || pc == 0 || !ok2 || form != c.keyForm) return false;",
        "if (!ok2 || form != c.keyForm) return false;",
        LINE,
        "test_verifyOnly_noPrecompile_UAConfig",
    ),
    (
        "walk-no-generation-order",
        REG,
        "if (pg != expect || pg == 0 || pg >= MAX_GENERATION",
        "if (pg == 0 || pg >= MAX_GENERATION",
        LINE,
        "test_fakePredecessor_generationOutOfRange_UAConfig0",
    ),
]
