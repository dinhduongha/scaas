# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Task 3: the one walk, the forwarding readers, the refusals, the probes. Mutants for runs/2026-11-20-multi-gen-verify/mutants.py."""

REG = "src/ua/UARegistry.sol"
CORE = "src/ua/UARegistryCoreLib.sol"
REGLIB = "src/ua/UARegistryRegLib.sol"
LINE = "test/ua/UARegistryLine.t.sol"

M = [
    (
        "pqzHome-newest",
        CORE,
        "if (h != address(0) && home == address(0) && pqz) home = address(this);",
        "if (h != address(0) && pqz) home = address(this);",
        LINE,
        "test_holderOf_pqzHome_thirdWord",
    ),
    (
        "pqzHomeOf-second-walk",
        CORE,
        "    function pqzHomeOf(bytes32 ua) external returns (address home) {\n        (,, home) = _holderOf(ua);",
        "    function pqzHomeOf(bytes32 ua) external returns (address home) {\n        (,, home) = _holderOf(ua);\n"
        "        address p = _pred();\n        if (p != address(0)) IUARegistry(p).pqzHomeOf(ua);",
        LINE,
        "test_holderOf_oneCallPerGeneration",
    ),
    (
        "nativeSpace-shortcut-removed",
        REG,
        "        if (UAKinds.inNativeSpace(ua)) return (address(0), 0, address(0));\n",
        "",
        LINE,
        "test_nativeSpace_noWalk_noStore",
    ),
    (
        "step1-verifyOnly-after-disabled",
        REGLIB,
        "        if (cfg >> 224 & 1 != 0) revert IUARegistry.UAVerifyOnly(kind);\n        revert IUARegistry.UAKindDisabled(kind);",
        "        revert IUARegistry.UAKindDisabled(kind);",
        LINE,
        "test_register_verifyOnly_UAVerifyOnly",
    ),
    (
        "identify-walks",
        REGLIB,
        "if (structure ? UARegistryCoreLib._kindOf(ua) != 0 : UAStore.layout().records[ua].kind != 0) {",
        "if (UARegistryCoreLib._kindOf(ua) != 0) {",
        LINE,
        "test_identify_singleKey_noWalk",
    ),
    (
        "readers-via-predecessor",
        REG,
        "        if (h != address(0)) return IUARegistry(h).msigOf(ua);",
        "        if (h != address(0)) return IUARegistry(predecessor).msigOf(ua);",
        LINE,
        "test_readers_forwardByHolder",
    ),
    (
        "cache-verifyOnly-not-refused",
        "src/ua/UARegistryAuxLib.sol",
        "        if (cfg >> 224 & 1 != 0) revert IUARegistry.UAVerifyOnly(kind); // §3: the cache is filled in the holding generation\n",
        "",
        LINE,
        "test_cacheExpandedKey_verifyOnly_UAVerifyOnly",
    ),
]
