# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Task 5: the consumer path (§4). Mutants for runs/2026-11-20-multi-gen-verify/mutants.py."""

REG = "src/ua/UARegistry.sol"
CORE = "src/ua/UARegistryCoreLib.sol"
V = "test/ua/UARegistryVerifyOnly.t.sol"

M = [
    (
        "handoff-to-predecessor",
        REG,
        "            else if (!UAStore.via(h, ua, purposeTag, digest, auth)) revert UAUnauthorized(ua);",
        "            else if (!UAStore.via(predecessor, ua, purposeTag, digest, auth)) revert UAUnauthorized(ua);",
        V,
        "test_kindNotCarried_goesToHolderDirectly",
    ),
    (
        "verifyOnly-branch-for-not-carried",
        REG,
        "            if (_vo(k)) h = address(0);",
        "            h = address(0);",
        V,
        "test_kindNotCarried_goesToHolderDirectly",
    ),
    (
        "registered-kind-to-library (msig held elsewhere)",
        REG,
        "            if (_vo(k)) _libView(",
        "            if (_cfg(k) != 0) _libView(",
        V,
        "test_predecessorMsig_forwardedWhole",
    ),
    (
        "portableApp-via-requirePortable",
        REG,
        "if (h != address(0)) IUARegistry(h).requirePortableApp(ua, appId, typedDigest, auth);",
        "if (h != address(0)) IUARegistry(h).requirePortable(ua, UAKinds.appPurpose(appId), typedDigest, auth);",
        V,
        "test_kindNotCarried_goesToHolderDirectly",
    ),
    (
        "member-handoff-to-predecessor",
        REG,
        "cfg >> 224 & 1 != 0 ? address(this) : h, id, purposeTag",
        "cfg >> 224 & 1 != 0 ? address(this) : predecessor, id, purposeTag",
        V,
        "test_kindNotCarried_member_goesToHolderDirectly",
    ),
    (
        "member-kind-read-locally",
        CORE,
        "|| !_voCheck(h, ua, k, purposeTag, digest, auth.keyData, auth.signature)",
        "|| !_voCheck(h, ua, UAStore.layout().records[ua].kind, purposeTag, digest, auth.keyData, auth.signature)",
        V,
        "test_memberKind_fromHolderOf",
    ),
    (
        "keyForm1-cache-ignored",
        CORE,
        "            if (cfg >> 225 & 1 != 0) {\n                (keyData, sel) = (UAStore.cacheAt(h, id, kind), MldsaVerifier.verifyCached.selector);",
        "            if (false) {\n                (keyData, sel) = (UAStore.cacheAt(h, id, kind), MldsaVerifier.verifyCached.selector);",
        V,
        "test_keyForm1_incompleteCache_UAKeyNotCached",
    ),
    (
        "failed-read-as-refusal",
        "src/ua/UAStore.sol",
        "        if (!ok) revert UAKinds.UAVerifyGas();\n    }\n\n    /// The registration key data",
        "        if (!ok) revert IUARegistry.UAUnauthorized(0);\n    }\n\n    /// The registration key data",
        V,
        "test_failedRead_UAVerifyGas",
    ),
]
