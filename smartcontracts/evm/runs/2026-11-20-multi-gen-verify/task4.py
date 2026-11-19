# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Task 4: writes are the holder's (W1, M1, N2). Mutants for runs/2026-11-20-multi-gen-verify/mutants.py; run after Task 5, whose
verify-only consumer path is what a write must never reach (before it, every record held elsewhere went to its holder anyway)."""

CORE = "src/ua/UARegistryCoreLib.sol"
W = "test/ua/UARegistryVerifyOnlyWrites.t.sol"
V = "test/ua/UARegistryVerifyOnly.t.sol"

M = [
    (
        "default-flipped-portableOk",
        CORE,
        "_sigOk(_cfgKind(), kind, d, ua, purpose, digest, sig.signature, sig.members, true);",
        "_sigOk(_cfgKind(), kind, d, ua, purpose, digest, sig.signature, sig.members, false);",
        W,
        "test_writes_acceptAll_setPqzKey_msigHeldHere",
    ),
    (
        "sigOk-msig-false (registration pop)",
        CORE,
        "_msig(ua, md, digest, purpose == UAKinds.PURPOSE_POP_V2, d, members, write);",
        "_msig(ua, md, digest, purpose == UAKinds.PURPOSE_POP_V2, d, members, false);",
        W,
        "test_writes_acceptAll_registrationPop_msigWithGen1Members",
    ),
    (
        "msigOk-false (updateMsig)",
        CORE,
        "        return _msig(ua, md, typed, false, d, sigs, true);",
        "        return _msig(ua, md, typed, false, d, sigs, false);",
        W,
        "test_writes_acceptAll_updateMsig",
    ),
    (
        "acceptMembership-false",
        CORE,
        "if (!_memberOk(d, md, typed, memberSig, 0, true))",
        "if (!_memberOk(d, md, typed, memberSig, 0, false))",
        W,
        "test_writes_acceptAll_acceptMembership",
    ),
    (
        "memberOk-write-via-this",
        CORE,
        "                write ? _at(id) : address(this),",
        "                address(this),",
        W,
        "test_writes_acceptAll_setPqzKey_msigHeldInPredecessor",
    ),
    (
        "inner-held-elsewhere-on-reader",
        CORE,
        "                    write || UAStore.layout().records[id].kind == 0",
        "                    write",
        V,
        "test_storedPath_innerMsig_heldElsewhere_holderVerifiers",
    ),
    (
        "single-uint160-test",
        CORE,
        "        if (!UAStore._registrable(cfg)) {\n            return UAStore.via(_at(ua)",
        "        if (uint160(cfg) == 0) {\n            return UAStore.via(_at(ua)",
        W,
        "test_writes_acceptAll_setPqzKey_singleKey",
    ),
]
