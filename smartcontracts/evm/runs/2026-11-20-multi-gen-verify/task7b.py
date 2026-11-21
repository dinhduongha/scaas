# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Task 7, part 2: the hard bound by txGasCap (P9), the PQZ debit at the fallback worst (M2), the constructor's M10 (d) check.
Mutants for runs/2026-11-20-multi-gen-verify/mutants.py (usage: `mutants.py 7b`)."""

REGLIB = "src/ua/UARegistryRegLib.sol"
REG = "src/ua/UARegistry.sol"
B = "test/ua/UARegistryHardBound.t.sol"

M = [
    ("sum-not-max", REGLIB, "        return (c > wr ? c : wr) <= _txGasCap();", "        return c + wr <= _txGasCap();", B,
     "test_bound_isMaxNotSum"),
    ("write-update-constants-only", REGLIB, "        if (pq && wr < PQZ_KEY_WRITE_GAS) wr = PQZ_KEY_WRITE_GAS;\n", "", B,
     "test_writeMode_dearestOfThree"),
    ("debit-write-mode-w", REGLIB,
     "        (uint256 fb,) = _worstHeld(d, LENIENT | FALLBACK, gen1 ? UAStore.SMART_KEY_1271_GAS : _nativeCap());",
     "        (uint256 fb,) = _worstHeld(d, LENIENT | WRITE, gen1 ? UAStore.SMART_KEY_1271_GAS : _nativeCap());", B,
     "test_msigDebit_wIsFallbackWorst"),
    ("consumer-reserve-dropped", REGLIB, "        uint256 c = _calldata(fb, a) + 21_000 + UA_CONSUMER_RESERVE_GAS;",
     "        uint256 c = _calldata(fb, a) + 21_000;", B, "test_bound_consumerModeBinds"),
    ("m10d-home-numbers", REGLIB,
     "            vc + hops * LINE_HOP_GAS + VO_READ_GAS + hc + hc / 63 + SigCheck.GAS_MARGIN,",
     "            hc,", B, "test_constructor_verifyOnlyFallback_overDebitBound_UAConfig"),
    ("m10d-skipped", REG, "        if (predecessor_ != address(0) && (k[18] != 0 ||",
     "        if (false && predecessor_ != address(0) && (k[18] != 0 ||", B,
     "test_constructor_verifyOnlyFallback_overDebitBound_UAConfig"),
    ("modes-never-split", REGLIB, "        if (!vo) return (w, w);", "        return (w, w);", B, "test_writeMode_dearestOfThree"),
    ("fallback-without-holder", REGLIB, "(mode & FALLBACK != 0 ? hc : 0)", "0", B, "test_bound_consumerModeBinds"),
    ("registration-hard-dropped", REGLIB, "                revert IUARegistry.UAKeyData(UAKinds.MSIG); // owner P9", "", B,
     "test_mldsa87x2_t2_registration_UAKeyData0120"),
    ("update-hard-dropped", REGLIB,
     "        if (!_hard(t, fb, ww, a, pq)) revert IUARegistry.UAMsigSlots(UAStore.u16(t, 2)); // owner P9", "", B,
     "test_updateMsig_toOverBound_UAMsigSlots"),
]
