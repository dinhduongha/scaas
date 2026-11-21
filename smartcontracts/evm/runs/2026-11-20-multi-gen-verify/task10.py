# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Task 10: equivalence (spec §7). The per-row lax precompiles of §7 (d) are the suite's own rows
(test_equivalence_d_laxPerRow_caught); these mutants change the verify-only verifier. For mutants.py."""

V = "src/ua/MlDsaVerifyOnly.sol"
E = "test/ua/VerifyOnlyEquivalence.t.sol"

M = [
    ("no-pq-framing", V, "        return _call(abi.encodePacked(keyData, sig, PqUA.pqMessage(KIND_TAG, message)));",
     "        return _call(abi.encodePacked(keyData, sig, message));", E, "test_equivalence_a_kat_mldsa65"),
    ("form1-parts-unchecked", V, "        if (!ok) return false;\n        return _call(abi.encodePacked(ek, sig,",
     "        return _call(abi.encodePacked(ek, sig,", E, "test_cacheLayout_missingPart_noCall"),
]
