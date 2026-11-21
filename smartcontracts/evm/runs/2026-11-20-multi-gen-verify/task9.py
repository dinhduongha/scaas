# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Task 9: ML-DSA verify-only verifiers (spec §2, §5, §9, M7). Mutants for runs/2026-11-20-multi-gen-verify/mutants.py."""

V = "src/ua/MlDsaVerifyOnly.sol"
T = "test/ua/MlDsaVerifyOnly.t.sol"

M = [
    ("no-alive-check", V, "        if (_answer(pc, SSTORE2.readChunks(_valid), g) == 1) return false; // alive: the input was invalid\n", "",
     T, "testFuzz_noPqNoAnswer_onWorkingStandIn"),
    ("no-explicit-gas-limit", V, "            let ok := staticcall(g, at, add(input, 0x20), mload(input), 0, 0x20)",
     "            let ok := staticcall(gas(), at, add(input, 0x20), mload(input), 0, 0x20)", T, "test_burnAll_aliveCheckKeepsGas"),
    ("edge-row-dropped", V, "        for (uint256 i; i < invalid.length; ++i) {\n            if (_answer(pc, invalid[i], g) != 0) return false;",
     "        for (uint256 i = 1; i < invalid.length; ++i) {\n            if (_answer(pc, invalid[i], g) != 0) return false;", T,
     "test_probe_edgeRowWrong_precompileZero"),
    ("lengths-not-first", V,
     "        if (keyData.length != P.pkLen || sig.length != P.sigLen) return false; // the holder's split\n", "", T,
     "test_malformed_answersZero"),
]
