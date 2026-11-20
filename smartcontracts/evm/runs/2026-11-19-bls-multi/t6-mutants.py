#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""bls-multi Task 6 mutants (BlsMultiBls12381Verifier). From the worktree root: python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

EVM = "smartcontracts/evm"
V = EVM + "/src/ua/verifiers/BlsMultiBls12381Verifier.sol"
CS = EVM + "/src/common/CurveSigs.sol"
T = [os.path.abspath("scripts/capped"), "forge", "test", "--match-path", "test/ua/verifiers/BlsMultiVerifier.t.sol"]
M = [(n, f, a, b, T, EVM, e) for n, f, a, b, e in [
    ("no memberDigest", V, "abi.encodePacked(keccak256(abi.encodePacked(p[0:32], uaMsg)))", "abi.encodePacked(uaMsg)",
     "test_verify_rows"),
    ("DST_MULTI_SIG equal to 0x0106's DST_SIG", CS, '"SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_MULTI_SIG_"',
     '"SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_SIG_"', "test_dstsSeparate_sameInput"),
    ("PoP under DST_MULTI_SIG (equal DSTs)", V, "CurveSigs.DST_MULTI_POP\n", "CurveSigs.DST_MULTI_SIG\n", "test_pop_rows"),
    ("m_i without pk_i", V, "abi.encodePacked(keccak256(abi.encodePacked(popMsg, pk)))", "abi.encodePacked(popMsg)",
     "test_pop_rows"),
    ("verify body used for verifyMinimal", V, "_sig(keyData, message, sig, mode == Mode.Minimal)",
     "_sig(keyData, message, sig, false)", "test_verifyMinimal_rows"),
    ("no apk(S) != O check", V, "if (apkS.length == 0 || _zero(apkS) || _zero(sigma)) return false;",
     "if (apkS.length == 0 || _zero(sigma)) return false;", "EQUIVALENT"),
    ("no sigma != O check", V, "if (apkS.length == 0 || _zero(apkS) || _zero(sigma)) return false;",
     "if (apkS.length == 0 || _zero(apkS)) return false;", "EQUIVALENT"),
    ("neither identity check", V, "if (apkS.length == 0 || _zero(apkS) || _zero(sigma)) return false;",
     "if (apkS.length == 0) return false;", "test_identityPair_refused"),
    ("apk(S) loop off by one (last member never summed)", V,
     "            bool first = true;\n            for (uint256 i; i < n; ++i) {",
     "            bool first = true;\n            for (uint256 i; i + 1 < n; ++i) {", "test_apkPathBoundary"),
    ("verify reads the d form's length", V,
     "        uint256 n = uint16(bytes2(p[226:228]));\n        if (n < 2 || n > 64 || p.length != 228 + 194 * n) return false;",
     "        uint256 n = uint16(bytes2(p[258:260]));\n        if (n < 2 || n > 64 || p.length != 260 + 258 * n) return false;",
     "test_verify_refusesDAtN48"),
    ("verifyPop reads the p form's length", V,
     "        uint256 n = uint16(bytes2(d[258:260]));\n        if (n < 2 || n > 64 || d.length != 260 + 258 * n ||",
     "        uint256 n = uint16(bytes2(d[226:228]));\n        if (n < 2 || n > 64 || d.length != 228 + 194 * n ||",
     "test_verifyPop_refusesPAtN64"),
    ("negation maps 0 to p_381", V, "            if or(hi, lo) {\n", "            if 1 {\n", "test_subtract_cancellingPair"),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
