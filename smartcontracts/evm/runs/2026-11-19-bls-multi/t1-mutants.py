#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""bls-multi Task 1 mutants (ua-rs key data and verification, 0x0121). From the worktree root: python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

RS = "clients/ua-rs"
BM = RS + "/src/bls_multi.rs"
T = [os.path.abspath("scripts/capped"), "cargo", "test", "--locked", "--offline", "--features", "vectors", "--test", "bls_multi"]
M = [(n, f, a, b, T, RS, e) for n, f, a, b, e in [
    ("verify under 0x0106's DST_SIG", BM, "    let h = hash_to_g1_bls12381(&m, DST_MULTI_SIG);",
     "    let h = hash_to_g1_bls12381(&m, crate::verify::BLS12381_DST_SIG);", "dsts_separate"),
    ("DST_MULTI_POP equal to DST_MULTI_SIG", BM, 'b"SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_MULTI_POP_"',
     'b"SCAAS-UA-V1_BLS12381G1_XMD:SHA-256_SSWU_RO_MULTI_SIG_"', "dsts_separate"),
    ("no memberDigest", BM, "    let m = keccak(&[&ua_of(d), ua_msg]);\n", "    let m = *ua_msg;\n", "cross_group"),
    ("min over all members", BM, "        min = min.min(w);\n    }", "    }\n    for m in &kd.members {\n        min = min.min(u32::from(m.1));\n    }",
     "minimal_rows"),
    ("weight >= t as > t", BM, "    if w < t || (minimal_form", "    if w <= t || (minimal_form", "verify_paths"),
    ("no high-bit check (bits at or above n ignored)", BM, "            if i >= n {\n                return None;\n            }",
     "            if i >= n {\n                continue;\n            }", "verify_paths"),
    ("no identity check on apk(S)", BM, "    if apk_s.is_zero() {\n        return false;\n    }\n", "", "EQUIVALENT"),
    ("a w_i <= t bound added", BM, '        need(w >= 1, "weight")?;\n', '        need(w >= 1 && w <= u32::from(u16_at(d, 256).unwrap() as u16), "weight")?;\n',
     "key_data_valid_rows"),
    ("u16 weight sum in validation", BM, "        total += w;\n", "        total = (total + w) & 0xffff;\n", "weight_sum_wide"),
    ("u16 weight sum in verify", BM, "        sum += w;\n        min", "        sum = (sum + w) & 0xffff;\n        min", "weight_sum_wide"),
    ("negation maps 0 to p_381", BM, "        if y.iter().all(|x| *x == 0) {\n            continue; // fneg(0) = 0\n        }\n", "",
     "subtract_cancelling_pair"),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
