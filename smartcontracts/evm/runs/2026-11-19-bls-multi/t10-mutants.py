#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""bls-multi Task 10 mutants (scaas-node 0x0121 rows). From the worktree root: python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

NODE = "scaas-node"
TY = NODE + "/src/typed.rs"
T = [os.path.abspath("scripts/capped"), "cargo", "test", "--locked", "--lib", "--", "typed::tests::bls_multi",
     "typed::tests::typed_register_bls_multi_row"]
M = [(n, f, a, b, T, NODE, e) for n, f, a, b, e in [
    ("signers not strictly increasing (duplicates pass)", TY, "if last.is_some_and(|l| l >= i) {", "if last.is_some_and(|l| l > i) {",
     "bls_multi_signers_refusals"),
    ("no index bound below 64", TY, "            .filter(|i| *i < BLS_MULTI_MAX as u64)\n", "",
     "bls_multi_signers_refusals"),
    ("no 64-entry bound on signers", TY, "    if a.is_empty() || a.len() > BLS_MULTI_MAX {", "    if a.is_empty() {",
     "bls_multi_signers_refusals"),
    ("the packed 160 bytes taken as a length error", TY, "    if sig.len() == 160 {\n", "    if sig.len() == 161 {\n",
     "bls_multi_hex_blob_refused"),
    ("other UASig fields allowed beside signers", TY,
     "    if let Some(k) = o.keys().find(|k| *k != \"signers\" && *k != \"signature\") {",
     "    if let Some(k) = o.keys().find(|k| *k == \"never\") {", "bls_multi_hex_blob_refused"),
    ("no 64-member bound on BlsMultiMember[]", TY, "        if el == \"BlsMultiMember\" && a.len() > BLS_MULTI_MAX {",
     "        if el == \"BlsMultiMember\" && a.len() > 65 {", "typed_register_bls_multi_row"),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
