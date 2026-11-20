#!/usr/bin/env python3
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""bls-multi Task 2 mutants (ua-rs PoP parts, partials, aggregation, builder). From the worktree root: python3 -I <this> [first last | check]"""
import importlib.util
import os

spec = importlib.util.spec_from_file_location("run", os.path.join(os.path.dirname(os.path.abspath(__file__)), "mutants-run.py"))
run = importlib.util.module_from_spec(spec)
spec.loader.exec_module(run)

RS = "clients/ua-rs"
BM = RS + "/src/bls_multi.rs"
T = [os.path.abspath("scripts/capped"), "cargo", "test", "--locked", "--offline", "--features", "vectors", "--test", "bls_multi", "--test", "wallet_sign"]
M = [(n, f, a, b, T, RS, e) for n, f, a, b, e in [
    ("m_i without pk_i", BM, "    keccak(&[pop_msg, pk])\n", "    *pop_msg\n", "pop_rogue_shared_message"),
    ("popMsg without d (m_i = keccak256(pk_i))", BM, "    keccak(&[pop_msg, pk])\n", "    keccak(&[pk])\n", "member_pop_for_other_group_named"),
    ("no per-partial check", BM, "        match partial_ok(s, &kd.members[idx].0, &m, DST_MULTI_SIG) {", "        match g1_valid(s) {",
     "aggregate_names_bad_partial"),
    ("weights not moved with keys in the builder", BM, "        d.extend_from_slice(&members[*i].1.to_be_bytes());",
     "        d.extend_from_slice(&members[pos].1.to_be_bytes());", "builder_order_and_index_map"),
    ("member_pop on a popMsg not derived from d", BM, "&pop_member_message(&pop_message(d)?, &kd.members[i].0)",
     "&pop_member_message(&[0u8; 32], &kd.members[i].0)", "member_pop_for_other_group_named"),
    ("aggregate defaults to surplus", BM, "    if !surplus {\n        ok.sort_by", "    if false {\n        ok.sort_by", "aggregate_default_minimal"),
]]
if __name__ == "__main__":
    raise SystemExit(run.main(M))
