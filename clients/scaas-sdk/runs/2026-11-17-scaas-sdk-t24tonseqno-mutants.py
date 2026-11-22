# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""rpc T24.ton-seqno: TON getters and the account read at one masterchain seqno, the stack and the bounded BoC reader:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t24tonseqno-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

R = "clients/scaas-rpc/src/ton.rs"
B = "clients/scaas-rpc/src/boc.rs"
T = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --features ton --test ton_seqno -- --exact "
MUTANTS = [
    ("an answer of another seqno read",
     [(R, "        || b.and_then(|b| b.get(\"seqno\")).and_then(Value::as_u64) != Some(seqno)\n", "")],
     T + "a_getter_answer_of_another_block_is_malformed"),
    ("a block of another workchain read",
     [(R, "    if b.and_then(|b| b.get(\"workchain\")).and_then(Value::as_i64) != Some(-1)\n        ||",
       "    if")],
     T + "a_getter_answer_of_another_block_is_malformed"),
    ("an answer not ok read",
     [(R, "    if v.get(\"ok\") != Some(&Value::Bool(true)) {", "    if false {")],
     T + "a_getter_answer_of_another_block_is_malformed"),
    ("the getter asked without the seqno",
     [(R, "\"stack\": args, \"seqno\": seqno});", "\"stack\": args});")],
     T + "a_getter_is_asked_at_the_seqno_and_its_cell_read"),
    ("a stack number of 66 hex digits read",
     [(R, "if (1..=65).contains(&h.len()) &&", "if (1..=66).contains(&h.len()) &&")],
     T + "a_stack_entry_out_of_form_is_malformed"),
    ("a stack number not hex read",
     [(R, "if (1..=65).contains(&h.len()) && h.bytes().all(|b| b.is_ascii_hexdigit()) =>",
       "if (1..=65).contains(&h.len()) =>")],
     T + "a_stack_entry_out_of_form_is_malformed"),
    ("a negative number read as a u128",
     [(R, "StackEntry::Num(s) => u128::from_str_radix(s.strip_prefix(\"0x\")?, 16).ok(),",
       "StackEntry::Num(s) => u128::from_str_radix(s.trim_start_matches('-').strip_prefix(\"0x\")?, 16).ok(),")],
     T + "a_stack_entry_out_of_form_is_malformed"),
    ("a balance of any text read",
     [(R, ".filter(|s| (1..=78).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit()))", "")],
     T + "an_account_answer_out_of_form_is_malformed"),
    ("a BoC of depth 1025 read",
     [(B, "        if depth > DEPTH_MAX {", "        if depth > DEPTH_MAX + 1 {")],
     T + "a_boc_deeper_than_1024_is_refused"),
    ("a BoC of 4097 cells read",
     [(B, "pub const CELLS_MAX: usize = 4096;", "pub const CELLS_MAX: usize = 4097;")],
     T + "a_boc_out_of_bounds_is_refused"),
    ("bytes after the BoC read",
     [(B, "    if p != b.len() {", "    if false {")],
     T + "a_boc_out_of_bounds_is_refused"),
    ("the cells size field not compared",
     [(B, "    if used != total {", "    if false {")],
     T + "a_boc_out_of_bounds_is_refused"),
    ("a reference to an unbuilt cell read as a leaf",
     [(B, "            let (c, d) = built[r]\n                .clone()\n                .ok_or(\"a BoC reference to an earlier cell\")?;",
       "            let (c, d) = built[r].clone().unwrap_or((\n                Arc::new(Cell { data: vec![], bits: 0, refs: vec![], exotic: false }),\n                0,\n            ));")],
     T + "a_boc_out_of_bounds_is_refused"),
    ("a fifth reference read",
     [(B, "        if n > 4 {", "        if n > 5 {")],
     T + "a_boc_out_of_bounds_is_refused"),
    ("a cell with a level read",
     [(B, "        if d1 & 0xf0 != 0 {", "        if d1 & 0xd0 != 0 {")],
     T + "a_boc_out_of_bounds_is_refused"),
    ("a padded byte without its tag read",
     [(B, "            if *last == 0 {", "            if false {")],
     T + "a_cells_bits_follow_the_completion_tag"),
    ("an anycast address read as addr_std",
     [(B, "c.byte_at(0, 3) != 0b100", "c.byte_at(0, 2) != 0b10")],
     T + "std_addresses_round_trip_and_nothing_else_is_one"),
    ("a cell with a reference read as an address",
     [(B, "    if c.bits != 267 || !c.refs.is_empty() ||", "    if c.bits != 267 ||")],
     T + "std_addresses_round_trip_and_nothing_else_is_one"),
    ("a workchain other than 0 and -1 read",
     [(R, "        \"-1\" => -1,\n        _ => return None,", "        \"-1\" => -1,\n        w => w.parse().ok()?,")],
     T + "raw_addresses"),
]

if __name__ == "__main__":
    main("t24tonseqno", MUTANTS)
