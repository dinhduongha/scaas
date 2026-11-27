# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""PqChat TreeKEM T5 mutants (the SDK's tree plan and the registry's KEM view), each killed by its named test of
`scaas-sdk` (`pqchat_tree::tests`, through scripts/capped, on scripts/mutant_guard.py via runs/mutants_lib.py, ARCH-POS-23):
python3 clients/scaas-sdk/runs/2026-11-26-pqchat-treekem-t5-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "runs"))
from mutants_lib import main

T = "clients/scaas-sdk/src/pqchat_tree.rs"
CMD = ("cd clients/scaas-sdk && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked -j 2 "
       "--features pqchat-records --offline --lib pqchat_tree")
MUTANTS = [
    ("a chunk plan that exceeds the block-limit rule",
     [(T, "            if l.fits(gas(mid)) {", "            if true {")],
     CMD, "a_20m_block_takes_a_plain_commit_and_refuses_the_bound_record"),
    ("every ciphertext released before the node keys are final",
     [(T, "        if !plan.txs.iter().filter(|x| serial(x)).all(|x| is_in(fin, x)) {", "        if false {")],
     CMD, "the_order_broken_and_its_controls"),
    ("a refusal by a protocol-wide constant (60 M), not the chain's block",
     [(T, "g.asked() <= self.block", "g.asked() <= 60_000_000")],
     CMD, "a_20m_block_takes_a_plain_commit_and_refuses_the_bound_record"),
    ("the decoder that drops the signature again",
     [(T, '"sig": hex(&r.sig)', '"sig": "0x"')], CMD, "the_kem_view_keeps_the_signature"),
    ("the order broken taken as complete",
     [(T, "        if !l.fits(one.add(completion)) {", "        if false {")], CMD, "the_order_broken_and_its_controls"),
    # B-7 of the T4-T9 review
    ("the 2^24 rule unpinned",
     [(T, "self.tx_regular.is_none_or(|c| g.regular <= c) && ", "")], CMD, "the_regular_cap_binds_by_itself"),
    ("asked() without the 5 %",
     [(T, "        t.saturating_add(t.div_ceil(20))", "        t")], CMD, "the_margin_decides"),
    ("the held piece sent before every chunk is final",
     [(T, "    if (serial(t) || last_left) && !all_final(first) {", "    if serial(t) && !all_final(first) {")],
     CMD, "the_held_piece_waits_for_every_chunk_to_be_final"),
    ("B-1 a commit with no piece sized as record plus completion",
     [(T, "    if s.cts == 0 && s.adds == 0 {\n        // B-1", "    if false {\n        // B-1")],
     CMD, "the_last_live_leafs_commit_plans_as_measured"),
    ("B-2 the record's tree term at the worst tree",
     [(T, "    Ok(g.record\n        .at(s.cts)", "    Ok(g.record\n        .at(511)")],
     CMD, "a_20m_block_takes_a_plain_commit_and_refuses_the_bound_record"),
    ("B-9 chunks halved, not the most that fit",
     [(T, "        let (mut lo, mut hi) = (0, n - first);", "        let (mut lo, mut hi) = (0, (n - first).min(8));")],
     CMD, "a_chunk_holds_the_most_that_fit"),
    ("B-8 a chunk left last sent whole",
     [(T, "    let end = if broken && last_left && a < z {", "    let end = if false {")],
     CMD, "a_chunk_left_last_goes_but_one"),
    ("C-1 the one-transaction fallback to the pieces dropped",
     [(T, "        return match pieces(g, l, s, PqGas::default()) {", "        return match Err::<PqTreePlan, _>(refused(\"x\", PqGas::default(), l)) {")],
     CMD, "a_record_stored_alone_is_not_complete"),
]

if __name__ == "__main__":
    main("t5", MUTANTS, prefix="2026-11-26-pqchat-treekem")
