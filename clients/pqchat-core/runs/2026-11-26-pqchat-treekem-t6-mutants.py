# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""PqChat TreeKEM T6 mutants (the crate's tree mode), each killed by its named test of `pqchat-core`'s `tests/tree_scenarios.rs`
(feature vectors, through scripts/capped, on scripts/mutant_guard.py via runs/mutants_lib.py, ARCH-POS-23):
python3 clients/pqchat-core/runs/2026-11-26-pqchat-treekem-t6-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "runs"))
from mutants_lib import main

T = "clients/pqchat-core/src/tree.rs"
S = "clients/scaas-sdk/src/pqchat_tree.rs"
CMD = ("cd clients/pqchat-core && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked -j 4 --features vectors "
       "--test tree_scenarios")
MUTANTS = [
    ("the majority read made only when an info changed (a read that depends on a decryption)",
     [(T, "        if !new_epochs.is_empty() {\n",
       "        if new_epochs.iter().any(|e| e.info.as_deref() == Some(\"changed\")) {\n")],
     CMD, "a_failed_open_reads_as_a_followed_one"),
    ("a changed info taken with 2 named endpoints",
     [(T, ".filter(|(_, named)| *named >= 3)", ".filter(|(_, named)| *named >= 2)")],
     CMD, "a_changed_info_needs_the_majority"),
    ("a changed info taken on a majority that names another head",
     [(T, ".is_some_and(|h| Some(h) == ids.last().map(|x| x.to_ascii_lowercase()));", ".is_some();")],
     CMD, "a_changed_info_needs_the_majority"),
    ("the snapshot not compared with the tree read at its end",
     [(T, "if same_head(&first, &again) {", "if true || same_head(&first, &again) {")],
     CMD, "one_snapshot_per_state"),
    ("an admin's new info after a gap sealed unreviewed",
     [(T, "(Some(_), None) if !c.info_reviewed => return Err(PqChatError::TreeInfoReview),", "")],
     CMD, "an_info_after_a_gap_needs_its_review"),
    ("the registry's KEM key read without its kept signature",
     [(S, '"sig": s(at(v, "sig"))?', '"sig": "0x"')], CMD, "recovery_every_scenario_device"),
    ("a view read from another session (the session id dropped)",
     [(T, '"sessionOf" => {\n                let r = self\n                    .home_read(s, "IPqChat.sessionOf", json!({ "sessionId": sid }))',
       '"sessionOf" => {\n                let r = self\n                    .home_read(s, "IPqChat.sessionOf", json!({ "sessionId": crate::model::ZERO32 }))')],
     CMD, "recovery_every_scenario_device"),
]

if __name__ == "__main__":
    main("t6", MUTANTS, prefix="2026-11-26-pqchat-treekem")
