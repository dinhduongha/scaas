# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""PqChat TreeKEM T8 mutants, node side: the tree commit job at the submit level on a fake chain (C37: the record alone
when the whole does not fit, the held piece last and alone, `consumed` once every piece is in state), each killed by
`scaas-node`'s `a_tree_commit_job_lands_in_c37_order_on_a_fake_chain` (lib, through scripts/capped, on
scripts/mutant_guard.py via runs/mutants_lib.py, ARCH-POS-23):
python3 runs/2026-11-26-pqchat-treekem-t8-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

S = "scaas-node/src/submit.rs"
CMD = ("cd scaas-node && CARGO_INCREMENTAL=0 ../scripts/capped cargo test --locked -j 2 --lib "
       "a_tree_commit_job_lands_in_c37_order_on_a_fake_chain")
TEST = "a_tree_commit_job_lands_in_c37_order_on_a_fake_chain"
MUTANTS = [
    ("the whole set sent again where the record alone goes first",
     [(S, 'self.tree_part(&w, "commit", ts::record_alone(&s))', 'self.tree_part(&w, "commit", s.args.clone())')],
     CMD, TEST),
    ("the held piece's job replaced by the whole commit",
     [(S, "self.dispatch(last, guard, g, None).await;", "self.dispatch(w.clone(), guard, g, None).await;")],
     CMD, TEST),
    ("a set too big for one transaction refused, not split",
     [(S, "                    Err(SimError::Revert(r)) if tree_over(&r) => {\n                        // D-12",
       "                    Err(SimError::Revert(r)) if false && tree_over(&r) => {\n                        // D-12")],
     CMD, TEST),
    ("A-1 a part another sender landed first taken as a refusal",
     [(S, "    .iter()\n    .any(|n| r.contains(n))\n}", "    .iter()\n    .any(|n| r.contains(n) && false)\n}")],
     CMD.replace("a_tree_commit_job_lands_in_c37_order_on_a_fake_chain", "a_part_another_sender_landed_first_is_no_verdict"),
     "a_part_another_sender_landed_first_is_no_verdict"),
    ("a complete set not reported consumed",
     [(S, '                if let Some(id) = w.job_id {\n                    let why = "TREE_SET_COMPLETE',
       '                if let Some(id) = w.job_id.filter(|_| false) {\n                    let why = "TREE_SET_COMPLETE')],
     CMD, TEST),
]

if __name__ == "__main__":
    main("t8", MUTANTS, prefix="2026-11-26-pqchat-treekem")
