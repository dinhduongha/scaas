# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""PqChat TreeKEM: the split of a batch of Adds over the per-transaction cap (owner 2026-11-27, CTR-CHAT-27): the margin and
the split, each killed by the SDK's named test (through scripts/capped, on scripts/mutant_guard.py via runs/mutants_lib.py,
ARCH-POS-23).
python3 runs/2026-11-27-pqchat-treekem-split-mutants.py check | run [name...]"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from mutants_lib import main

S = "clients/scaas-sdk/src/pqchat_tree.rs"
SDK = ("cd clients/scaas-sdk && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j 2 "
       "--features pqchat-records,vectors --lib a_batch_of_adds_over_the_cap_is_split")
MUTANTS = [
    ("the split's margin dropped",
     [(S, "        tx_regular: l.tx_regular.map(|c| c - c / SPLIT_MARGIN_DIV),", "        tx_regular: l.tx_regular,")],
     SDK, "a_batch_of_adds_over_the_cap_is_split"),
    ("no split: the whole batch in one commit",
     [(S, "    let mut out = vec![per; (s.adds / per) as usize];", "    let mut out = vec![s.adds; 1];")],
     SDK, "a_batch_of_adds_over_the_cap_is_split"),
]

if __name__ == "__main__":
    main("split", MUTANTS, prefix="2026-11-27-pqchat-treekem")
