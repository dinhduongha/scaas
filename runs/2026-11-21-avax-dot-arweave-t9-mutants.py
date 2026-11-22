# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Plan T9 mutants (the node's PqChatStore row): python3 runs/2026-11-21-avax-dot-arweave-t9-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

G = "scaas-node/src/guard.rs"
T = "cd scaas-node && CAPPED_MEM=6G ../scripts/capped cargo test --locked --offline -j2 --lib a_pqchatstore_job"
NAME = "guard::tests::a_pqchatstore_job_runs_on_the_pinned_code_under_the_lane_policy"
MUTANTS = [
    ("the code-hash check skipped", [(G, "        if h != self.chatstore_code_hash {", "        if false {")], T, NAME),
    (
        "the default policy relaying unpaid writes",
        [(G, '(contract == "pqchat" || rule == Rule::ChatStore)', 'contract == "pqchat"')],
        T,
        NAME,
    ),
    (
        "the pinned hash not the release data's",
        [(G, 'r["runtimeCodeHash"]', 'r["initCodeHash"]')],
        T,
        NAME,
    ),
]

if __name__ == "__main__":
    main("t9", MUTANTS)
