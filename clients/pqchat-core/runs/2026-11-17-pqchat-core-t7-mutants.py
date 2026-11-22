# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""pqchat-core plan T7's mutants (stores: chain store, postMessage, the store list, spend consent), each killed by its own
named test through a fixture that reaches its check: python3 clients/pqchat-core/runs/2026-11-17-pqchat-core-t7-mutants.py
check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from pqc_mutants import main  # noqa: E402

ST = "clients/pqchat-core/src/stores.rs"
SE = "clients/pqchat-core/src/session.rs"
T = "cd clients/pqchat-core && ../../scripts/capped cargo test --locked --offline -j2 --test stores "
MUTANTS = [
    ("send to the first store only",
     [(ST, "        for (i, e, confirmed) in plan {", "        for (i, e, confirmed) in plan.into_iter().take(1) {")],
     T + "one_send_every_store_same_bytes"),
    ("send typing to a chain store",
     [(ST, "if !e.holds_messages() || (typing && !is_matrix(e)) {", "if !e.holds_messages() {")],
     T + "typing_to_the_room_only"),
    ("skip the spend consent",
     [(ST, "        if (post || targets.iter().any(|e| is_chain(e))) && !prefs.chain_spend {",
       "        if (post || targets.iter().any(|e| is_chain(e))) && false {")],
     T + "chain_cost_unconfirmed"),
    ("use a new store without confirmation",
     [(ST, "plan.push((i, e.clone(), prefs.confirmed.contains(e)));", "plan.push((i, e.clone(), true));")],
     T + "rekey_by_a_member_adds_an_unconfirmed_store"),
    ("accept a list with no message store",
     [(SE, "    if count(StoreEntry::holds_messages) == 0\n        ||", "    if false\n        ||")],
     T + "store_list_invalid"),
    ("sign before the store-list check",
     [(ST, "        check_stores(&info)?;\n", ""),
      (ST, "        let out = self.seal_under(&ep, me, &v).await?;\n",
       "        let out = self.seal_under(&ep, me, &v).await?;\n        check_stores(&info)?;\n")],
     T + "hcs_listed_refused_before_signing"),
]

if __name__ == "__main__":
    main("t7", MUTANTS)
