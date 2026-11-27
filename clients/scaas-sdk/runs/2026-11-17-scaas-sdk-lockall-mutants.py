# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk `lock_all` hidden-set mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-lockall-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

U = "clients/scaas-sdk/src/vault/unlock.rs"
SDK = "cd clients/scaas-sdk && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 --test vault "
MUTANTS = [
    ("lock_all locks the open seeds only (hidden sets' seeds dropped)",
     [(U, "        let mut ids: BTreeSet<String> = self\n", "        let ids: BTreeSet<String> = self\n"),
      (U, "        ids.extend(\n", "        let _ = (\n")],
     SDK + "lock_all_locks_hidden_sets_of_a_locked_seed"),
]

if __name__ == "__main__":
    main("lockall", MUTANTS)
