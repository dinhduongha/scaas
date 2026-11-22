# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""P6h (3) mutants, ua-rs side (CLI-SGN-55: Wallet::seal_pq_key, PqzKey::open_leaf, pqz_leaf_label), each killed by
tests/pqz_leaf.rs (default features, through scripts/capped):
python3 runs/2026-11-22-p6h-sealpq-rs-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

F = "clients/ua-rs/src/facade/pqz.rs"
W = "clients/ua-rs/src/wallet/mod.rs"
T = "cd clients/ua-rs && CAPPED_SLOTS=4 CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked -j 2 --test pqz_leaf"
MUTANTS = [
    (
        "open_leaf takes another leaf's label",
        [(F, "            if vault.label() != pqz_leaf_label(account, index, version) {", "            if false {")],
        T,
        "pqz_leaf_json_refusals",
    ),
    (
        "open_leaf keeps each refusal's own class",
        [(F, "        open().map_err(|_| Error::VaultOpen)", "        open()")],
        T,
        "pqz_leaf_json_refusals",
    ),
    (
        "the label names no key version",
        [(F, '    format!("pqz:registry:{account}:{index}:{version}")', '    format!("pqz:registry:{account}:{index}")')],
        T,
        "leaf_label_is_clientkeys",
    ),
    (
        "seal_pq_key seals version 0's label",
        [(W, "            &crate::facade::pqz::pqz_leaf_label(account, index, version),", "            &crate::facade::pqz::pqz_leaf_label(account, index, 0),")],
        T,
        "seal_pq_key_round_trip",
    ),
    (
        "seal_pq_key seals under a fresh vault id",
        [(W, "        Vault::seal(\n            &self.vault_id()?,", "        Vault::seal(\n            &vault::new_vault_id()?,")],
        T,
        "seal_pq_key_round_trip",
    ),
]

if __name__ == "__main__":
    main("rs", MUTANTS, prefix="2026-11-22-p6h-sealpq")
