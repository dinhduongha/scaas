# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T5 mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t5-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

M = "clients/ua-rs/src/wallet/mod.rs"
S = "clients/scaas-sdk/src/vault/seeds.rs"
UA = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --test bip85 "
SDK = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --test children "
MUTANTS = [
    ("24' -> 12' in the path", [(M, "[83696968, 39, 0, 24, i]", "[83696968, 39, 0, 12, i]")], UA + "children_0_to_2_and_the_high_water_mark"),
    ("the index never raised (a lower one reused)", [(M, "            m.bip85_next = next;\n", "            let _ = next;\n")],
     SDK + "remove_then_derive_never_reuses"),
    ("drop the warning inheritance", [(S, "                    pe.warnings.clone(),\n", "                    vec![],\n")], SDK + "derive_child_is_the_rows_child_and_inherits"),
    ("HMAC key changed", [(M, 'new_from_slice(b"bip-entropy-from-k")', 'new_from_slice(b"bip-entropy-from-K")')],
     UA + "children_0_to_2_and_the_high_water_mark"),
]

if __name__ == "__main__":
    main("t5", MUTANTS)
