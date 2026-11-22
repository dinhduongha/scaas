# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Native NEAR (owner 2026-11-22): a plain account's native balance through `view_account` on a profile without tokens:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-nearnative-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

S = "clients/scaas-sdk/src/wallet/families/near.rs"
T = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features near --test near -- --exact "
MUTANTS = [
    ("the native read off",
     [(S, "        Holder::Account(a) => Some(native(near, i, h, a).await?),", "        Holder::Account(_) => None,")],
     T + "near_native_plain_account"),
    ("the native read at the latest block, not the final one",
     [(S, '"view_account", "account_id": account, "block_id": h}', '"view_account", "account_id": account, "finality": "optimistic"}')],
     T + "near_native_plain_account"),
    ("an unknown plain account refused, not 0",
     [(S, '            if error.pointer("/cause/name").and_then(Value::as_str) == Some("UNKNOWN_ACCOUNT") =>',
       '            if false =>')],
     T + "near_native_plain_account"),
]

if __name__ == "__main__":
    main("nearnative", MUTANTS)
