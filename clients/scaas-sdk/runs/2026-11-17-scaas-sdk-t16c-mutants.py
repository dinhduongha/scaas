# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Plan T16 part 3 (the controller calls P-T16-1..5 of 2026-11-19): python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t16c-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

P = "clients/ua-rs/src/wallet/policy.rs"
U = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --test sign_scaas "
MUTANTS = [
    ("P-T16-1: PqzAuth under metatx (the old mapping)",
     [(P, '        "PqzRollOver" | "PqzAuth" => "zether-auth",\n', '        "PqzRollOver" => "zether-auth",\n')],
     U + "owner_statements_sign_under_their_contract_purpose"),
]

if __name__ == "__main__":
    main("t16c", MUTANTS)
