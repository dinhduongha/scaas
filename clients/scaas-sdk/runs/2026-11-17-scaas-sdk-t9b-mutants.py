# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T9b mutants (owner 2026-11-18, Q1, Q2): python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t9b-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

A = "clients/scaas-sdk/src/account/mod.rs"
T = "clients/scaas-sdk/src/text.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
SDK = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} "
MUTANTS = [
    ("a duplicate row is Argument again (Q1)", [(A, "return Err(SdkError::AccountExists);", "return Err(SdkError::Argument);")], SDK + "--test account one_index_per_wallet"),
    ("account names refuse control characters only (Q2)", [(A, "!n.chars().any(crate::text::hidden)", "!n.chars().any(char::is_control)")], SDK + "--test account names_bounded"),
    ("the helper forgets category Cf (Q2)", [(T, "c.is_control() || CF.iter().any(", "c.is_control() && CF.iter().any(")], SDK + "--lib text::"),
]

if __name__ == "__main__":
    main("t9b", MUTANTS)
