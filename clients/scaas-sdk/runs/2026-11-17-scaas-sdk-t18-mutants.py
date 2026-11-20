# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T18 (`admin`, completeness) mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t18-mutants.py check | run [name]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

S = "clients/scaas-sdk/src/surface.rs"
A = "clients/scaas-sdk/src/admin.rs"
W = "clients/scaas-sdk/src/wallet/ops.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
SDK = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} "
MUTANTS = [
    ("map one pair twice", [(S, "pairs: &[(\"Wrap\", \"token\"), (\"Wrap\", \"zether\"), (\"Wrap\", \"pqz\")],", "pairs: &[(\"UABurn\", \"token\"), (\"Wrap\", \"token\"), (\"Wrap\", \"zether\"), (\"Wrap\", \"pqz\")],")], SDK + "--test completeness every_pair_has_one_entry_point"),
    ("leave one pair unmapped", [(S, "pairs: &[(\"UABurn\", \"token\"), (\"UABurn\", \"zether\"), (\"UABurn\", \"pqz\")],", "pairs: &[(\"UABurn\", \"token\"), (\"UABurn\", \"zether\")],")], SDK + "--test completeness every_pair_has_one_entry_point"),
    ("zether_shield and pqz_shield in one entry", [(S, "pairs: &[(\"UAShield\", \"zether\")],", "pairs: &[(\"UAShield\", \"zether\"), (\"UAShield\", \"pqz\")],")], SDK + "--test completeness zether_and_pqz_pairs_are_apart"),
    ("the wallet takes the router's cancel", [(W, "if kind == \"gov_router\" {", "if kind == \"gov_routerX\" {")], SDK + "--lib admin::tests::wallet_refuses_the_router_admin_takes_it"),
    ("a nested field one level deeper", [(A, "if depth(&v) > NESTED_DEPTH ||", "if depth(&v) > NESTED_DEPTH + 1 ||")], SDK + "--lib admin::tests::nested_fields_are_bounded"),
]

if __name__ == "__main__":
    main("t18", MUTANTS)
