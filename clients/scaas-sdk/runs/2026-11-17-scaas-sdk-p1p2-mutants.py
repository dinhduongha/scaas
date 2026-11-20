# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""Owner rulings P1, P2 of 2026-11-19 (plan T15's report): python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-p1p2-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

R = "clients/scaas-sdk/src/confidential/read.rs"
G = "clients/scaas-sdk/src/op/gas.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
T = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --test confidential "
MUTANTS = [
    ("P1: the request's figure always (the table row ignored)",
     [(G, "    .unwrap_or((app, GasFrom::App))\n", "    .map_or((app, GasFrom::App), |_| (app, GasFrom::App))\n")],
     T + "zether_ua_verify_gas_from_the_table_then_the_request"),
    ("P1: no request figure (0 without a table row)",
     [(G, "    .unwrap_or((app, GasFrom::App))\n", "    .unwrap_or((0, GasFrom::App))\n")],
     T + "zether_ua_verify_gas_from_the_table_then_the_request"),
    ("P2: an unregistered recipient is LegKeyMismatch",
     [(R, "            return Err(SdkError::ReceiverUnregistered);", "            return Err(SdkError::LegKeyMismatch);")],
     T + "zether_transfer_single_pair"),
    ("P2: the holder's missing record named as a recipient's",
     [(R, "        if i > 0 && u16::from_be_bytes", "        if u16::from_be_bytes")],
     T + "leg_of_another_key_refused"),
]

if __name__ == "__main__":
    main("p1p2", MUTANTS)
