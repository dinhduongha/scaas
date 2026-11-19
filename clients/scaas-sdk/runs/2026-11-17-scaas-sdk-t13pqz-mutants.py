# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T13 part 2: the PQZ key attribute of a registration mutants:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t13pqz-mutants.py check | run [name...]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

R = "clients/scaas-sdk/src/account/register.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
T = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --test account_ops "
MUTANTS = [
    ("the PoP leaves out the PQZ key", [(R, "                Some(&pqz_key),\n                Some(&pqz_pop),", "                None,\n                None,")],
     T + "registration_with_pqz_key"),
    ("pqzPopHash not the proof's hash", [(R, "        false => hex(&scaas_ua::keccak256(&pqz_pop)),", "        false => hex(&[7u8; 32]),")],
     T + "registration_with_pqz_key"),
    ("a non-holder proved", [(R, "                if !scaas_ua::is_pqz_holder(k.kind()) {", "                if false {")],
     T + "registration_args_equal_portable_json"),
]

if __name__ == "__main__":
    main("t13pqz", MUTANTS)
