# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""PR #22's CI fix on the merged tree (2026-11-20): Soroban's `kind_name` names 0x0121 (bls12381-multi), as EVM's table:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-ci22-mutants.py check | run [name]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

D = "smartcontracts/soroban/contracts/ua-registry/src/digest.rs"
T = ("cd smartcontracts/soroban && ../../scripts/capped cargo test -p scaas-ua-registry --lib "
     "test_ua_portable::ua_portable_kind_name_table")
MUTANTS = [
    ("Soroban's kind_name without 0x0121",
     [(D, '        0x0121 => "bls12381-multi", // named here as EVM, refused by `register` until the Soroban round\n', "")], T),
]

if __name__ == "__main__":
    main("ci22", MUTANTS)
