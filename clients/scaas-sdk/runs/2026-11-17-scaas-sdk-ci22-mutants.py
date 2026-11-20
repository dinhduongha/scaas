# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""PR #22's CI fixes on the merged tree (2026-11-20): Soroban's `kind_name` names 0x0121 (bls12381-multi), as EVM's table; the
SDK gas suite `SdkGasConfPqz` pins its figures at the committed PQZ set only and rolls up to the set's own ROLL_MAX:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-ci22-mutants.py check | run [name]"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

D = "smartcontracts/soroban/contracts/ua-registry/src/digest.rs"
T = ("cd smartcontracts/soroban && ../../scripts/capped cargo test -p scaas-ua-registry --lib "
     "test_ua_portable::ua_portable_kind_name_table")
G = "smartcontracts/evm/test/gas/SdkGasConfPqz.t.sol"
FORGE = ("cd smartcontracts/evm && PATH=$HOME/.foundry/bin:$PATH ../../scripts/capped forge test "
         "--match-path test/gas/SdkGasConfPqz.t.sol --match-test ")
MUTANTS = [
    ("Soroban's kind_name without 0x0121",
     [(D, '        0x0121 => "bls12381-multi", // named here as EVM, refused by `register` until the Soroban round\n', "")], T),
    ("the table set's ROLL_MAX expected wrong",
     [(G, "assertEq(PqzSet.ROLL_MAX, 64,", "assertEq(PqzSet.ROLL_MAX, 32,")], FORGE + "'test_sdkGas_pqzConfRoll$'"),
    ("the roll rows stop below ROLL_MAX",
     [(G, "counts[k] = PqzSet.ROLL_MAX;", "counts[k] = PqzSet.ROLL_MAX - 1;")], FORGE + "'test_sdkGas_pqzConfRoll$'"),
    ("nothing pinned at the committed set",
     [(G, "return keccak256(bytes(PqzSet.NAME)) == keccak256(bytes(_sgCommittedSet()));", "return false;")],
     FORGE + "test_sdkGas_pqzPinnedAtTheCommittedSet"),
]

if __name__ == "__main__":
    main("ci22", MUTANTS)
