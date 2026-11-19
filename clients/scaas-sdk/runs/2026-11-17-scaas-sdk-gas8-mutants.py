# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk gas-table item 8 mutants (owner 2026-11-19): the newly measured rows held to their measurement and to the
coverage lists, the floor-free meter held to the transaction's figure, and ua-rs `fee_due` of a struct without the envelope
(owner ruling G6): python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gas8-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

P = "clients/scaas-sdk/src/op/prepared.rs"
R = "clients/scaas-sdk/gas/reference.json"
POL = "clients/ua-rs/src/wallet/policy.rs"
M = "smartcontracts/evm/test/gas/SdkGasMeter.sol"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
U = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --lib "
UA = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --test sign_scaas "
FORGE = ("cd smartcontracts/evm && ../../scripts/capped forge test --match-path test/gas/SdkGasOrder.t.sol "
         "--match-contract '^SdkGasOrderTokenTest$'")
GUARD = '        _ if op_row(op).is_some_and(|o| !o.envelope) => return Ok("0".into()),\n'
MUTANTS = [
    # the new rows held to their measurement (measured <= gas < measured + 1,000: the parse's bounds)
    ("a new row below its measurement",
     [(R, '"gas": 251000,\n      "measured": 250855,', '"gas": 250000,\n      "measured": 250855,')],
     U + "reference_file_parses"),
    # the coverage lists: a new entry dropped from QUOTABLE, or left in UNMEASURED too
    ("a measured entry in neither list", [(P, '    ("mtxCancelOrders", &["dex"]),\n', "")],
     U + "reference_table_covers_every_quotable_key"),
    ("a measured entry in both lists",
     [(P, '    ("mtxSetAuditorUA", &["gov_router"]),\n', '    ("mtxSetAuditorUA", &["gov_router"]),\n    ("mtxPause", &["gov_router"]),\n')],
     U + "reference_table_covers_every_quotable_key"),
    ("an unmeasured entry listed as quotable",
     [(P, '    ("mtxPrepareAcc", &["pqz"]),\n', '    ("mtxPrepareAcc", &["pqz"]),\n    ("mtxSetAuditorUA", &["gov_router"]),\n'),
      (P, '    ("mtxSetAuditorUA", &["gov_router"]),\n];', "];")],
     U + "reference_table_covers_every_quotable_key"),
    # the newly quotable entry quotes the reference row (its quote fails closed without it)
    ("the account's fresh cancel row gone from the table",
     [(R, '      "entry": "mtxCancelNonce",\n      "kind": "account",\n      "fresh": true,',
       '      "entry": "mtxCancelNonceX",\n      "kind": "account",\n      "fresh": true,')],
     U + "a_newly_measured_entry_quotes_from_the_reference_table"),
    # the meter's offset held by its control
    ("the meter's offset off by 38", [(M, "SG_METER_CALL = 3_038;", "SG_METER_CALL = 3_000;")], FORGE),
    # ua-rs fee_due (G6)
    ("fee_due: the guard removed (the order refused for its missing mode)", [(POL, GUARD, "")],
     UA + "fee_due_of_a_struct_without_the_envelope_is_zero"),
    ("fee_due: 0 for every row, the envelope's too",
     [(POL, GUARD, '        _ if op_row(op).is_some() => return Ok("0".into()),\n')],
     UA + "fee_due_is_the_amount_the_check_charges"),
    ("fee_due: 0 for a struct without its mode (an enveloped one included)",
     [(POL, GUARD, '        _ if get(&m, "mode").is_none() => return Ok("0".into()),\n')],
     UA + "fee_due_of_a_struct_without_the_envelope_is_zero"),
]

if __name__ == "__main__":
    main("gas8", MUTANTS)
