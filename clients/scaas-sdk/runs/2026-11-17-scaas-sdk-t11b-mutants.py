# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk T11b mutants (owner 2026-11-18, rulings 3, 4, 5): python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t11b-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

N = "clients/scaas-sdk/src/wallet/native_evm.rs"
Q = "clients/scaas-sdk/src/op/quote.rs"
FO = "clients/scaas-sdk/src/op/follow.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
T = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --test wallet "
MUTANTS = [
    ("type 3 (blob) accepted (3)", [(N, "req.tx_type.is_some_and(|t| t > 2)", "req.tx_type.is_some_and(|t| t > 3)")], T + "native_send_types"),
    ("type 2 on a chain without a base fee (3)", [(Q, "tx_type: if block.base_fee.is_some() { 2 } else { 0 },", "tx_type: 2,")],
     T + "native_send_types"),
    ("an asked type 2 kept without a base fee (3)", [(N, "Some(2) if quote.tx_type != 2 => return Err(SdkError::TxTypeRefused),",
                                                        "Some(2) if false => return Err(SdkError::TxTypeRefused),")], T + "native_send_types"),
    ("a reverted send is Consumed (4)", [(FO, "        }) => OpState::Reverted {\n            block: number,\n            hash: format!(\"{hash:#x}\"),\n        },\n",
                                          "        }) => { let _ = (number, hash); OpState::Consumed }\n")], T + "native_send_reverted_is_reverted"),
    ("no delegation mark (5)", [(N, "let delegated = delegated(&pool.code(from).await.map_err(sim)?);",
                                 "let delegated = { let _ = (delegated(&[]), &pool, sim); false };")], T + "delegated_sender_send_carries_the_mark"),
]

if __name__ == "__main__":
    main("t11b", MUTANTS)
