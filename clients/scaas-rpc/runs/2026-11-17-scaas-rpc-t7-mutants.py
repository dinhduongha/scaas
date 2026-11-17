# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-rpc plan T7 mutants: python3 clients/scaas-rpc/runs/2026-11-17-scaas-rpc-t7-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

E = "clients/scaas-rpc/src/evm.rs"
T = "cd clients/scaas-rpc && ../../scripts/capped cargo test --locked --offline -j2 --all-features --test evm_fakes "
MUTANTS = [
    ("trust the answered hash", [(E, "Some(h) if h == id => SendOutcome::Accepted,", "Some(_) => SendOutcome::Accepted,")],
     T + "another_id_is_refused"),
    ("read a refusal as Replaced (a nonce not above)", [(E, "let replaced = |t: &TxFacts| t.receipt.is_none() && t.nonce > nonce && !t.known;", "let replaced = |t: &TxFacts| t.receipt.is_none() && t.nonce >= nonce && !t.known;")],
     T + "all_refused_is_rejected_and_not_final"),
    ("Final without the depth", [(E, "Some(r) if decisive && r.block_number <= a.number =>", "Some(r) if decisive =>")],
     T + "final_from_a_discovered_first_endpoint_is_not_terminal"),
    ("terminal from endpoint 1", [(E, "            strict || (a.members == [0] && self.pool.class(0) != crate::Class::Discovered);\n        let endpoint = a.members[0];",
       "            strict || (a.members.len() == 1 && self.pool.class(0) != crate::Class::Discovered);\n        let endpoint = a.members[0];")],
     T + "replaced_from_a_later_endpoint_is_pending"),
    ("Replaced without the transaction-by-hash read", [(E, "let replaced = |t: &TxFacts| t.receipt.is_none() && t.nonce > nonce && !t.known;", "let replaced = |t: &TxFacts| t.receipt.is_none() && t.nonce > nonce;")],
     T + "replaced_needs_the_transaction_unknown"),
    ("the receipt's block hash not checked", [(E, "        if self.header(i, number, deadline).await? != hash {\n            return Ok(None);",
                                                "        if false {\n            return Ok(None);")],
     T + "a_receipt_whose_block_hash_is_not_the_header_is_not_counted"),
]

if __name__ == "__main__":
    main("t7", MUTANTS)
